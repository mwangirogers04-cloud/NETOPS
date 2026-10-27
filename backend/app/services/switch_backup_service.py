import difflib
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.switch_config import SwitchConfig
from ..models.switch_backup import SwitchBackup
from ..services.event_service import create_event
from .switch.manager import create_switch_driver, get_active_switch_driver

logger = logging.getLogger(__name__)


def generate_config_checksum(config_text: str) -> str:
    """Calculate SHA-256 hash of configuration text for tamper and identity detection."""
    clean = (config_text or "").strip().encode("utf-8")
    return hashlib.sha256(clean).hexdigest()


def detect_security_alerts_in_diff(diff_lines: list[str]) -> list[str]:
    """
    Analyze unified diff lines to detect sensitive security modifications:
    - VLAN creation, deletion, or modification
    - Secret, password, or key changes
    - Spanning-tree modifications (BPDU guard, portfast)
    - Port security or trunk mode alterations
    - Management IP or default-gateway updates
    """
    alerts: list[str] = []
    added = [line[1:].strip() for line in diff_lines if line.startswith("+") and not line.startswith("+++")]
    removed = [line[1:].strip() for line in diff_lines if line.startswith("-") and not line.startswith("---")]

    for line in added:
        l = line.lower()
        if l.startswith("vlan ") and "name" not in l:
            alerts.append(f"⚠️ New VLAN introduced in running configuration: '{line}'")
        elif "enable secret" in l or "password" in l:
            alerts.append("🔒 Privileged credentials or enable secret modified")
        elif "switchport mode trunk" in l:
            alerts.append(f"🛡️ Port converted to 802.1Q Trunk uplink: '{line}'")
        elif "no spanning-tree" in l or "no spanning-tree bpduguard" in l:
            alerts.append(f"🚨 Spanning-Tree Loop Protection disabled: '{line}'")
        elif "ip address" in l and ("vlan" in l or "mgmt" in l):
            alerts.append(f"🌐 In-Band Management IP modified: '{line}'")

    for line in removed:
        l = line.lower()
        if l.startswith("vlan ") and "name" not in l:
            alerts.append(f"🗑️ VLAN removed from switch running configuration: '{line}'")
        elif "spanning-tree" in l:
            alerts.append(f"⚠️ Spanning-Tree parameter removed: '{line}'")

    return list(dict.fromkeys(alerts))  # Unique preserved in order


def compute_config_diff(
    old_config: str,
    new_config: str,
    old_label: str = "Baseline",
    new_label: str = "Current",
) -> dict[str, Any]:
    """
    Generate unified and line-by-line structured diff between two configuration texts.
    Returns visual items with addition, removal, context, line numbers, and security alerts.
    """
    old_lines = (old_config or "").splitlines()
    new_lines = (new_config or "").splitlines()

    checksum_old = generate_config_checksum(old_config)
    checksum_new = generate_config_checksum(new_config)
    identical = checksum_old == checksum_new

    raw_diff = list(
        difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=old_label,
            tofile=new_label,
            lineterm="",
        )
    )

    additions = sum(1 for line in raw_diff if line.startswith("+") and not line.startswith("+++"))
    deletions = sum(1 for line in raw_diff if line.startswith("-") and not line.startswith("---"))

    # Build structured diff items for frontend rendering
    structured_items: list[dict[str, Any]] = []
    line_old_num = 1
    line_new_num = 1

    matcher = difflib.SequenceMatcher(None, old_lines, new_lines)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for line in old_lines[i1:i2]:
                structured_items.append({
                    "type": "context",
                    "text": line,
                    "line_old": line_old_num,
                    "line_new": line_new_num,
                })
                line_old_num += 1
                line_new_num += 1
        elif tag == "delete":
            for line in old_lines[i1:i2]:
                structured_items.append({
                    "type": "removed",
                    "text": line,
                    "line_old": line_old_num,
                    "line_new": None,
                })
                line_old_num += 1
        elif tag == "insert":
            for line in new_lines[j1:j2]:
                structured_items.append({
                    "type": "added",
                    "text": line,
                    "line_old": None,
                    "line_new": line_new_num,
                })
                line_new_num += 1
        elif tag == "replace":
            for line in old_lines[i1:i2]:
                structured_items.append({
                    "type": "removed",
                    "text": line,
                    "line_old": line_old_num,
                    "line_new": None,
                })
                line_old_num += 1
            for line in new_lines[j1:j2]:
                structured_items.append({
                    "type": "added",
                    "text": line,
                    "line_old": None,
                    "line_new": line_new_num,
                })
                line_new_num += 1

    security_alerts = detect_security_alerts_in_diff(raw_diff)

    return {
        "identical": identical,
        "additions": additions,
        "deletions": deletions,
        "total_lines_old": len(old_lines),
        "total_lines_new": len(new_lines),
        "checksum_old": checksum_old,
        "checksum_new": checksum_new,
        "diff_items": structured_items,
        "raw_diff": "\n".join(raw_diff),
        "security_alerts": security_alerts,
    }


def create_switch_backup(
    db: Session,
    switch_id: int,
    backup_name: str | None = None,
    created_by: str = "Administrator",
    backup_type: str = "manual",
) -> SwitchBackup:
    """
    Pull live running configuration from the switch driver, compute SHA-256 checksum,
    diff against the preceding backup to generate a change summary, and store record.
    """
    switch = db.get(SwitchConfig, switch_id)
    if not switch:
        raise ValueError(f"Switch #{switch_id} not found.")

    driver = create_switch_driver(switch)
    config_text = driver.get_running_config()

    if not config_text or len(config_text.strip()) < 10:
        raise ValueError(f"Failed to retrieve running configuration from switch '{switch.name}'.")

    checksum = generate_config_checksum(config_text)
    lines_count = len(config_text.splitlines())
    size_bytes = len(config_text.encode("utf-8"))

    # Find the most recent existing backup for this switch
    prev_backup = db.scalar(
        select(SwitchBackup)
        .where(SwitchBackup.switch_id == switch_id)
        .order_by(SwitchBackup.created_at.desc())
        .limit(1)
    )

    if prev_backup:
        diff_res = compute_config_diff(
            prev_backup.config_text,
            config_text,
            old_label=f"Backup #{prev_backup.id}",
            new_label="New Backup",
        )
        if diff_res["identical"]:
            change_summary = "Identical to preceding backup (No changes)"
        else:
            change_summary = f"+{diff_res['additions']} added, -{diff_res['deletions']} removed vs #{prev_backup.id}"
    else:
        change_summary = "Initial Baseline Running-Config"

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    clean_name = (backup_name or "").strip() or f"{switch.name} Running-Config ({now_str} UTC)"

    backup = SwitchBackup(
        switch_id=switch.id,
        backup_name=clean_name,
        config_text=config_text,
        config_type="running-config",
        backup_type=backup_type,
        created_by=created_by,
        checksum=checksum,
        lines_count=lines_count,
        size_bytes=size_bytes,
        change_summary=change_summary,
    )
    db.add(backup)
    db.commit()
    db.refresh(backup)

    create_event(
        db,
        "switch_backup_created",
        f"Switch configuration backup created for '{switch.name}' ({switch.management_ip}): {change_summary}.",
        actor=created_by,
    )

    return backup


def list_switch_backups(db: Session, switch_id: int) -> list[SwitchBackup]:
    """Retrieve all historical configuration backups for a given switch."""
    return list(
        db.scalars(
            select(SwitchBackup)
            .where(SwitchBackup.switch_id == switch_id)
            .order_by(SwitchBackup.created_at.desc())
        ).all()
    )


def get_switch_backup(db: Session, backup_id: int) -> SwitchBackup | None:
    """Retrieve a single switch configuration backup by ID."""
    return db.get(SwitchBackup, backup_id)


def compare_two_backups(
    db: Session,
    backup_id_a: int,
    backup_id_b: int,
) -> dict[str, Any]:
    """Compare two historical configuration backups and return unified diff analysis."""
    backup_a = db.get(SwitchBackup, backup_id_a)
    backup_b = db.get(SwitchBackup, backup_id_b)

    if not backup_a or not backup_b:
        raise ValueError("One or both requested configuration backups were not found.")

    return compute_config_diff(
        backup_a.config_text,
        backup_b.config_text,
        old_label=f"{backup_a.backup_name} (#{backup_a.id})",
        new_label=f"{backup_b.backup_name} (#{backup_b.id})",
    )


def compare_live_with_backup(
    db: Session,
    switch_id: int,
    backup_id: int,
) -> dict[str, Any]:
    """
    Pull live configuration from the switch and diff against a saved baseline backup.
    Detects unapproved manual changes made directly on the switch CLI!
    """
    switch = db.get(SwitchConfig, switch_id)
    if not switch:
        raise ValueError(f"Switch #{switch_id} not found.")

    backup = db.get(SwitchBackup, backup_id)
    if not backup or backup.switch_id != switch_id:
        raise ValueError("Baseline configuration backup not found for this switch.")

    driver = create_switch_driver(switch)
    live_config = driver.get_running_config()

    return compute_config_diff(
        backup.config_text,
        live_config,
        old_label=f"Saved Baseline (#{backup.id} - {backup.backup_name})",
        new_label=f"Live Active Running-Config ({switch.management_ip})",
    )


def delete_switch_backup(db: Session, backup_id: int) -> bool:
    """Delete a configuration backup record. Strictly reserved for Super Admin."""
    backup = db.get(SwitchBackup, backup_id)
    if not backup:
        return False

    db.delete(backup)
    db.commit()
    return True
