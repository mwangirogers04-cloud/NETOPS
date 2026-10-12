import time

from ..database import SessionLocal
from .discovery import discover_devices, save_discovered_devices
from .enforcement_monitor import enforce_all_devices_once

def monitor_network(
    network: str,
    interval: int = 30,
):
    print(f"NETOPS monitoring started for {network}")
    print(f"Scan interval: {interval} seconds")

    while True:
        try:
            devices = discover_devices(network)

            db = SessionLocal()

            try:
                saved_devices = save_discovered_devices(
                    devices,
                    db,
                )

                pending_devices = [
                    device
                    for device in saved_devices
                    if device.approval_status == "pending"
                ]

                print("")
                print("[MONITOR] Scan complete")
                print(f"[MONITOR] Devices found: {len(devices)}")
                print(
                    f"[MONITOR] Devices processed: "
                    f"{len(saved_devices)}"
                )
                print(
                    f"[MONITOR] Pending approval: "
                    f"{len(pending_devices)}"
                )
                enforcement_results = enforce_all_devices_once(db)
                db.commit()

                allowed_devices = [
                    result
                    for result in enforcement_results
                    if result["enforcement_status"] == "allowed"
                ]

                quarantined_devices = [
                    result
                    for result in enforcement_results
                    if result["enforcement_status"] == "quarantined"
                ]

                print(
                    f"[ENFORCEMENT] Devices checked: "
                    f"{len(enforcement_results)}"
                )

                print(
                    f"[ENFORCEMENT] Allowed: "
                    f"{len(allowed_devices)}"
                )

                print(
                    f"[ENFORCEMENT] Quarantined: "
                    f"{len(quarantined_devices)}"
                )

                for device in pending_devices:
                    print("")
                    print("[ALERT] Device awaiting approval")
                    print(f"        ID: {device.id}")
                    print(f"        IP: {device.ip_address}")
                    print(f"        MAC: {device.mac_address}")
                    print(f"        Vendor: {device.vendor}")
                    print(f"        Type: {device.device_type}")
                    print(f"        VLAN: {device.vlan_id}")
                    print(
                        f"        Approval: "
                        f"{device.approval_status}"
                    )

            finally:
                db.close()

        except Exception as error:
            print(f"[ERROR] Monitoring error: {error}")

        time.sleep(interval)


def monitor_once(network: str):
    devices = discover_devices(network)

    db = SessionLocal()

    try:
        saved_devices = save_discovered_devices(
            devices,
            db,
        )

        return saved_devices

    finally:
        db.close()


if __name__ == "__main__":
    monitor_network(
        "192.168.0.0/24",
        interval=30,
    )
