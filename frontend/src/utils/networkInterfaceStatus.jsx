import React from "react";

export const TYPE_TO_VLAN = {
  ip_phone: 10,
  phone: 10,
  voip: 10,
  computer: 20,
  cctv: 30,
  printer: 40,
  server: 50,
  access_point: 60,
  ap: 60,
  wifi_ap: 60,
  unknown: 90,
};

export const VLAN_TO_TYPE = {
  10: "ip_phone",
  20: "computer",
  30: "cctv",
  40: "printer",
  50: "server",
  60: "access_point",
  90: "unknown",
};

export const getExpectedVlanForType = (deviceType) => {
  if (!deviceType) return 90;
  const t = String(deviceType).toLowerCase().trim();
  return TYPE_TO_VLAN[t] !== undefined ? TYPE_TO_VLAN[t] : 90;
};

export const isTypeAndVlanMatching = (device) => {
  if (!device) return true;
  const expected = getExpectedVlanForType(device.device_type);
  const current = Number(device.vlan_id || 90);
  return current === expected;
};

/**
 * Computes network interface type and real-time internet connectivity status
 * for any LAN or WLAN (Wi-Fi) device.
 *
 * Honors the security invariant:
 * A device connected to WLAN0 or ETH0 has NO INTERNET ACCESS when:
 * 1. It is Quarantined (enforcement_status == "quarantined" or vlan_id == 90 or access_decision == "quarantine")
 * 2. It is Security Isolated (enforcement_status == "isolated" or access_decision == "isolated")
 * 3. It is Disconnected / Offline (status == "offline" or status == "disconnected")
 * 4. It is Pending / Unapproved (approval_status == "pending" or rejected or not approved)
 * 5. It is Unauthorized (internet_access_authorized == false)
 * 6. TYPE and VLAN section mismatch (For a device to be connected it must be same in TYPE and VLAN section)
 */
export const getDeviceInternetStatus = (device) => {
  if (!device) {
    return {
      isWireless: false,
      hasNoInternet: true,
      reason: "Device data unavailable",
      shortReason: "Offline",
      statusIcon: "🔌⚪",
      badgeColor: "#64748b",
      badgeBg: "rgba(100, 116, 139, 0.15)",
      badgeBorder: "#94a3b8",
      ifaceLabel: "LAN (eth0)",
      isTypeVlanMismatch: false,
      expectedVlan: 90,
    };
  }

  const iface = device.network_interface || "";
  const isWireless = Boolean(
    iface === "wlan0" ||
    iface.startsWith("wl") ||
    device.medium === "wireless" ||
    ["access_point", "ap", "wifi_ap", "smartphone", "phone", "mobile"].includes(device.device_type)
  );

  const isDisconnected = device.status === "offline" || device.status === "disconnected";
  const isQuarantined =
    device.enforcement_status === "quarantined" ||
    device.vlan_id === 90 ||
    device.access_decision === "quarantine";
  const isIsolated =
    device.enforcement_status === "isolated" ||
    device.access_decision === "isolated" ||
    device.status === "isolated";
  const isPending =
    device.approval_status === "pending" ||
    device.approval_status === "rejected" ||
    (device.approval_status && device.approval_status !== "approved");
  const isUnauthorized = device.internet_access_authorized === false;

  const expectedVlan = getExpectedVlanForType(device.device_type);
  const isTypeVlanMismatch = device.vlan_id !== undefined && device.vlan_id !== null && Number(device.vlan_id) !== expectedVlan;

  const hasNoInternet = isDisconnected || isQuarantined || isIsolated || isPending || isUnauthorized || isTypeVlanMismatch;

  let reason = "Internet Access Active";
  let shortReason = "Active";
  let statusIcon = isWireless ? "📶" : "🔌";
  let badgeColor = "#059669";
  let badgeBg = "rgba(16, 185, 129, 0.15)";
  let badgeBorder = "#10b981";

  if (isDisconnected) {
    reason = isWireless ? "Wi-Fi Disconnected / Offline" : "Wired Cable Disconnected / Offline";
    shortReason = "Offline";
    statusIcon = isWireless ? "📶⚪" : "🔌⚪";
    badgeColor = "#64748b";
    badgeBg = "rgba(100, 116, 139, 0.15)",
    badgeBorder = "#94a3b8";
  } else if (isTypeVlanMismatch) {
    reason = `Type & VLAN Mismatch: Device type '${device.device_type || "unknown"}' requires VLAN ${expectedVlan}, but assigned VLAN ${device.vlan_id || 90}. Device must match in TYPE and VLAN section to be connected.`;
    shortReason = "Type/VLAN Mismatch";
    statusIcon = isWireless ? "📶⚠️" : "🔌⚠️";
    badgeColor = "#b45309";
    badgeBg = "rgba(245, 158, 11, 0.15)";
    badgeBorder = "#f59e0b";
  } else if (isQuarantined) {
    reason = "Quarantined in VLAN 90 (Zero-Trust NAC: No Internet Access)";
    shortReason = "Quarantined (VLAN 90)";
    statusIcon = isWireless ? "📶🚫" : "🔌🚫";
    badgeColor = "#dc2626";
    badgeBg = "rgba(220, 38, 38, 0.15)";
    badgeBorder = "#ef4444";
  } else if (isIsolated) {
    reason = "Isolated by Security Policy (No Internet Access)";
    shortReason = "Isolated";
    statusIcon = isWireless ? "📶🔒" : "🔌🔒";
    badgeColor = "#9333ea";
    badgeBg = "rgba(147, 51, 234, 0.15)";
    badgeBorder = "#a855f7";
  } else if (isPending) {
    reason = "Pending Approval (Unapproved Device: No Internet Access)";
    shortReason = "Pending Approval";
    statusIcon = isWireless ? "📶⚠️" : "🔌⚠️";
    badgeColor = "#d97706";
    badgeBg = "rgba(217, 119, 6, 0.15)";
    badgeBorder = "#f59e0b";
  } else if (isUnauthorized) {
    reason = "Internet Access Not Authorized (Firewall Blocked)";
    shortReason = "Not Authorized";
    statusIcon = isWireless ? "📶🚫" : "🔌🚫";
    badgeColor = "#dc2626";
    badgeBg = "rgba(220, 38, 38, 0.15)";
    badgeBorder = "#ef4444";
  }

  const ifaceLabel = isWireless ? "WLAN0 (Wi-Fi)" : `${(iface || "eth0").toUpperCase()} (LAN)`;

  return {
    isWireless,
    hasNoInternet,
    isDisconnected,
    isQuarantined,
    isIsolated,
    isPending,
    isUnauthorized,
    isTypeVlanMismatch,
    expectedVlan,
    reason,
    shortReason,
    statusIcon,
    badgeColor,
    badgeBg,
    badgeBorder,
    ifaceLabel,
  };
};

export const DeviceInterfaceBadge = ({ device, compact = false }) => {
  const status = getDeviceInternetStatus(device);
  return (
    <span
      style={{
        fontSize: compact ? "10px" : "11px",
        padding: compact ? "1px 6px" : "2px 8px",
        borderRadius: "4px",
        background: status.badgeBg,
        color: status.badgeColor,
        border: `1px solid ${status.badgeBorder}`,
        fontWeight: "700",
        display: "inline-flex",
        alignItems: "center",
        gap: "4px",
        verticalAlign: "middle",
      }}
      title={`${status.ifaceLabel} • ${status.reason}`}
    >
      <span style={{ fontSize: compact ? "11px" : "13px" }}>{status.statusIcon}</span>
      <span>{status.ifaceLabel}</span>
      {status.hasNoInternet ? (
        <span
          style={{
            fontSize: "9px",
            padding: "1px 5px",
            borderRadius: "3px",
            background: status.badgeColor,
            color: "#ffffff",
            fontWeight: "800",
            letterSpacing: "0.2px",
          }}
        >
          NO INTERNET
        </span>
      ) : (
        <span
          style={{
            fontSize: "9px",
            padding: "1px 5px",
            borderRadius: "3px",
            background: "#059669",
            color: "#ffffff",
            fontWeight: "800",
          }}
        >
          INTERNET ACTIVE
        </span>
      )}
    </span>
  );
};
