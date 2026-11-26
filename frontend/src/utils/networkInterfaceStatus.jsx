import React from "react";
import {
  Wifi,
  WifiOff,
  Cable,
  ShieldAlert,
  Lock,
  AlertTriangle,
  Clock,
  Ban,
  CheckCircle2,
  Phone,
  Laptop,
  Camera,
  Printer,
  Server,
  Radio,
  Tag,
} from "lucide-react";

export const VLAN_STANDARDS = {
  10: {
    id: 10,
    name: "VoIP & Telephony",
    shortName: "VoIP",
    deviceType: "ip_phone",
    color: "#0284c7",
    bg: "rgba(2, 132, 199, 0.12)",
    border: "#38bdf8",
    subnet: "192.168.10.0/24",
    Icon: Phone,
    description: "Voice-over-IP phones, video conferencing, SIP terminals",
  },
  20: {
    id: 20,
    name: "Workstations & Computers",
    shortName: "Computers",
    deviceType: "computer",
    color: "#2563eb",
    bg: "rgba(37, 99, 235, 0.12)",
    border: "#60a5fa",
    subnet: "192.168.20.0/24",
    Icon: Laptop,
    description: "Corporate desktop PCs, laptops, and developer workstations",
  },
  30: {
    id: 30,
    name: "Surveillance & CCTV",
    shortName: "CCTV",
    deviceType: "cctv",
    color: "#d97706",
    bg: "rgba(217, 119, 6, 0.12)",
    border: "#fbbf24",
    subnet: "192.168.30.0/24",
    Icon: Camera,
    description: "IP cameras, NVRs, and security video surveillance feeds",
  },
  40: {
    id: 40,
    name: "Network Printers & Scanners",
    shortName: "Printers",
    deviceType: "printer",
    color: "#059669",
    bg: "rgba(5, 150, 105, 0.12)",
    border: "#34d399",
    subnet: "192.168.40.0/24",
    Icon: Printer,
    description: "Shared office network printers, MFPs, and scanners",
  },
  50: {
    id: 50,
    name: "Infrastructure Servers",
    shortName: "Servers",
    deviceType: "server",
    color: "#7c3aed",
    bg: "rgba(124, 58, 237, 0.12)",
    border: "#a78bfa",
    subnet: "192.168.50.0/24",
    Icon: Server,
    description: "Domain controllers, NAS, database and application hosts",
  },
  60: {
    id: 60,
    name: "Wireless Access Points",
    shortName: "Access Points",
    deviceType: "access_point",
    color: "#0891b2",
    bg: "rgba(8, 145, 178, 0.12)",
    border: "#22d3ee",
    subnet: "192.168.60.0/24",
    Icon: Radio,
    description: "Enterprise Wi-Fi APs, mesh repeaters, and bridge links",
  },
  90: {
    id: 90,
    name: "Quarantine & Isolation",
    shortName: "Quarantine",
    deviceType: "unknown",
    color: "#dc2626",
    bg: "rgba(220, 38, 38, 0.15)",
    border: "#f87171",
    subnet: "192.168.90.0/24",
    Icon: ShieldAlert,
    description: "Zero-Trust quarantine for untrusted, rogue, or pending devices",
  },
};

export const STATUS_STANDARDS = {
  online: {
    label: "Online",
    color: "#10b981",
    bg: "rgba(16, 185, 129, 0.12)",
    border: "#34d399",
    dotColor: "#10b981",
  },
  offline: {
    label: "Offline",
    color: "#64748b",
    bg: "rgba(100, 116, 139, 0.12)",
    border: "#94a3b8",
    dotColor: "#94a3b8",
  },
  quarantined: {
    label: "Quarantined",
    color: "#ef4444",
    bg: "rgba(239, 68, 68, 0.12)",
    border: "#f87171",
    dotColor: "#ef4444",
  },
  isolated: {
    label: "Isolated",
    color: "#a855f7",
    bg: "rgba(168, 85, 247, 0.12)",
    border: "#c084fc",
    dotColor: "#a855f7",
  },
  pending: {
    label: "Pending",
    color: "#f59e0b",
    bg: "rgba(245, 158, 11, 0.12)",
    border: "#fbbf24",
    dotColor: "#f59e0b",
  },
};

export const DeviceVlanBadge = ({ vlanId, compact = false }) => {
  const vlan = VLAN_STANDARDS[Number(vlanId)] || {
    id: vlanId || 90,
    name: `VLAN ${vlanId || 90}`,
    shortName: `VLAN ${vlanId || 90}`,
    color: "#64748b",
    bg: "rgba(100, 116, 139, 0.12)",
    border: "#94a3b8",
    Icon: Tag,
  };
  const IconComp = vlan.Icon || Tag;

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: compact ? "3px" : "5px",
        fontSize: compact ? "10px" : "11px",
        fontWeight: "700",
        padding: compact ? "1px 6px" : "2px 8px",
        borderRadius: "4px",
        background: vlan.bg,
        color: vlan.color,
        border: `1px solid ${vlan.border}`,
        whiteSpace: "nowrap",
      }}
      title={`VLAN ${vlan.id}: ${vlan.name} (${vlan.subnet || ""})`}
    >
      <IconComp size={compact ? 10 : 12} />
      <span>VLAN {vlan.id}</span>
      {!compact && (
        <span style={{ opacity: 0.8, fontSize: "10px", fontWeight: "600" }}>
          ({vlan.shortName})
        </span>
      )}
    </span>
  );
};

export const DeviceStatusBadge = ({ status, compact = false }) => {
  const normStatus = String(status || "offline").toLowerCase().trim();
  const config = STATUS_STANDARDS[normStatus] || STATUS_STANDARDS.offline;

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "5px",
        fontSize: compact ? "10px" : "11px",
        fontWeight: "700",
        padding: compact ? "1px 6px" : "2px 8px",
        borderRadius: "4px",
        background: config.bg,
        color: config.color,
        border: `1px solid ${config.border}`,
        textTransform: "uppercase",
        letterSpacing: "0.4px",
        whiteSpace: "nowrap",
      }}
    >
      <span
        style={{
          width: compact ? "5px" : "6px",
          height: compact ? "5px" : "6px",
          borderRadius: "50%",
          background: config.dotColor,
          boxShadow: normStatus === "online" ? "0 0 6px #10b981" : "none",
        }}
      />
      <span>{config.label}</span>
    </span>
  );
};

export const TYPE_TO_VLAN = {
  ip_phone: 10,
  phone: 10,
  voip: 10,
  smartphone: 10,
  mobile: 10,
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
 * Determines whether a device is physically online and connected to the network.
 * Physical presence is determined by device.status === "online" or device.is_online === true.
 * Security policies (quarantine, pending approval, internet block) restrict internet access,
 * but do not change the fact that the device is physically connected and detected on LAN/WLAN.
 */
export const isDeviceActuallyOnline = (device) => {
  if (!device) return false;
  const s = String(device.status || "").trim().toLowerCase();
  if (s === "offline" || s === "disconnected") return false;
  return Boolean(s === "online" || device.is_online === true);
};

/**
 * Determines whether a device reflects in QUARANTINED DEVICES.
 *
 * Architecture rules:
 * 1. When a new device is joining the network, it is quarantined directly (approval_status === "pending").
 * 2. When a device is approved, it is still quarantined until explicitly given internet access
 *    (approval_status === "approved" && (!device.internet_access_authorized || device.enforcement_status === "quarantined")).
 * 3. When a device is blocked / rejected / isolated, even if offline, it reflects in QUARANTINED devices!
 *    (approval_status === "rejected" || enforcement_status === "isolated" || !device.internet_access_authorized || device.enforcement_status === "quarantined" || vlan_id === 90).
 *
 * A device ONLY leaves quarantine when it is approved AND actively authorized for internet access (enforcement_status === "allowed" && internet_access_authorized === true).
 */
export const isDeviceInQuarantine = (device) => {
  if (!device) return false;

  // Security isolation
  if (device.enforcement_status === "isolated" || device.access_decision === "isolated") {
    return true;
  }

  // Pending approval (new device joining) or explicitly rejected
  if (device.approval_status === "pending" || device.approval_status === "rejected") {
    return true;
  }

  // Blocked, unapproved for internet, or assigned to Quarantine VLAN 90
  if (
    !device.internet_access_authorized ||
    device.enforcement_status === "quarantined" ||
    Number(device.vlan_id) === 90 ||
    device.access_decision === "quarantine"
  ) {
    return true;
  }

  return false;
};

/**
 * Determines whether a device reflects in OFFLINE DEVICES.
 *
 * Architecture rule:
 * A device reflects in Offline devices ONLY when an approved, internet-authorized device
 * leaves the Wi-Fi / LAN coverage area (e.g. employee takes laptop home, powers off, leaves building).
 * Blocked / rejected / pending devices reflect in Quarantined devices instead.
 */
export const isDeviceOffline = (device) => {
  if (!device) return false;

  // If physically connected and passing network traffic, it is not offline
  if (isDeviceActuallyOnline(device)) {
    return false;
  }

  // If in quarantine (new pending, blocked, rejected, unauthorized, or isolated),
  // it reflects in Quarantined devices
  if (isDeviceInQuarantine(device)) {
    return false;
  }

  // Approved, internet-authorized device that has disconnected (left Wi-Fi coverage area)
  return device.approval_status === "approved" && Boolean(device.internet_access_authorized);
};

export const isDeviceOfflineRegistered = isDeviceOffline;

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
      statusIcon: "",
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
  let statusIcon = "";
  let badgeColor = "#059669";
  let badgeBg = "rgba(16, 185, 129, 0.15)";
  let badgeBorder = "#10b981";

  if (isDisconnected) {
    reason = isWireless ? "Wi-Fi Disconnected / Offline" : "Wired Cable Disconnected / Offline";
    shortReason = "Offline";
    statusIcon = "";
    badgeColor = "#64748b";
    badgeBg = "rgba(100, 116, 139, 0.15)";
    badgeBorder = "#94a3b8";
  } else if (isTypeVlanMismatch) {
    reason = `Type & VLAN Mismatch: Device type '${device.device_type || "unknown"}' requires VLAN ${expectedVlan}, but assigned VLAN ${device.vlan_id || 90}. Device must match in TYPE and VLAN section to be connected.`;
    shortReason = "Type/VLAN Mismatch";
    statusIcon = "";
    badgeColor = "#b45309";
    badgeBg = "rgba(245, 158, 11, 0.15)";
    badgeBorder = "#f59e0b";
  } else if (isQuarantined) {
    reason = "Quarantined in VLAN 90 (Zero-Trust NAC: No Internet Access)";
    shortReason = "Quarantined (VLAN 90)";
    statusIcon = "";
    badgeColor = "#dc2626";
    badgeBg = "rgba(220, 38, 38, 0.15)";
    badgeBorder = "#ef4444";
  } else if (isIsolated) {
    reason = "Isolated by Security Policy (No Internet Access)";
    shortReason = "Isolated";
    statusIcon = "";
    badgeColor = "#9333ea";
    badgeBg = "rgba(147, 51, 234, 0.15)";
    badgeBorder = "#a855f7";
  } else if (isPending) {
    reason = "Pending Approval (Unapproved Device: No Internet Access)";
    shortReason = "Pending Approval";
    statusIcon = "";
    badgeColor = "#d97706";
    badgeBg = "rgba(217, 119, 6, 0.15)";
    badgeBorder = "#f59e0b";
  } else if (isUnauthorized) {
    reason = "Internet Access Not Authorized (Firewall Blocked)";
    shortReason = "Not Authorized";
    statusIcon = "";
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
  const iconSize = compact ? 12 : 14;

  const renderStatusIcon = () => {
    if (status.isDisconnected) {
      return status.isWireless ? <WifiOff size={iconSize} /> : <Cable size={iconSize} style={{ opacity: 0.6 }} />;
    }
    if (status.isQuarantined) {
      return <ShieldAlert size={iconSize} />;
    }
    if (status.isIsolated) {
      return <Lock size={iconSize} />;
    }
    if (status.isPending) {
      return <Clock size={iconSize} />;
    }
    if (status.isUnauthorized) {
      return <Ban size={iconSize} />;
    }
    if (status.isTypeVlanMismatch) {
      return <AlertTriangle size={iconSize} />;
    }
    return status.isWireless ? <Wifi size={iconSize} /> : <Cable size={iconSize} />;
  };

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
      <span style={{ display: "inline-flex", alignItems: "center" }}>{renderStatusIcon()}</span>
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
