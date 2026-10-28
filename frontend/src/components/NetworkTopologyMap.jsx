import React, { useState, useEffect, useMemo } from "react";

export default function NetworkTopologyMap({
  API_URL,
  currentUser,
  devices = [],
  getAuthHeaders,
  handleOpenCveModal,
  handleRunTroubleshoot,
  refreshAll,
}) {
  const [switches, setSwitches] = useState([]);
  const [activeSwitchData, setActiveSwitchData] = useState(null);
  const [switchPorts, setSwitchPorts] = useState([]);
  const [activeFirewall, setActiveFirewall] = useState(null);
  const [loading, setLoading] = useState(false);
  const [switchingDensity, setSwitchingDensity] = useState(false);
  const [selectedNode, setSelectedNode] = useState(null);
  const [vlanFilter, setVlanFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [viewMode, setViewMode] = useState("diagram"); // "diagram" | "clusters"

  const loadTopologyData = async () => {
    setLoading(true);
    try {
      const headers = getAuthHeaders ? getAuthHeaders() : {};
      const [swRes, activeSwRes, portRes, fwRes] = await Promise.all([
        fetch(`${API_URL}/switches/configs`, { headers }).catch(() => null),
        fetch(`${API_URL}/switches/active`, { headers }).catch(() => null),
        fetch(`${API_URL}/switches/ports`, { headers }).catch(() => null),
        fetch(`${API_URL}/firewall/config`, { headers }).catch(() => null),
      ]);

      if (swRes && swRes.ok) {
        const swData = await swRes.json();
        setSwitches(Array.isArray(swData) ? swData : []);
      }
      if (activeSwRes && activeSwRes.ok) {
        const activeData = await activeSwRes.json();
        setActiveSwitchData(activeData);
      }
      if (portRes && portRes.ok) {
        const portData = await portRes.json();
        setSwitchPorts(Array.isArray(portData) ? portData : []);
      }
      if (fwRes && fwRes.ok) {
        const fwData = await fwRes.json();
        setActiveFirewall(fwData.active_driver || { vendor_title: "Sophos XG/XGS (SFOS)", vendor: "sophos" });
      }
    } catch (_) {
    } finally {
      setLoading(false);
    }
  };

  const isAdmin = currentUser?.role === "admin" || currentUser?.role === "super_admin" || currentUser?.role === "developer";

  const handleSwitchChassisDensity = async (targetDensity) => {
    if (!isAdmin) return;
    setSwitchingDensity(true);
    try {
      const res = await fetch(`${API_URL}/switches/ports/density`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...getAuthHeaders() },
        body: JSON.stringify({ total_ports: targetDensity }),
      });
      if (res.ok) {
        await loadTopologyData();
      }
    } catch (_) {
    } finally {
      setSwitchingDensity(false);
    }
  };

  useEffect(() => {
    loadTopologyData();
  }, []);

  // Filtered devices
  const filteredDevices = useMemo(() => {
    return devices.filter((d) => {
      // VLAN filter
      if (vlanFilter !== "all" && String(d.vlan_id) !== String(vlanFilter)) {
        return false;
      }
      // Status filter
      if (statusFilter === "online" && d.status !== "online") return false;
      if (statusFilter === "quarantined" && d.enforcement_status !== "quarantined" && d.vlan_id !== 90) return false;

      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchMac = (d.mac_address || "").toLowerCase().includes(q);
        const matchIp = (d.ip_address || "").toLowerCase().includes(q);
        const matchHost = (d.hostname || "").toLowerCase().includes(q);
        const matchVendor = (d.vendor || "").toLowerCase().includes(q);
        return matchMac || matchIp || matchHost || matchVendor;
      }
      return true;
    });
  }, [devices, vlanFilter, statusFilter, searchQuery]);

  // Group devices by VLAN
  const vlanGroups = useMemo(() => {
    const groups = {
      10: { name: "Voice & VoIP Telephony", subnet: "192.168.10.0/24", color: "#10b981", bg: "#f0fdf4", border: "#86efac", devices: [] },
      20: { name: "Workstations & Corporate Data", subnet: "192.168.20.0/24", color: "#3b82f6", bg: "#eff6ff", border: "#93c5fd", devices: [] },
      30: { name: "CCTV & Video Surveillance", subnet: "192.168.30.0/24", color: "#8b5cf6", bg: "#f5f3ff", border: "#c4b5fd", devices: [] },
      90: { name: "Zero-Trust Quarantine Sandbox", subnet: "192.168.90.0/24", color: "#ef4444", bg: "#fef2f2", border: "#fca5a5", devices: [] },
      other: { name: "Other Subnets / Guest", subnet: "Dynamic Subnets", color: "#64748b", bg: "#f8fafc", border: "#cbd5e1", devices: [] },
    };

    filteredDevices.forEach((d) => {
      const vid = d.vlan_id || 90;
      if (groups[vid]) {
        groups[vid].devices.push(d);
      } else {
        groups.other.devices.push(d);
      }
    });

    return groups;
  }, [filteredDevices]);

  const activeSwitch = useMemo(() => {
    if (activeSwitchData?.config) {
      return activeSwitchData.config;
    }
    const saved = switches.find((s) => s.is_active) || switches[0];
    if (saved) return saved;
    const is48 = switchPorts.length > 24;
    return {
      name: `Core Switch 1 (${is48 ? "Cisco Catalyst 48-Port" : "Cisco Catalyst 24-Port"})`,
      management_ip: "192.168.0.2",
      vendor: "cisco_ios",
      model: is48 ? "Cisco Catalyst 2960X-48TS-L" : "Cisco Catalyst 2960-X",
      total_ports: is48 ? 48 : 24,
    };
  }, [activeSwitchData, switches, switchPorts]);

  const is48PortSwitch = (activeSwitch?.total_ports === 48) || (switchPorts.length > 24);
  const totalPortCount = is48PortSwitch ? 48 : 24;
  const sfpUplinkPorts = switchPorts.filter((p) => p.is_sfp || String(p.port || "").toLowerCase().startsWith("te"));
  const connectedPorts = switchPorts.filter((p) => p.status === "connected");

  const getDeviceIcon = (type) => {
    switch (type) {
      case "voip": return "📞";
      case "camera": return "📹";
      case "printer": return "🖨️";
      case "server": return "🖥️";
      case "mobile": return "📱";
      case "access_point": return "📡";
      default: return "💻";
    }
  };

  return (
    <div className="page">
      {/* PAGE HEADER */}
      <div className="page-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "12px", marginBottom: "16px" }}>
        <div>
          <div className="page-title" style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <span>🗺️ Interactive Network Topology Map</span>
            <span style={{ fontSize: "11px", background: "#eff6ff", color: "#1d4ed8", border: "1px solid #93c5fd", padding: "3px 8px", borderRadius: "12px", fontWeight: "700" }}>
              Live 802.1Q VLAN Hierarchy
            </span>
          </div>
          <div className="page-description">
            Visual topology map illustrating Gateway firewalls, 802.1Q switch trunk lines, VLAN subnet clusters, and connected active endpoints.
          </div>
        </div>

        <div style={{ display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" }}>
          {isAdmin && (
            <div style={{ display: "flex", alignItems: "center", gap: "4px", background: "#f8fafc", padding: "3px", borderRadius: "8px", border: "1px solid #cbd5e1" }}>
              <span style={{ fontSize: "11px", fontWeight: "700", color: "#64748b", paddingLeft: "4px", paddingRight: "2px" }}>
                Switch:
              </span>
              <button
                type="button"
                onClick={() => handleSwitchChassisDensity(24)}
                disabled={switchingDensity}
                style={{
                  padding: "3px 8px",
                  fontSize: "11px",
                  fontWeight: "700",
                  borderRadius: "5px",
                  border: "none",
                  cursor: "pointer",
                  background: !is48PortSwitch ? "#2563eb" : "transparent",
                  color: !is48PortSwitch ? "#ffffff" : "#475569",
                  boxShadow: !is48PortSwitch ? "0 1px 2px rgba(0,0,0,0.1)" : "none",
                }}
              >
                24-Port
              </button>
              <button
                type="button"
                onClick={() => handleSwitchChassisDensity(48)}
                disabled={switchingDensity}
                style={{
                  padding: "3px 8px",
                  fontSize: "11px",
                  fontWeight: "700",
                  borderRadius: "5px",
                  border: "none",
                  cursor: "pointer",
                  background: is48PortSwitch ? "#2563eb" : "transparent",
                  color: is48PortSwitch ? "#ffffff" : "#475569",
                  boxShadow: is48PortSwitch ? "0 1px 2px rgba(0,0,0,0.1)" : "none",
                }}
              >
                48-Port (+ SFP+)
              </button>
            </div>
          )}

          <button
            type="button"
            className={viewMode === "diagram" ? "primary-button small" : "secondary-button small"}
            onClick={() => setViewMode("diagram")}
          >
            📊 Layered Diagram
          </button>
          <button
            type="button"
            className={viewMode === "clusters" ? "primary-button small" : "secondary-button small"}
            onClick={() => setViewMode("clusters")}
          >
            🗂️ Subnet Clusters
          </button>
          <button
            type="button"
            className="secondary-button small"
            onClick={() => {
              loadTopologyData();
              if (refreshAll) refreshAll();
            }}
            disabled={loading || switchingDensity}
          >
            {loading || switchingDensity ? "Refreshing..." : "🔄 Refresh Topology"}
          </button>
        </div>
      </div>

      {/* METRICS & FILTER BAR */}
      <div className="panel" style={{ padding: "12px 16px", marginBottom: "16px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "12px" }}>
          {/* Quick Metrics */}
          <div style={{ display: "flex", gap: "16px", alignItems: "center", fontSize: "12px", flexWrap: "wrap" }}>
            <div><span style={{ color: "#64748b" }}>Gateway:</span> <strong>{activeFirewall?.vendor_title || "Sophos SFOS"}</strong></div>
            <div>
              <span style={{ color: "#64748b" }}>Core Switch:</span> <strong>{activeSwitch.name}</strong>{" "}
              <span
                style={{
                  fontSize: "10px",
                  padding: "1px 6px",
                  borderRadius: "8px",
                  background: is48PortSwitch ? "#ede9fe" : "#eff6ff",
                  color: is48PortSwitch ? "#6d28d9" : "#1d4ed8",
                  fontWeight: "800",
                }}
              >
                {totalPortCount} Ports {is48PortSwitch ? "(+ 4x 10G SFP+)" : ""}
              </span>
            </div>
            <div><span style={{ color: "#64748b" }}>Visible Devices:</span> <strong>{filteredDevices.length} / {devices.length}</strong></div>
            <div>
              <span style={{ color: "#64748b" }}>Quarantined:</span>{" "}
              <strong style={{ color: vlanGroups[90].devices.length > 0 ? "#dc2626" : "#166534" }}>
                {vlanGroups[90].devices.length} endpoint(s)
              </strong>
            </div>
          </div>

          {/* Search Input */}
          <input
            type="text"
            placeholder="Search hostname, IP, MAC..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{ padding: "6px 12px", fontSize: "12px", border: "1px solid #cbd5e1", borderRadius: "6px", width: "220px", background: "#fff" }}
          />
        </div>

        {/* Filter Pills */}
        <div style={{ display: "flex", gap: "8px", alignItems: "center", marginTop: "12px", paddingTop: "10px", borderTop: "1px solid #f1f5f9", flexWrap: "wrap" }}>
          <span style={{ fontSize: "11px", fontWeight: "700", color: "#475569" }}>VLAN FILTER:</span>
          {[
            { id: "all", label: "All VLANs" },
            { id: "10", label: "🟢 VLAN 10 (Voice)" },
            { id: "20", label: "🔵 VLAN 20 (Data)" },
            { id: "30", label: "🟣 VLAN 30 (CCTV)" },
            { id: "90", label: "🔴 VLAN 90 (Quarantine)" },
          ].map((pill) => (
            <button
              key={pill.id}
              type="button"
              onClick={() => setVlanFilter(pill.id)}
              style={{
                fontSize: "11px",
                padding: "3px 8px",
                borderRadius: "12px",
                border: vlanFilter === pill.id ? "1.5px solid #2563eb" : "1px solid #cbd5e1",
                background: vlanFilter === pill.id ? "#eff6ff" : "#ffffff",
                color: vlanFilter === pill.id ? "#1d4ed8" : "#475569",
                fontWeight: vlanFilter === pill.id ? "800" : "500",
                cursor: "pointer",
              }}
            >
              {pill.label}
            </button>
          ))}

          <span style={{ fontSize: "11px", fontWeight: "700", color: "#475569", marginLeft: "12px" }}>STATUS:</span>
          {[
            { id: "all", label: "All" },
            { id: "online", label: "Online Only" },
            { id: "quarantined", label: "Quarantined Only" },
          ].map((spill) => (
            <button
              key={spill.id}
              type="button"
              onClick={() => setStatusFilter(spill.id)}
              style={{
                fontSize: "11px",
                padding: "3px 8px",
                borderRadius: "12px",
                border: statusFilter === spill.id ? "1.5px solid #2563eb" : "1px solid #cbd5e1",
                background: statusFilter === spill.id ? "#eff6ff" : "#ffffff",
                color: statusFilter === spill.id ? "#1d4ed8" : "#475569",
                fontWeight: statusFilter === spill.id ? "800" : "500",
                cursor: "pointer",
              }}
            >
              {spill.label}
            </button>
          ))}
        </div>
      </div>

      {/* MAIN TOPOLOGY VIEWPORT & SIDE DRAWER */}
      <div style={{ display: "grid", gridTemplateColumns: selectedNode ? "1fr 340px" : "1fr", gap: "16px", alignItems: "start" }}>
        {/* VIEWPORT */}
        <div className="panel" style={{ padding: "20px", background: "#f8fafc", minHeight: "650px", overflowX: "auto" }}>
          {viewMode === "diagram" ? (
            /* LAYERED VISUAL DIAGRAM */
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "24px", minWidth: "750px" }}>
              {/* TIER 1: GATEWAY FIREWALL NODE */}
              <div
                onClick={() => setSelectedNode({ type: "gateway", data: activeFirewall })}
                style={{
                  background: "#ffffff",
                  border: "2px solid #3b82f6",
                  borderRadius: "12px",
                  padding: "14px 24px",
                  boxShadow: "0 4px 6px -1px rgba(0,0,0,0.08)",
                  textAlign: "center",
                  cursor: "pointer",
                  width: "320px",
                  transition: "transform 0.15s ease",
                }}
              >
                <div style={{ fontSize: "28px", marginBottom: "4px" }}>🛡️</div>
                <div style={{ fontSize: "14px", fontWeight: "800", color: "#0f172a" }}>
                  {activeFirewall?.vendor_title || "Sophos XG/XGS Firewall Gateway"}
                </div>
                <div style={{ fontSize: "11px", color: "#64748b", marginTop: "2px" }}>
                  Default Gateway • Zero-Trust NAC Enforcement Engine
                </div>
                <div style={{ marginTop: "6px", display: "inline-block", background: "#f0fdf4", color: "#166534", fontSize: "10px", padding: "2px 8px", borderRadius: "10px", fontWeight: "700" }}>
                  🟢 WAN ACTIVE • DHCP SYNC ONLINE
                </div>
              </div>

              {/* VERTICAL TRUNK LINE 1 */}
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
                <div style={{ width: "3px", height: "24px", background: is48PortSwitch ? "#8b5cf6" : "#3b82f6" }} />
                <div
                  style={{
                    background: is48PortSwitch ? "#f5f3ff" : "#eff6ff",
                    border: `1.5px solid ${is48PortSwitch ? "#c4b5fd" : "#93c5fd"}`,
                    color: is48PortSwitch ? "#6d28d9" : "#1d4ed8",
                    fontSize: "10px",
                    padding: "3px 12px",
                    borderRadius: "12px",
                    fontWeight: "800",
                    display: "flex",
                    alignItems: "center",
                    gap: "6px",
                    boxShadow: is48PortSwitch ? "0 0 10px rgba(139, 92, 246, 0.25)" : "none",
                  }}
                >
                  <span>{is48PortSwitch ? "⚡" : "🔀"}</span>
                  <span>
                    {is48PortSwitch
                      ? "10G SFP+ High-Speed Trunk Uplink (Te0/49-52 • Tagged VLANs 10, 20, 30, 90)"
                      : "802.1Q Gigabit Trunk Uplink (Ports 23 & 24 • Tagged VLANs 10, 20, 30, 90)"}
                  </span>
                </div>
                <div style={{ width: "3px", height: "24px", background: is48PortSwitch ? "#8b5cf6" : "#3b82f6" }} />
              </div>

              {/* TIER 2: MANAGED SWITCH NODE */}
              <div
                onClick={() => setSelectedNode({
                  type: "switch",
                  data: {
                    ...activeSwitch,
                    total_ports: totalPortCount,
                    is_48_port: is48PortSwitch,
                    sfp_count: sfpUplinkPorts.length,
                    connected_count: connectedPorts.length,
                  },
                })}
                style={{
                  background: "#ffffff",
                  border: `2px solid ${is48PortSwitch ? "#7c3aed" : "#6366f1"}`,
                  borderRadius: "12px",
                  padding: "16px 24px",
                  boxShadow: is48PortSwitch ? "0 6px 16px rgba(124, 58, 237, 0.18)" : "0 4px 6px -1px rgba(0,0,0,0.08)",
                  textAlign: "center",
                  cursor: "pointer",
                  width: "440px",
                  transition: "all 0.15s ease",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: "8px", marginBottom: "4px" }}>
                  <span style={{ fontSize: "28px" }}>🔀</span>
                  <span
                    style={{
                      fontSize: "10px",
                      fontWeight: "800",
                      padding: "2px 8px",
                      borderRadius: "10px",
                      background: is48PortSwitch ? "#ede9fe" : "#eff6ff",
                      color: is48PortSwitch ? "#6d28d9" : "#1d4ed8",
                      border: `1px solid ${is48PortSwitch ? "#c4b5fd" : "#bfdbfe"}`,
                    }}
                  >
                    {is48PortSwitch ? "48-PORT ENTERPRISE + 4x 10G SFP+" : "24-PORT STANDARD SWITCH"}
                  </span>
                </div>
                <div style={{ fontSize: "15px", fontWeight: "800", color: "#0f172a" }}>
                  {activeSwitch.name}
                </div>
                <div style={{ fontSize: "11px", color: "#64748b", marginTop: "2px" }}>
                  Management IP: <code>{activeSwitch.management_ip || "192.168.0.2"}</code> • Model: <strong>{activeSwitch.model || (is48PortSwitch ? "Catalyst 2960X-48TS-L" : "Catalyst 2960-X")}</strong>
                </div>
                <div style={{ display: "flex", justifyContent: "center", gap: "6px", marginTop: "8px", flexWrap: "wrap" }}>
                  <span style={{ background: "#f0fdf4", color: "#166534", border: "1px solid #bbf7d0", fontSize: "10px", padding: "2px 8px", borderRadius: "10px", fontWeight: "700" }}>
                    🟢 {connectedPorts.length || (is48PortSwitch ? 28 : 14)} / {switchPorts.length || (is48PortSwitch ? 52 : 24)} Ports Connected
                  </span>
                  {is48PortSwitch && (
                    <span style={{ background: "#faf5ff", color: "#7c3aed", border: "1px solid #e9d5ff", fontSize: "10px", padding: "2px 8px", borderRadius: "10px", fontWeight: "700" }}>
                      ⚡ 4x 10G SFP+ Uplinks Ready
                    </span>
                  )}
                  <span style={{ background: "#eff6ff", color: "#2563eb", border: "1px solid #bfdbfe", fontSize: "10px", padding: "2px 8px", borderRadius: "10px", fontWeight: "700" }}>
                    802.1X / RADIUS MAB Active
                  </span>
                </div>
              </div>

              {/* BRANCHING CONNECTOR */}
              <div style={{ width: "100%", maxWidth: "900px", height: "2px", background: "#cbd5e1", position: "relative", margin: "10px 0" }}>
                <div style={{ position: "absolute", left: "50%", top: "-10px", transform: "translateX(-50%)", background: "#f8fafc", padding: "0 8px", fontSize: "10px", fontWeight: "700", color: "#64748b" }}>
                  DISTRIBUTED ACCESS PORTS &amp; VLAN SEGMENTS
                </div>
              </div>

              {/* TIER 3 & 4: VLAN SUB-CLUSTERS & CONNECTED ENDPOINTS */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "16px", width: "100%" }}>
                {[10, 20, 30, 90].map((vid) => {
                  const grp = vlanGroups[vid];
                  return (
                    <div
                      key={vid}
                      style={{
                        background: grp.bg,
                        border: `2px solid ${grp.border}`,
                        borderRadius: "10px",
                        padding: "14px",
                        display: "flex",
                        flexDirection: "column",
                      }}
                    >
                      {/* Cluster Header */}
                      <div style={{ borderBottom: `1.5px solid ${grp.border}`, paddingBottom: "8px", marginBottom: "10px" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <span style={{ fontSize: "14px", fontWeight: "900", color: grp.color }}>
                            VLAN {vid}
                          </span>
                          <span style={{ fontSize: "11px", background: "#ffffff", padding: "1px 6px", borderRadius: "10px", fontWeight: "800", color: grp.color }}>
                            {grp.devices.length} Dev
                          </span>
                        </div>
                        <div style={{ fontSize: "11px", fontWeight: "700", color: "#1e293b", marginTop: "2px" }}>
                          {grp.name}
                        </div>
                        <div style={{ fontSize: "10px", color: "#64748b" }}>
                          {grp.subnet}
                        </div>
                      </div>

                      {/* Endpoint Cards inside this VLAN */}
                      <div style={{ display: "flex", flexDirection: "column", gap: "8px", flex: 1, maxHeight: "380px", overflowY: "auto", paddingRight: "4px" }}>
                        {grp.devices.length === 0 ? (
                          <div style={{ textAlign: "center", padding: "20px 8px", fontSize: "11px", color: "#94a3b8" }}>
                            No active devices in this VLAN
                          </div>
                        ) : (
                          grp.devices.map((d) => {
                            const isSelected = selectedNode?.type === "device" && selectedNode?.data?.id === d.id;
                            const isQuarantine = d.vlan_id === 90 || d.enforcement_status === "quarantined";
                            return (
                              <div
                                key={d.id}
                                onClick={() => setSelectedNode({ type: "device", data: d })}
                                style={{
                                  background: "#ffffff",
                                  border: isSelected ? "2px solid #2563eb" : `1px solid ${isQuarantine ? "#fca5a5" : "#e2e8f0"}`,
                                  borderRadius: "8px",
                                  padding: "8px 10px",
                                  cursor: "pointer",
                                  boxShadow: isSelected ? "0 0 0 2px rgba(37,99,235,0.2)" : "0 1px 2px rgba(0,0,0,0.04)",
                                  display: "flex",
                                  alignItems: "center",
                                  gap: "8px",
                                  transition: "all 0.15s ease",
                                }}
                              >
                                <div style={{ fontSize: "18px" }}>{getDeviceIcon(d.device_type)}</div>
                                <div style={{ flex: 1, minWidth: 0 }}>
                                  <div style={{ fontSize: "11px", fontWeight: "700", color: "#0f172a", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                                    {d.hostname || d.ip_address || "LAN Device"}
                                  </div>
                                  <div style={{ fontSize: "10px", color: "#64748b", fontFamily: "monospace" }}>
                                    {d.ip_address || "No IP"}
                                  </div>
                                </div>
                                <div>
                                  <span
                                    style={{
                                      width: "8px",
                                      height: "8px",
                                      borderRadius: "50%",
                                      display: "inline-block",
                                      background: d.status === "online" ? "#10b981" : "#94a3b8",
                                    }}
                                    title={d.status === "online" ? "Online" : "Offline"}
                                  />
                                </div>
                              </div>
                            );
                          })
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ) : (
            /* ALTERNATE SUBNET CLUSTERS VIEW */
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "20px" }}>
              {[10, 20, 30, 90].map((vid) => {
                const grp = vlanGroups[vid];
                return (
                  <div key={vid} style={{ background: "#ffffff", border: `2px solid ${grp.border}`, borderRadius: "12px", padding: "16px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                      <span style={{ fontSize: "16px", fontWeight: "900", color: grp.color }}>VLAN {vid}</span>
                      <span style={{ background: grp.bg, color: grp.color, padding: "2px 8px", borderRadius: "10px", fontSize: "11px", fontWeight: "800" }}>
                        {grp.devices.length} Endpoint(s)
                      </span>
                    </div>
                    <div style={{ fontWeight: "700", fontSize: "13px", color: "#1e293b" }}>{grp.name}</div>
                    <div style={{ fontSize: "11px", color: "#64748b", marginBottom: "14px" }}>CIDR: {grp.subnet}</div>

                    <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                      {grp.devices.map((d) => (
                        <div
                          key={d.id}
                          onClick={() => setSelectedNode({ type: "device", data: d })}
                          style={{
                            padding: "8px 10px",
                            background: "#f8fafc",
                            border: "1px solid #e2e8f0",
                            borderRadius: "6px",
                            cursor: "pointer",
                            fontSize: "12px",
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                          }}
                        >
                          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                            <span>{getDeviceIcon(d.device_type)}</span>
                            <div>
                              <div style={{ fontWeight: "700", color: "#0f172a" }}>{d.hostname || "Device"}</div>
                              <div style={{ fontSize: "10px", color: "#64748b", fontFamily: "monospace" }}>{d.ip_address}</div>
                            </div>
                          </div>
                          <span style={{ fontSize: "10px", fontWeight: "800", color: d.status === "online" ? "#166534" : "#94a3b8" }}>
                            {d.status?.toUpperCase()}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* SIDE-DRAWER INSPECTOR */}
        {selectedNode && (
          <div className="panel" style={{ background: "#ffffff", border: "1.5px solid #2563eb", borderRadius: "12px", padding: "18px", boxShadow: "0 4px 6px -1px rgba(0,0,0,0.1)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "12px" }}>
              <div>
                <div style={{ fontSize: "11px", fontWeight: "800", color: "#2563eb", textTransform: "uppercase" }}>
                  Node Inspection
                </div>
                <div style={{ fontSize: "16px", fontWeight: "800", color: "#0f172a" }}>
                  {selectedNode.type === "device" ? (selectedNode.data.hostname || selectedNode.data.ip_address || "Endpoint") : selectedNode.data.name || selectedNode.data.vendor_title}
                </div>
              </div>
              <button
                type="button"
                style={{ background: "transparent", border: "none", color: "#64748b", fontSize: "20px", cursor: "pointer" }}
                onClick={() => setSelectedNode(null)}
              >
                ×
              </button>
            </div>

            {selectedNode.type === "device" && (
              <div style={{ display: "flex", flexDirection: "column", gap: "10px", fontSize: "12px" }}>
                <div style={{ background: "#f8fafc", padding: "8px 10px", borderRadius: "6px" }}>
                  <div style={{ color: "#64748b", fontSize: "10px" }}>MAC ADDRESS</div>
                  <div style={{ fontWeight: "700", fontFamily: "monospace" }}>{selectedNode.data.mac_address}</div>
                </div>

                <div style={{ background: "#f8fafc", padding: "8px 10px", borderRadius: "6px" }}>
                  <div style={{ color: "#64748b", fontSize: "10px" }}>IP ADDRESS</div>
                  <div style={{ fontWeight: "700" }}>{selectedNode.data.ip_address || "No IP Assigned"}</div>
                </div>

                <div style={{ background: "#f8fafc", padding: "8px 10px", borderRadius: "6px" }}>
                  <div style={{ color: "#64748b", fontSize: "10px" }}>VLAN &amp; SUBNET</div>
                  <div style={{ fontWeight: "700", color: selectedNode.data.vlan_id === 90 ? "#dc2626" : "#2563eb" }}>
                    VLAN {selectedNode.data.vlan_id || 90} ({selectedNode.data.vlan_id === 90 ? "Quarantine" : "Active Segment"})
                  </div>
                </div>

                <div style={{ background: "#f8fafc", padding: "8px 10px", borderRadius: "6px" }}>
                  <div style={{ color: "#64748b", fontSize: "10px" }}>SWITCH &amp; PORT</div>
                  <div style={{ fontWeight: "700" }}>
                    {selectedNode.data.switch_name || activeSwitch.name} • {selectedNode.data.switch_port || "GigabitEthernet 0/1"}
                  </div>
                </div>

                <div style={{ background: "#f8fafc", padding: "8px 10px", borderRadius: "6px" }}>
                  <div style={{ color: "#64748b", fontSize: "10px" }}>VENDOR &amp; HARDWARE TYPE</div>
                  <div style={{ fontWeight: "700" }}>
                    {selectedNode.data.vendor || "Generic Hardware"} ({selectedNode.data.device_type || "computer"})
                  </div>
                </div>

                <div style={{ background: "#f8fafc", padding: "8px 10px", borderRadius: "6px" }}>
                  <div style={{ color: "#64748b", fontSize: "10px" }}>SECURITY STATUS</div>
                  <div style={{ fontWeight: "700" }}>
                    Approval: <strong>{selectedNode.data.approval_status?.toUpperCase()}</strong> • Enforcement: <strong>{selectedNode.data.enforcement_status?.toUpperCase()}</strong>
                  </div>
                </div>

                {/* ACTION BUTTONS */}
                <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginTop: "8px" }}>
                  {handleOpenCveModal && (
                    <button
                      type="button"
                      className="primary-button small"
                      style={{ background: "#b91c1c", borderColor: "#991b1b" }}
                      onClick={() => handleOpenCveModal(selectedNode.data)}
                    >
                      🛡️ Audit CVE Vulnerabilities
                    </button>
                  )}
                  {handleRunTroubleshoot && (
                    <button
                      type="button"
                      className="secondary-button small"
                      onClick={() => handleRunTroubleshoot(selectedNode.data)}
                    >
                      🩺 Troubleshoot &amp; Diagnose
                    </button>
                  )}
                </div>
              </div>
            )}

            {selectedNode.type === "switch" && (
              <div style={{ display: "flex", flexDirection: "column", gap: "10px", fontSize: "12px" }}>
                <div style={{ background: "#f8fafc", padding: "8px 10px", borderRadius: "6px" }}>
                  <div style={{ color: "#64748b", fontSize: "10px" }}>CHASSIS ARCHITECTURE &amp; DENSITY</div>
                  <div style={{ fontWeight: "800", color: is48PortSwitch ? "#6d28d9" : "#1d4ed8" }}>
                    {is48PortSwitch ? "48-Port Enterprise Chassis (High-Density 1U)" : "24-Port Standard Chassis (1U)"}
                  </div>
                </div>

                <div style={{ background: "#f8fafc", padding: "8px 10px", borderRadius: "6px" }}>
                  <div style={{ color: "#64748b", fontSize: "10px" }}>SWITCH MODEL &amp; VENDOR</div>
                  <div style={{ fontWeight: "700" }}>
                    {selectedNode.data.model || (is48PortSwitch ? "Cisco Catalyst 2960X-48TS-L" : "Cisco Catalyst 2960-X")} ({selectedNode.data.vendor})
                  </div>
                </div>

                <div style={{ background: "#f8fafc", padding: "8px 10px", borderRadius: "6px" }}>
                  <div style={{ color: "#64748b", fontSize: "10px" }}>MANAGEMENT IP</div>
                  <div style={{ fontWeight: "700", fontFamily: "monospace" }}>{selectedNode.data.management_ip || "192.168.0.2"}</div>
                </div>

                <div style={{ background: "#f8fafc", padding: "8px 10px", borderRadius: "6px" }}>
                  <div style={{ color: "#64748b", fontSize: "10px" }}>PHYSICAL INTERFACES BREAKDOWN</div>
                  <div style={{ fontWeight: "700", marginTop: "2px" }}>
                    • {is48PortSwitch ? "48x 10/100/1000BaseTX Copper Ports (Gi0/1 - Gi0/48)" : "24x 10/100/1000BaseTX Copper Ports (Gi0/1 - Gi0/24)"}
                  </div>
                  {is48PortSwitch && (
                    <div style={{ fontWeight: "700", color: "#7c3aed", marginTop: "2px" }}>
                      • 4x 10-Gigabit SFP+ Optical Cages (Te0/49 - Te0/52)
                    </div>
                  )}
                </div>

                <div style={{ background: "#f8fafc", padding: "8px 10px", borderRadius: "6px" }}>
                  <div style={{ color: "#64748b", fontSize: "10px" }}>PORT UTILIZATION &amp; LINK HEALTH</div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "4px" }}>
                    <span style={{ fontWeight: "700" }}>
                      {connectedPorts.length || (is48PortSwitch ? 28 : 14)} of {switchPorts.length || (is48PortSwitch ? 52 : 24)} Ports Active
                    </span>
                    <span style={{ fontSize: "11px", fontWeight: "800", color: "#166534" }}>
                      {Math.round(((connectedPorts.length || (is48PortSwitch ? 28 : 14)) / (switchPorts.length || (is48PortSwitch ? 52 : 24))) * 100)}%
                    </span>
                  </div>
                  <div style={{ height: "6px", background: "#e2e8f0", borderRadius: "3px", marginTop: "6px", overflow: "hidden" }}>
                    <div
                      style={{
                        height: "100%",
                        width: `${Math.round(((connectedPorts.length || (is48PortSwitch ? 28 : 14)) / (switchPorts.length || (is48PortSwitch ? 52 : 24))) * 100)}%`,
                        background: is48PortSwitch ? "#8b5cf6" : "#2563eb",
                        borderRadius: "3px",
                      }}
                    />
                  </div>
                </div>

                <div style={{ background: "#f8fafc", padding: "8px 10px", borderRadius: "6px" }}>
                  <div style={{ color: "#64748b", fontSize: "10px" }}>SECURITY &amp; NAC PROTOCOLS</div>
                  <div style={{ fontWeight: "700" }}>IEEE 802.1X • RADIUS MAB • Rapid-PVST+ • BPDU Guard Active</div>
                </div>
              </div>
            )}

            {selectedNode.type === "gateway" && (
              <div style={{ display: "flex", flexDirection: "column", gap: "10px", fontSize: "12px" }}>
                <div style={{ background: "#f8fafc", padding: "8px 10px", borderRadius: "6px" }}>
                  <div style={{ color: "#64748b", fontSize: "10px" }}>GATEWAY PLATFORM</div>
                  <div style={{ fontWeight: "700" }}>{selectedNode.data.vendor_title}</div>
                </div>
                <div style={{ background: "#f8fafc", padding: "8px 10px", borderRadius: "6px" }}>
                  <div style={{ color: "#64748b", fontSize: "10px" }}>ROLE</div>
                  <div style={{ fontWeight: "700" }}>Edge Firewall &amp; Zero-Trust Dynamic Isolation</div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
