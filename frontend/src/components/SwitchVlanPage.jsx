import React, { useEffect, useState } from "react";

export default function SwitchVlanPage({ API_URL, currentUser, getAuthHeaders, devices = [] }) {
  const isAdmin = currentUser?.role === "admin" || currentUser?.role === "super_admin";
  const [activeTab, setActiveTab] = useState("vlans"); // "vlans" | "ports" | "switch_settings"

  // Data states
  const [vlans, setVlans] = useState([]);
  const [ports, setPorts] = useState([]);
  const [activeSwitch, setActiveSwitch] = useState(null);
  const [switchVendors, setSwitchVendors] = useState([]);
  const [savedConfigs, setSavedConfigs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState({ text: "", type: "" });

  // Create VLAN Modal
  const [showCreateVlanModal, setShowCreateVlanModal] = useState(false);
  const [newVlanId, setNewVlanId] = useState("");
  const [newVlanName, setNewVlanName] = useState("");
  const [newVlanDescription, setNewVlanDescription] = useState("");
  const [newVlanSubnet, setNewVlanSubnet] = useState("");
  const [creatingVlan, setCreatingVlan] = useState(false);

  // Assign Port Modal
  const [selectedPort, setSelectedPort] = useState(null);
  const [targetVlanId, setTargetVlanId] = useState("");
  const [assigningPort, setAssigningPort] = useState(false);

  // Switch Config Form
  const [switchForm, setSwitchForm] = useState({
    id: null,
    vendor: "cisco_ios",
    name: "Core Switch 1 (Cisco Catalyst)",
    management_ip: "192.168.0.2",
    port: 22,
    username: "admin",
    password: "",
    enable_secret: "",
    connection_protocol: "ssh",
    model: "Cisco Catalyst 2960-X",
    total_ports: 24,
    description: "Main Access Switch for LAN workstations and VoIP",
    is_active: true,
  });
  const [testingSwitch, setTestingSwitch] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [savingSwitch, setSavingSwitch] = useState(false);

  const showStatus = (text, type = "success") => {
    setStatusMessage({ text, type });
    setTimeout(() => setStatusMessage({ text: "", type: "" }), 5000);
  };

  const loadAllData = async () => {
    setLoading(true);
    try {
      const headers = getAuthHeaders ? getAuthHeaders() : {};
      const [vlanRes, portRes, activeRes, vendorRes, configRes] = await Promise.all([
        fetch(`${API_URL}/switches/vlans`, { headers }).then((r) => r.json()).catch(() => []),
        fetch(`${API_URL}/switches/ports`, { headers }).then((r) => r.json()).catch(() => []),
        fetch(`${API_URL}/switches/active`, { headers }).then((r) => r.json()).catch(() => null),
        fetch(`${API_URL}/switches/vendors`, { headers }).then((r) => r.json()).catch(() => []),
        fetch(`${API_URL}/switches/configs`, { headers }).then((r) => r.json()).catch(() => []),
      ]);

      if (Array.isArray(vlanRes)) setVlans(vlanRes);
      if (Array.isArray(portRes)) setPorts(portRes);
      if (activeRes) setActiveSwitch(activeRes);
      if (Array.isArray(vendorRes)) setSwitchVendors(vendorRes);
      if (Array.isArray(configRes)) setSavedConfigs(configRes);
    } catch (err) {
      console.error("Failed to load switch data:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAllData();
    const interval = setInterval(loadAllData, 20000);
    return () => clearInterval(interval);
  }, []);

  // Handle Create VLAN
  const handleCreateVlan = async (e) => {
    if (e) e.preventDefault();
    if (!newVlanId || !newVlanName) {
      showStatus("Please enter both VLAN ID and Name.", "error");
      return;
    }
    const vid = parseInt(newVlanId, 10);
    if (isNaN(vid) || vid < 1 || vid > 4094) {
      showStatus("VLAN ID must be a number between 1 and 4094.", "error");
      return;
    }

    setCreatingVlan(true);
    try {
      const res = await fetch(`${API_URL}/switches/vlans`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...getAuthHeaders() },
        body: JSON.stringify({
          vlan_id: vid,
          name: newVlanName.trim(),
          description: newVlanDescription.trim() || null,
          subnet: newVlanSubnet.trim() || null,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to create VLAN on switch.");

      showStatus(`VLAN ${vid} ('${newVlanName}') successfully provisioned to switch!`, "success");
      setShowCreateVlanModal(false);
      setNewVlanId("");
      setNewVlanName("");
      setNewVlanDescription("");
      setNewVlanSubnet("");
      await loadAllData();
    } catch (err) {
      showStatus(err.message, "error");
    } finally {
      setCreatingVlan(false);
    }
  };

  // Handle Delete VLAN
  const handleDeleteVlan = async (vlanId, vlanName) => {
    if (!window.confirm(`Are you sure you want to delete VLAN ${vlanId} ('${vlanName}') from the switch? This will remove its configuration.`)) {
      return;
    }
    try {
      const res = await fetch(`${API_URL}/switches/vlans/${vlanId}`, {
        method: "DELETE",
        headers: getAuthHeaders(),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to delete VLAN.");
      showStatus(`VLAN ${vlanId} removed from switch.`, "success");
      await loadAllData();
    } catch (err) {
      showStatus(err.message, "error");
    }
  };

  // Handle Assign Port VLAN
  const handleAssignPort = async (e) => {
    if (e) e.preventDefault();
    if (!selectedPort || !targetVlanId) return;

    setAssigningPort(true);
    try {
      const res = await fetch(`${API_URL}/switches/ports/assign`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...getAuthHeaders() },
        body: JSON.stringify({
          port_name: selectedPort.port,
          vlan_id: parseInt(targetVlanId, 10),
          mode: "access",
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to assign port VLAN.");

      showStatus(`Port ${selectedPort.port} reconfigured to VLAN ${targetVlanId} successfully!`, "success");
      setSelectedPort(null);
      await loadAllData();
    } catch (err) {
      showStatus(err.message, "error");
    } finally {
      setAssigningPort(false);
    }
  };

  // Instant Port Quarantine
  const handleQuarantinePort = async (portObj) => {
    if (!window.confirm(`Quarantine switch port ${portObj.port}? This will immediately reconfigure it to Quarantine VLAN 90.`)) {
      return;
    }
    try {
      const res = await fetch(`${API_URL}/switches/ports/assign`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...getAuthHeaders() },
        body: JSON.stringify({
          port_name: portObj.port,
          vlan_id: 90,
          mode: "access",
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to quarantine port.");
      showStatus(`Port ${portObj.port} isolated into Quarantine VLAN 90.`, "success");
      await loadAllData();
    } catch (err) {
      showStatus(err.message, "error");
    }
  };

  // Test Switch Connection
  const handleTestConnection = async () => {
    setTestingSwitch(true);
    setTestResult(null);
    try {
      const res = await fetch(`${API_URL}/switches/test-connection`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...getAuthHeaders() },
        body: JSON.stringify({
          vendor: switchForm.vendor,
          management_ip: switchForm.management_ip.trim(),
          port: parseInt(switchForm.port, 10) || 22,
          username: switchForm.username?.trim() || null,
          password: switchForm.password || null,
          enable_secret: switchForm.enable_secret || null,
        }),
      });
      const data = await res.json();
      setTestResult(data);
      if (data.success) {
        showStatus("Switch reachable! Credentials and CLI verified.", "success");
      } else {
        showStatus(data.message || "Switch connection test failed.", "error");
      }
    } catch (err) {
      showStatus(err.message || "Failed to test connection.", "error");
    } finally {
      setTestingSwitch(false);
    }
  };

  // Save Switch Profile
  const handleSaveSwitch = async (e) => {
    if (e) e.preventDefault();
    setSavingSwitch(true);
    try {
      const res = await fetch(`${API_URL}/switches/configs`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...getAuthHeaders() },
        body: JSON.stringify(switchForm),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to save switch profile.");

      showStatus(`Switch profile '${switchForm.name}' saved and activated!`, "success");
      await loadAllData();
    } catch (err) {
      showStatus(err.message, "error");
    } finally {
      setSavingSwitch(false);
    }
  };

  // Activate Switch Profile
  const handleActivateSwitch = async (id, name) => {
    try {
      const res = await fetch(`${API_URL}/switches/configs/${id}/activate`, {
        method: "POST",
        headers: getAuthHeaders(),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to activate switch profile.");
      showStatus(`Switch profile '${name}' is now active.`, "success");
      await loadAllData();
    } catch (err) {
      showStatus(err.message, "error");
    }
  };

  // Get VLAN Color Theme
  const getVlanColor = (vid) => {
    switch (vid) {
      case 10: return { bg: "#ecfdf5", border: "#10b981", text: "#065f46", chip: "#34d399" }; // Green (VoIP)
      case 20: return { bg: "#eff6ff", border: "#3b82f6", text: "#1e40af", chip: "#60a5fa" }; // Blue (Computers)
      case 30: return { bg: "#f5f3ff", border: "#8b5cf6", text: "#5b21b6", chip: "#a78bfa" }; // Purple (CCTV)
      case 40: return { bg: "#fffbeb", border: "#f59e0b", text: "#92400e", chip: "#fbbf24" }; // Amber (Printers)
      case 50: return { bg: "#f0fdf4", border: "#16a34a", text: "#14532d", chip: "#4ade80" }; // Emerald (Servers)
      case 60: return { bg: "#ecfeff", border: "#06b6d4", text: "#155e75", chip: "#22d3ee" }; // Cyan (WiFi APs)
      case 90: return { bg: "#fef2f2", border: "#ef4444", text: "#991b1b", chip: "#f87171" }; // Red (Quarantine)
      default: return { bg: "#f8fafc", border: "#94a3b8", text: "#334155", chip: "#cbd5e1" }; // Gray
    }
  };

  const connectedPortsCount = ports.filter((p) => p.status === "connected").length;
  const quarantinePortsCount = ports.filter((p) => p.vlan === 90).length;

  return (
    <div className="page">
      <div className="page-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "16px" }}>
        <div>
          <div className="page-title" style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <span>🔀</span>
            <span>Switch & VLAN Automation Center</span>
          </div>
          <div className="page-description">
            Zero-Console Network Provisioning: configure enterprise switches, create & deploy VLANs, and assign physical switch ports directly from the web interface.
          </div>
        </div>

        {isAdmin && (
          <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
            <button
              type="button"
              className="primary-button"
              onClick={() => setShowCreateVlanModal(true)}
              style={{ display: "flex", alignItems: "center", gap: "6px" }}
            >
              <span>➕</span> Create New VLAN on Switch
            </button>
            <button
              type="button"
              className="secondary-button"
              onClick={loadAllData}
              disabled={loading}
              title="Refresh live VLANs and switch ports"
            >
              🔄 Refresh
            </button>
          </div>
        )}
      </div>

      {statusMessage.text && (
        <div
          style={{
            background: statusMessage.type === "success" ? "#ecfdf5" : "#fef2f2",
            border: `1px solid ${statusMessage.type === "success" ? "#a7f3d0" : "#fecaca"}`,
            color: statusMessage.type === "success" ? "#065f46" : "#991b1b",
            padding: "12px 16px",
            borderRadius: "8px",
            marginBottom: "16px",
            fontWeight: "600",
            fontSize: "13px",
            display: "flex",
            alignItems: "center",
            gap: "8px",
          }}
        >
          <span>{statusMessage.type === "success" ? "✓" : "⚠️"}</span>
          <span>{statusMessage.text}</span>
        </div>
      )}

      {/* STATS HEADER CARDS */}
      <div className="stats-grid" style={{ marginBottom: "20px" }}>
        <div className="stat-card">
          <div className="stat-label">ACTIVE NETWORK SWITCH</div>
          <div className="stat-value" style={{ fontSize: "16px", fontWeight: "800", color: "#0f172a", marginTop: "4px" }}>
            {activeSwitch?.config?.name || "Cisco Catalyst 2960-X"}
          </div>
          <div style={{ fontSize: "12px", color: "#64748b", marginTop: "4px" }}>
            IP: <strong>{activeSwitch?.config?.management_ip || "192.168.0.2"}</strong> ({activeSwitch?.driver_title?.split("(")[0] || "Cisco IOS-XE"})
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-label">TOTAL CONFIGURED VLANS</div>
          <div className="stat-value" style={{ color: "#2563eb" }}>{vlans.length}</div>
          <div style={{ fontSize: "12px", color: "#64748b", marginTop: "4px" }}>
            Active on Switch NVRAM
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-label">SWITCH PORTS CONNECTED</div>
          <div className="stat-value" style={{ color: "#059669" }}>
            {connectedPortsCount} <span style={{ fontSize: "14px", color: "#64748b", fontWeight: "normal" }}>/ {ports.length || 24}</span>
          </div>
          <div style={{ fontSize: "12px", color: "#64748b", marginTop: "4px" }}>
            Active Gigabit Ethernet Links
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-label">QUARANTINE ISOLATION (VLAN 90)</div>
          <div className="stat-value" style={{ color: quarantinePortsCount > 0 ? "#dc2626" : "#475569" }}>
            {quarantinePortsCount}
          </div>
          <div style={{ fontSize: "12px", color: "#64748b", marginTop: "4px" }}>
            Ports currently isolated in VLAN 90
          </div>
        </div>
      </div>

      {/* NAVIGATION TABS */}
      <div style={{ display: "flex", gap: "10px", borderBottom: "2px solid #e2e8f0", marginBottom: "20px" }}>
        <button
          type="button"
          onClick={() => setActiveTab("vlans")}
          style={{
            padding: "10px 18px",
            border: "none",
            background: "transparent",
            fontWeight: activeTab === "vlans" ? "800" : "600",
            color: activeTab === "vlans" ? "#2563eb" : "#64748b",
            borderBottom: activeTab === "vlans" ? "3px solid #2563eb" : "3px solid transparent",
            cursor: "pointer",
            fontSize: "14px",
            display: "flex",
            alignItems: "center",
            gap: "8px",
          }}
        >
          <span>🏷️</span> VLAN Management Table ({vlans.length})
        </button>

        <button
          type="button"
          onClick={() => setActiveTab("ports")}
          style={{
            padding: "10px 18px",
            border: "none",
            background: "transparent",
            fontWeight: activeTab === "ports" ? "800" : "600",
            color: activeTab === "ports" ? "#2563eb" : "#64748b",
            borderBottom: activeTab === "ports" ? "3px solid #2563eb" : "3px solid transparent",
            cursor: "pointer",
            fontSize: "14px",
            display: "flex",
            alignItems: "center",
            gap: "8px",
          }}
        >
          <span>🔌</span> 24-Port Switch Panel & Matrix
        </button>

        {isAdmin && (
          <button
            type="button"
            onClick={() => setActiveTab("switch_settings")}
            style={{
              padding: "10px 18px",
              border: "none",
              background: "transparent",
              fontWeight: activeTab === "switch_settings" ? "800" : "600",
              color: activeTab === "switch_settings" ? "#2563eb" : "#64748b",
              borderBottom: activeTab === "switch_settings" ? "3px solid #2563eb" : "3px solid transparent",
              cursor: "pointer",
              fontSize: "14px",
              display: "flex",
              alignItems: "center",
              gap: "8px",
            }}
          >
            <span>⚙️</span> Multi-Vendor Switch Configuration
          </button>
        )}
      </div>

      {/* ======================================================== */}
      {/* TAB 1: VLANS TABLE                                       */}
      {/* ======================================================== */}
      {activeTab === "vlans" && (
        <div>
          {/* VLAN QUICK CARDS GRID */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: "12px", marginBottom: "24px" }}>
            {vlans.map((v) => {
              const theme = getVlanColor(v.vlan_id);
              const matchingDevices = devices.filter((d) => d.vlan_id === v.vlan_id);
              return (
                <div
                  key={v.vlan_id}
                  style={{
                    background: theme.bg,
                    border: `1.5px solid ${theme.border}`,
                    borderRadius: "10px",
                    padding: "14px",
                    boxShadow: "0 1px 3px rgba(0,0,0,0.05)",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ fontSize: "16px", fontWeight: "900", color: theme.text }}>
                      VLAN {v.vlan_id}
                    </span>
                    <span
                      style={{
                        background: theme.chip,
                        color: "#ffffff",
                        padding: "2px 8px",
                        borderRadius: "12px",
                        fontSize: "10px",
                        fontWeight: "800",
                      }}
                    >
                      {v.is_quarantine ? "ISOLATION" : "ACTIVE"}
                    </span>
                  </div>

                  <div style={{ fontWeight: "700", color: "#0f172a", fontSize: "13px", marginTop: "6px" }}>
                    {v.name}
                  </div>

                  <div style={{ fontSize: "11px", color: "#64748b", marginTop: "4px" }}>
                    {v.description || (v.subnet ? `Subnet: ${v.subnet}` : "Enterprise Segment")}
                  </div>

                  <div style={{ marginTop: "10px", paddingTop: "8px", borderTop: `1px solid ${theme.border}44`, display: "flex", justifyContent: "space-between", fontSize: "11px", color: "#475569" }}>
                    <span>Devices: <strong>{matchingDevices.length}</strong></span>
                    <span>Status: <strong style={{ color: "#059669" }}>Live</strong></span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* VLANS DETAILED TABLE */}
          <div className="panel" style={{ padding: 0 }}>
            <div style={{ padding: "16px 20px", borderBottom: "1px solid #e2e8f0", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div style={{ fontSize: "15px", fontWeight: "700", color: "#0f172a" }}>
                Active Switch VLAN Directory
              </div>
              <div style={{ fontSize: "12px", color: "#64748b" }}>
                Pushed via SSH CLI & stored in running-config
              </div>
            </div>

            <div className="table-responsive">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>VLAN ID</th>
                    <th>VLAN Name</th>
                    <th>Segment Purpose / Description</th>
                    <th>Subnet</th>
                    <th>Assigned Ports</th>
                    <th>Status</th>
                    {isAdmin && <th style={{ textAlign: "right" }}>Actions</th>}
                  </tr>
                </thead>
                <tbody>
                  {vlans.map((v) => {
                    const theme = getVlanColor(v.vlan_id);
                    return (
                      <tr key={v.vlan_id}>
                        <td>
                          <span
                            style={{
                              background: theme.bg,
                              border: `1px solid ${theme.border}`,
                              color: theme.text,
                              fontWeight: "800",
                              fontSize: "12px",
                              padding: "3px 8px",
                              borderRadius: "6px",
                            }}
                          >
                            VLAN {v.vlan_id}
                          </span>
                        </td>
                        <td>
                          <strong>{v.name}</strong>
                          {v.is_default && <span style={{ marginLeft: "6px", fontSize: "10px", color: "#64748b" }}>(Default)</span>}
                        </td>
                        <td>{v.description || "—"}</td>
                        <td><code>{v.subnet || "DHCP Pool"}</code></td>
                        <td>
                          <span style={{ fontSize: "12px", color: "#334155" }}>
                            {v.ports || "Dynamic / Untagged"}
                          </span>
                        </td>
                        <td>
                          <span className="status-badge online" style={{ fontSize: "10px" }}>
                            🟢 {v.status || "active"}
                          </span>
                        </td>
                        {isAdmin && (
                          <td style={{ textAlign: "right" }}>
                            {v.is_default || v.is_quarantine ? (
                              <span style={{ fontSize: "11px", color: "#94a3b8", fontStyle: "italic" }}>
                                System Protected
                              </span>
                            ) : (
                              <button
                                type="button"
                                className="secondary-button small"
                                style={{ color: "#dc2626", borderColor: "#fca5a5" }}
                                onClick={() => handleDeleteVlan(v.vlan_id, v.name)}
                                title="Delete this VLAN from the switch"
                              >
                                🗑️ Delete
                              </button>
                            )}
                          </td>
                        )}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ======================================================== */}
      {/* TAB 2: 24-PORT SWITCH MATRIX & FRONT PANEL               */}
      {/* ======================================================== */}
      {activeTab === "ports" && (
        <div>
          <div className="panel" style={{ marginBottom: "20px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px", flexWrap: "wrap", gap: "10px" }}>
              <div>
                <div style={{ fontSize: "16px", fontWeight: "800", color: "#0f172a" }}>
                  Physical Switch Front Panel (24 Ports)
                </div>
                <div style={{ fontSize: "12px", color: "#64748b" }}>
                  Live port visualization. Click any port to change its VLAN assignment without console login.
                </div>
              </div>
              <div style={{ display: "flex", gap: "12px", alignItems: "center", fontSize: "12px" }}>
                <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                  <span style={{ width: "10px", height: "10px", borderRadius: "50%", background: "#10b981", display: "inline-block" }}></span> Connected
                </span>
                <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                  <span style={{ width: "10px", height: "10px", borderRadius: "50%", background: "#94a3b8", display: "inline-block" }}></span> Idle / Disconnected
                </span>
                <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                  <span style={{ width: "10px", height: "10px", borderRadius: "50%", background: "#ef4444", display: "inline-block" }}></span> Quarantine (90)
                </span>
              </div>
            </div>

            {/* SWITCH CHASSIS RACK SIMULATOR */}
            <div
              style={{
                background: "#0f172a",
                borderRadius: "12px",
                padding: "20px",
                boxShadow: "inset 0 2px 4px rgba(0,0,0,0.5)",
                border: "2px solid #334155",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", color: "#94a3b8", fontSize: "11px", marginBottom: "12px", fontWeight: "700", letterSpacing: "1px" }}>
                <span>CISCO CATALYST 2960-X SERIES 24-PORT GIGABIT</span>
                <span style={{ color: "#38bdf8" }}>MANAGEMENT: {activeSwitch?.config?.management_ip || "192.168.0.2"}</span>
              </div>

              {/* 24-PORT MATRIX (2 ROWS OF 12 PORTS) */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(12, 1fr)", gap: "8px" }}>
                {ports.map((p, idx) => {
                  const isUp = p.status === "connected";
                  const isQuarantine = p.vlan === 90;
                  const theme = getVlanColor(p.vlan);

                  return (
                    <div
                      key={p.port || idx}
                      onClick={() => {
                        if (isAdmin) {
                          setSelectedPort(p);
                          setTargetVlanId(String(p.vlan));
                        }
                      }}
                      style={{
                        background: "#1e293b",
                        border: `2px solid ${isQuarantine ? "#ef4444" : isUp ? theme.border : "#334155"}`,
                        borderRadius: "8px",
                        padding: "8px 4px",
                        textAlign: "center",
                        cursor: isAdmin ? "pointer" : "default",
                        transition: "all 0.15s ease",
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.transform = "translateY(-2px)";
                        e.currentTarget.style.boxShadow = "0 4px 6px rgba(0,0,0,0.3)";
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.transform = "none";
                        e.currentTarget.style.boxShadow = "none";
                      }}
                      title={`Click to reassign ${p.port} (Current: VLAN ${p.vlan})`}
                    >
                      {/* LINK LED */}
                      <div style={{ display: "flex", justifyContent: "center", marginBottom: "4px" }}>
                        <span
                          style={{
                            width: "8px",
                            height: "8px",
                            borderRadius: "50%",
                            background: isUp ? "#10b981" : "#475569",
                            boxShadow: isUp ? "0 0 6px #10b981" : "none",
                            display: "inline-block",
                          }}
                        />
                      </div>

                      {/* PORT NUMBER */}
                      <div style={{ fontSize: "11px", fontWeight: "800", color: "#f8fafc" }}>
                        {p.short_name || `P${idx + 1}`}
                      </div>

                      {/* CURRENT VLAN BADGE */}
                      <div
                        style={{
                          marginTop: "6px",
                          fontSize: "10px",
                          fontWeight: "800",
                          background: isQuarantine ? "#ef4444" : theme.chip,
                          color: "#ffffff",
                          borderRadius: "4px",
                          padding: "1px 2px",
                        }}
                      >
                        V{p.vlan}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* PORTS TABLE */}
          <div className="panel" style={{ padding: 0 }}>
            <div style={{ padding: "16px 20px", borderBottom: "1px solid #e2e8f0" }}>
              <div style={{ fontSize: "15px", fontWeight: "700", color: "#0f172a" }}>
                Switch Interface Directory & VLAN Mapping
              </div>
            </div>

            <div className="table-responsive">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Interface</th>
                    <th>Link Status</th>
                    <th>Assigned VLAN</th>
                    <th>Port Mode</th>
                    <th>Speed / Duplex</th>
                    <th>Connected Device MAC</th>
                    {isAdmin && <th style={{ textAlign: "right" }}>Actions</th>}
                  </tr>
                </thead>
                <tbody>
                  {ports.map((p) => {
                    const theme = getVlanColor(p.vlan);
                    return (
                      <tr key={p.port}>
                        <td><strong>{p.port}</strong></td>
                        <td>
                          {p.status === "connected" ? (
                            <span className="status-badge online" style={{ fontSize: "10px" }}>🟢 connected</span>
                          ) : (
                            <span className="status-badge offline" style={{ fontSize: "10px" }}>⚪ notconnect</span>
                          )}
                        </td>
                        <td>
                          <span
                            style={{
                              background: theme.bg,
                              border: `1px solid ${theme.border}`,
                              color: theme.text,
                              fontWeight: "800",
                              fontSize: "12px",
                              padding: "2px 8px",
                              borderRadius: "6px",
                            }}
                          >
                            VLAN {p.vlan}
                          </span>
                        </td>
                        <td><code>{p.mode || "access"}</code></td>
                        <td>{p.speed || "1Gbps"} / {p.duplex || "full"}</td>
                        <td>
                          {p.connected_mac ? (
                            <code style={{ color: "#2563eb" }}>{p.connected_mac}</code>
                          ) : (
                            <span style={{ color: "#94a3b8" }}>—</span>
                          )}
                        </td>
                        {isAdmin && (
                          <td style={{ textAlign: "right" }}>
                            <div style={{ display: "flex", justifyContent: "flex-end", gap: "6px" }}>
                              <button
                                type="button"
                                className="secondary-button small"
                                onClick={() => {
                                  setSelectedPort(p);
                                  setTargetVlanId(String(p.vlan));
                                }}
                              >
                                ✏️ Assign VLAN
                              </button>
                              {p.vlan !== 90 && (
                                <button
                                  type="button"
                                  className="secondary-button small"
                                  style={{ color: "#dc2626", borderColor: "#fca5a5" }}
                                  onClick={() => handleQuarantinePort(p)}
                                  title="Instantly isolate this port to Quarantine VLAN 90"
                                >
                                  🔒 Quarantine
                                </button>
                              )}
                            </div>
                          </td>
                        )}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ======================================================== */}
      {/* TAB 3: MULTI-VENDOR SWITCH CONFIGURATION (SETTINGS)      */}
      {/* ======================================================== */}
      {activeTab === "switch_settings" && isAdmin && (
        <div>
          {/* SUPPORTED SWITCH PLATFORMS GRID */}
          <div className="panel" style={{ marginBottom: "20px" }}>
            <div style={{ fontSize: "16px", fontWeight: "800", color: "#0f172a", marginBottom: "4px" }}>
              Supported Enterprise Switch Platforms
            </div>
            <div style={{ fontSize: "12px", color: "#64748b", marginBottom: "16px" }}>
              Click any platform to load recommended default credentials and port settings.
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))", gap: "12px" }}>
              {switchVendors.map((vnd) => {
                const isSelected = switchForm.vendor === vnd.id;
                return (
                  <div
                    key={vnd.id}
                    onClick={() => {
                      setSwitchForm((prev) => ({
                        ...prev,
                        vendor: vnd.id,
                        name: `${vnd.name} Switch`,
                        port: vnd.default_port,
                        model: vnd.default_model,
                      }));
                      setTestResult(null);
                    }}
                    style={{
                      background: isSelected ? "#eff6ff" : "#ffffff",
                      border: `2px solid ${isSelected ? "#2563eb" : "#cbd5e1"}`,
                      borderRadius: "10px",
                      padding: "14px",
                      cursor: "pointer",
                      transition: "all 0.15s ease",
                    }}
                  >
                    <div style={{ fontSize: "24px", marginBottom: "6px" }}>{vnd.icon}</div>
                    <div style={{ fontWeight: "800", color: "#0f172a", fontSize: "14px" }}>{vnd.name}</div>
                    <div style={{ fontSize: "11px", color: "#475569", marginTop: "4px", lineHeight: "1.4" }}>
                      {vnd.description}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* SWITCH CONFIGURATION FORM */}
          <div className="panel" style={{ marginBottom: "20px" }}>
            <div style={{ fontSize: "16px", fontWeight: "800", color: "#0f172a", marginBottom: "16px" }}>
              Configure Network Switch Connection
            </div>

            <form onSubmit={handleSaveSwitch}>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: "16px", marginBottom: "16px" }}>
                <div className="form-group">
                  <label className="form-label">Switch Vendor Platform *</label>
                  <select
                    className="login-input"
                    value={switchForm.vendor}
                    onChange={(e) => {
                      const selected = switchVendors.find((v) => v.id === e.target.value);
                      setSwitchForm({
                        ...switchForm,
                        vendor: e.target.value,
                        name: selected ? `${selected.name} Switch` : switchForm.name,
                        port: selected ? selected.default_port : switchForm.port,
                        model: selected ? selected.default_model : switchForm.model,
                      });
                      setTestResult(null);
                    }}
                  >
                    {switchVendors.map((vnd) => (
                      <option key={vnd.id} value={vnd.id}>
                        {vnd.icon} {vnd.name}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Switch Profile Name *</label>
                  <input
                    type="text"
                    className="login-input"
                    value={switchForm.name}
                    onChange={(e) => setSwitchForm({ ...switchForm, name: e.target.value })}
                    required
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Switch Management IP *</label>
                  <input
                    type="text"
                    className="login-input"
                    placeholder="e.g. 192.168.0.2"
                    value={switchForm.management_ip}
                    onChange={(e) => setSwitchForm({ ...switchForm, management_ip: e.target.value })}
                    required
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Management Port (SSH)</label>
                  <input
                    type="number"
                    className="login-input"
                    value={switchForm.port}
                    onChange={(e) => setSwitchForm({ ...switchForm, port: parseInt(e.target.value, 10) || 22 })}
                    required
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">SSH Username</label>
                  <input
                    type="text"
                    className="login-input"
                    placeholder="e.g. admin or netops"
                    value={switchForm.username}
                    onChange={(e) => setSwitchForm({ ...switchForm, username: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">SSH Password</label>
                  <input
                    type="password"
                    className="login-input"
                    placeholder="Enter switch password"
                    value={switchForm.password}
                    onChange={(e) => setSwitchForm({ ...switchForm, password: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Enable Secret (Cisco Privileged Exec)</label>
                  <input
                    type="password"
                    className="login-input"
                    placeholder="Enter Cisco enable secret"
                    value={switchForm.enable_secret}
                    onChange={(e) => setSwitchForm({ ...switchForm, enable_secret: e.target.value })}
                  />
                </div>
              </div>

              {testResult && (
                <div
                  style={{
                    background: testResult.success ? "#ecfdf5" : "#fef2f2",
                    border: `1px solid ${testResult.success ? "#a7f3d0" : "#fecaca"}`,
                    color: testResult.success ? "#065f46" : "#991b1b",
                    padding: "12px 14px",
                    borderRadius: "8px",
                    marginBottom: "16px",
                    fontSize: "13px",
                  }}
                >
                  <strong>{testResult.success ? "✓ Test Passed:" : "⚠️ Test Failed:"}</strong> {testResult.message}
                </div>
              )}

              <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", alignItems: "center" }}>
                <button
                  type="button"
                  className="secondary-button"
                  onClick={handleTestConnection}
                  disabled={testingSwitch}
                  style={{ display: "flex", alignItems: "center", gap: "6px" }}
                >
                  <span>🔌</span> {testingSwitch ? "Testing Switch Connection..." : "Test Switch Connection"}
                </button>

                <button
                  type="submit"
                  className="primary-button"
                  disabled={savingSwitch}
                  style={{ display: "flex", alignItems: "center", gap: "6px" }}
                >
                  <span>💾</span> {savingSwitch ? "Saving & Activating..." : "Save & Activate Switch Profile"}
                </button>
              </div>
            </form>
          </div>

          {/* SAVED SWITCH PROFILES */}
          <div className="panel" style={{ padding: 0 }}>
            <div style={{ padding: "16px 20px", borderBottom: "1px solid #e2e8f0" }}>
              <div style={{ fontSize: "15px", fontWeight: "700", color: "#0f172a" }}>
                Saved Switch Profiles ({savedConfigs.length})
              </div>
            </div>

            <div className="table-responsive">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Switch Name</th>
                    <th>Vendor</th>
                    <th>Management IP</th>
                    <th>Ports</th>
                    <th>Status</th>
                    <th style={{ textAlign: "right" }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {savedConfigs.length === 0 ? (
                    <tr>
                      <td colSpan="6" style={{ textAlign: "center", padding: "20px", color: "#64748b" }}>
                        No switch profiles saved yet. Fill out the form above to register your switch.
                      </td>
                    </tr>
                  ) : (
                    savedConfigs.map((cfg) => (
                      <tr key={cfg.id}>
                        <td><strong>{cfg.name}</strong></td>
                        <td><code>{cfg.vendor}</code></td>
                        <td><code>{cfg.management_ip}:{cfg.port}</code></td>
                        <td>{cfg.total_ports || 24} Ports</td>
                        <td>
                          {cfg.is_active ? (
                            <span className="status-badge online" style={{ fontSize: "10px" }}>🟢 ACTIVE SWITCH</span>
                          ) : (
                            <span className="status-badge offline" style={{ fontSize: "10px" }}>⚪ Standby</span>
                          )}
                        </td>
                        <td style={{ textAlign: "right" }}>
                          {!cfg.is_active && (
                            <button
                              type="button"
                              className="secondary-button small"
                              onClick={() => handleActivateSwitch(cfg.id, cfg.name)}
                              style={{ marginRight: "6px" }}
                            >
                              ⚡ Activate
                            </button>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ======================================================== */}
      {/* MODAL: CREATE NEW VLAN ON SWITCH                         */}
      {/* ======================================================== */}
      {showCreateVlanModal && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: "rgba(15, 23, 42, 0.6)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 99999,
            padding: "16px",
          }}
        >
          <div
            style={{
              backgroundColor: "#ffffff",
              borderRadius: "12px",
              width: "100%",
              maxWidth: "460px",
              padding: "24px",
              boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.25)",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
              <div style={{ fontSize: "16px", fontWeight: "800", color: "#0f172a", display: "flex", alignItems: "center", gap: "8px" }}>
                <span>🏷️</span>
                <span>Create & Deploy VLAN to Switch</span>
              </div>
              <button
                type="button"
                onClick={() => setShowCreateVlanModal(false)}
                style={{ background: "transparent", border: "none", fontSize: "18px", color: "#64748b", cursor: "pointer" }}
              >
                ×
              </button>
            </div>

            <div style={{ fontSize: "12px", color: "#64748b", marginBottom: "16px", lineHeight: "1.5" }}>
              This will automatically log into the switch via SSH, execute <code>vlan [id]</code> and <code>name [name]</code>, and save to startup configuration.
            </div>

            <form onSubmit={handleCreateVlan}>
              <div style={{ marginBottom: "12px" }}>
                <label style={{ display: "block", fontSize: "12px", fontWeight: "600", color: "#334155", marginBottom: "4px" }}>
                  VLAN ID (1 – 4094) *
                </label>
                <input
                  type="number"
                  min="1"
                  max="4094"
                  style={{ width: "100%", padding: "8px 12px", borderRadius: "6px", border: "1px solid #cbd5e1", fontSize: "13px" }}
                  placeholder="e.g. 25"
                  value={newVlanId}
                  onChange={(e) => setNewVlanId(e.target.value)}
                  disabled={creatingVlan}
                  required
                />
              </div>

              <div style={{ marginBottom: "12px" }}>
                <label style={{ display: "block", fontSize: "12px", fontWeight: "600", color: "#334155", marginBottom: "4px" }}>
                  VLAN Name *
                </label>
                <input
                  type="text"
                  style={{ width: "100%", padding: "8px 12px", borderRadius: "6px", border: "1px solid #cbd5e1", fontSize: "13px" }}
                  placeholder="e.g. Finance_Dept or Marketing"
                  value={newVlanName}
                  onChange={(e) => setNewVlanName(e.target.value)}
                  disabled={creatingVlan}
                  required
                />
              </div>

              <div style={{ marginBottom: "12px" }}>
                <label style={{ display: "block", fontSize: "12px", fontWeight: "600", color: "#334155", marginBottom: "4px" }}>
                  Subnet (Optional)
                </label>
                <input
                  type="text"
                  style={{ width: "100%", padding: "8px 12px", borderRadius: "6px", border: "1px solid #cbd5e1", fontSize: "13px" }}
                  placeholder="e.g. 192.168.25.0/24"
                  value={newVlanSubnet}
                  onChange={(e) => setNewVlanSubnet(e.target.value)}
                  disabled={creatingVlan}
                />
              </div>

              <div style={{ marginBottom: "16px" }}>
                <label style={{ display: "block", fontSize: "12px", fontWeight: "600", color: "#334155", marginBottom: "4px" }}>
                  Description / Department
                </label>
                <input
                  type="text"
                  style={{ width: "100%", padding: "8px 12px", borderRadius: "6px", border: "1px solid #cbd5e1", fontSize: "13px" }}
                  placeholder="e.g. Financial analysts and accounting systems"
                  value={newVlanDescription}
                  onChange={(e) => setNewVlanDescription(e.target.value)}
                  disabled={creatingVlan}
                />
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px" }}>
                <button
                  type="button"
                  className="secondary-button small"
                  onClick={() => setShowCreateVlanModal(false)}
                  disabled={creatingVlan}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="primary-button small"
                  disabled={creatingVlan}
                >
                  {creatingVlan ? "Deploying to Switch..." : "🚀 Provision to Switch"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ======================================================== */}
      {/* MODAL: ASSIGN SWITCH PORT TO VLAN                        */}
      {/* ======================================================== */}
      {selectedPort && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: "rgba(15, 23, 42, 0.6)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 99999,
            padding: "16px",
          }}
        >
          <div
            style={{
              backgroundColor: "#ffffff",
              borderRadius: "12px",
              width: "100%",
              maxWidth: "420px",
              padding: "24px",
              boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.25)",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
              <div style={{ fontSize: "16px", fontWeight: "800", color: "#0f172a", display: "flex", alignItems: "center", gap: "8px" }}>
                <span>🔌</span>
                <span>Assign Port {selectedPort.port}</span>
              </div>
              <button
                type="button"
                onClick={() => setSelectedPort(null)}
                style={{ background: "transparent", border: "none", fontSize: "18px", color: "#64748b", cursor: "pointer" }}
              >
                ×
              </button>
            </div>

            <div style={{ fontSize: "12px", color: "#64748b", marginBottom: "16px" }}>
              Select target VLAN to configure on interface <strong>{selectedPort.port}</strong>.
            </div>

            <form onSubmit={handleAssignPort}>
              <div style={{ marginBottom: "16px" }}>
                <label style={{ display: "block", fontSize: "12px", fontWeight: "600", color: "#334155", marginBottom: "4px" }}>
                  Target VLAN *
                </label>
                <select
                  style={{ width: "100%", padding: "8px 12px", borderRadius: "6px", border: "1px solid #cbd5e1", fontSize: "13px" }}
                  value={targetVlanId}
                  onChange={(e) => setTargetVlanId(e.target.value)}
                  disabled={assigningPort}
                  required
                >
                  {vlans.map((v) => (
                    <option key={v.vlan_id} value={v.vlan_id}>
                      VLAN {v.vlan_id} — {v.name} {v.vlan_id === 90 ? "(Quarantine)" : ""}
                    </option>
                  ))}
                </select>
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px" }}>
                <button
                  type="button"
                  className="secondary-button small"
                  onClick={() => setSelectedPort(null)}
                  disabled={assigningPort}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="primary-button small"
                  disabled={assigningPort}
                >
                  {assigningPort ? "Applying..." : "Apply Port VLAN"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
