import React, { useEffect, useState } from "react";
import { isTypeAndVlanMatching, getExpectedVlanForType } from "../utils/networkInterfaceStatus";

export default function SwitchVlanPage({ API_URL, currentUser, getAuthHeaders, devices = [] }) {
  const isAdmin = currentUser?.role === "admin" || currentUser?.role === "super_admin";
  const isSuperAdmin = currentUser?.role === "super_admin";
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

  // Edit VLAN Modal (Custom Department Naming)
  const [editingVlan, setEditingVlan] = useState(null);
  const [editVlanName, setEditVlanName] = useState("");
  const [editVlanDescription, setEditVlanDescription] = useState("");
  const [editVlanSubnet, setEditVlanSubnet] = useState("");
  const [savingEditVlan, setSavingEditVlan] = useState(false);

  // Assign Port Modal
  const [selectedPort, setSelectedPort] = useState(null);
  const [targetVlanId, setTargetVlanId] = useState("");
  const [isTrunk, setIsTrunk] = useState(false);
  const [assigningPort, setAssigningPort] = useState(false);
  const [configuringUplinks, setConfiguringUplinks] = useState(false);
  const [portTableFilter, setPortTableFilter] = useState("all");

  // Config Backups & CLI Diff States
  const [backups, setBackups] = useState([]);
  const [loadingBackups, setLoadingBackups] = useState(false);
  const [takingBackup, setTakingBackup] = useState(false);
  const [backupNameInput, setBackupNameInput] = useState("");
  const [backupTypeInput, setBackupTypeInput] = useState("manual");
  const [viewingBackup, setViewingBackup] = useState(null);
  const [diffResult, setDiffResult] = useState(null);
  const [diffLoading, setDiffLoading] = useState(false);
  const [diffCompareMode, setDiffCompareMode] = useState("live"); // "live" | "two_backups"
  const [selectedBackupA, setSelectedBackupA] = useState("");
  const [selectedBackupB, setSelectedBackupB] = useState("");
  const [showDiffModal, setShowDiffModal] = useState(false);
  const [copiedConfig, setCopiedConfig] = useState(false);
  const [deletingBackupId, setDeletingBackupId] = useState(null);
  const [backupSchedule, setBackupSchedule] = useState({
    enabled: true,
    interval_minutes: 60,
    backup_only_on_change: true,
    alert_on_drift: true,
    last_run_at: null,
    last_run_status: "never_run",
  });
  const [savingSchedule, setSavingSchedule] = useState(false);
  const [runningCycle, setRunningCycle] = useState(false);
  const [cycleFeedback, setCycleFeedback] = useState(null);

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
  const [switchingDensity, setSwitchingDensity] = useState(false);

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

      const targetSwId = activeRes?.config?.id || (Array.isArray(configRes) && configRes.find((c) => c.is_active)?.id) || 0;
      loadBackups(targetSwId);
      loadBackupSchedule();
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
    if (!isSuperAdmin) {
      showStatus("Permission Denied: Only Super Administrators can delete VLAN configurations.", "error");
      return;
    }
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

  // Department Presets for 1-Click Company Customization
  const DEPARTMENT_PRESETS = [
    { name: "HR_Management", desc: "Human Resources, Payroll & Staff Onboarding", subnet: "192.168.10.0/24" },
    { name: "IT_Operations", desc: "IT Engineers, Infrastructure, Monitoring & NOC", subnet: "192.168.20.0/24" },
    { name: "Finance_Accounting", desc: "Finance, Billing, Auditing & Accounting Systems", subnet: "192.168.30.0/24" },
    { name: "Executive_Suite", desc: "C-Level Leadership, Boardroom & High-Priority Access", subnet: "192.168.40.0/24" },
    { name: "Sales_Marketing", desc: "Sales Representatives, CRM & Marketing Workstations", subnet: "192.168.50.0/24" },
    { name: "Customer_Support", desc: "Helpdesk, Call Center & Customer Relations", subnet: "192.168.60.0/24" },
    { name: "Warehouse_Logistics", desc: "Inventory Scanning, Shipping & Logistics Barcodes", subnet: "192.168.70.0/24" },
    { name: "Engineering_Lab", desc: "Research, Software Development & Testing Labs", subnet: "192.168.80.0/24" },
    { name: "Guest_WiFi", desc: "Isolated Visitor & Contractor Internet Access", subnet: "192.168.100.0/24" },
    { name: "CCTV_Security", desc: "Surveillance Cameras, Access Control & NVRs", subnet: "192.168.200.0/24" },
  ];

  // Open Edit VLAN Modal
  const handleOpenEditVlan = (vlanObj) => {
    setEditingVlan(vlanObj);
    setEditVlanName(vlanObj.name || "");
    setEditVlanDescription(vlanObj.description || "");
    setEditVlanSubnet(vlanObj.subnet || "");
  };

  // Save Edit VLAN
  const handleSaveEditVlan = async (e) => {
    if (e) e.preventDefault();
    if (!editingVlan || !editVlanName.trim()) {
      showStatus("Please enter a valid VLAN name.", "error");
      return;
    }

    setSavingEditVlan(true);
    try {
      const res = await fetch(`${API_URL}/switches/vlans/${editingVlan.vlan_id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", ...getAuthHeaders() },
        body: JSON.stringify({
          name: editVlanName.trim(),
          description: editVlanDescription.trim(),
          subnet: editVlanSubnet.trim() || null,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to update VLAN.");

      showStatus(`VLAN ${editingVlan.vlan_id} updated to '${data.name}' successfully!`, "success");
      setEditingVlan(null);
      await loadAllData();
    } catch (err) {
      showStatus(err.message, "error");
    } finally {
      setSavingEditVlan(false);
    }
  };

  // Handle Assign Port VLAN (Access or 802.1Q Trunk)
  const handleAssignPort = async (e) => {
    if (e) e.preventDefault();
    if (!selectedPort) return;

    setAssigningPort(true);
    try {
      const res = await fetch(`${API_URL}/switches/ports/assign`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...getAuthHeaders() },
        body: JSON.stringify({
          port_name: selectedPort.port,
          vlan_id: parseInt(targetVlanId || "1", 10),
          mode: isTrunk ? "trunk" : "access",
          is_trunk: isTrunk,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to assign port.");

      showStatus(
        isTrunk
          ? `Port ${selectedPort.port} successfully configured as 802.1Q Trunk Uplink!`
          : `Port ${selectedPort.port} reconfigured to VLAN ${targetVlanId} successfully!`,
        "success"
      );
      setSelectedPort(null);
      await loadAllData();
    } catch (err) {
      showStatus(err.message, "error");
    } finally {
      setAssigningPort(false);
    }
  };

  // Handle Quick Configuration of Uplink Ports as Trunk Uplinks
  const handleConfigureUplinks = async () => {
    if (!window.confirm("Configure switch uplink ports as 802.1Q Trunk Uplinks? This will configure them to carry all active VLANs upstream to distribution or firewall.")) {
      return;
    }
    setConfiguringUplinks(true);
    try {
      const res = await fetch(`${API_URL}/switches/ports/configure-uplinks`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...getAuthHeaders() },
        body: JSON.stringify({ native_vlan: 1, mode: "trunk" }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to configure trunk uplinks.");
      showStatus(data.message || "Trunk uplinks configured successfully!", "success");
      await loadAllData();
    } catch (err) {
      showStatus(err.message, "error");
    } finally {
      setConfiguringUplinks(false);
    }
  };

  // Handle Switch Chassis Density Switch (24-Port vs 48-Port)
  const handleSwitchDensity = async (targetDensity) => {
    if (!isAdmin) return;
    setSwitchingDensity(true);
    try {
      const res = await fetch(`${API_URL}/switches/ports/density`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...getAuthHeaders() },
        body: JSON.stringify({ total_ports: targetDensity }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to switch chassis density.");
      showStatus(data.message || `Switched to ${targetDensity}-Port Chassis layout.`, "success");
      await loadAllData();
    } catch (err) {
      showStatus(err.message, "error");
    } finally {
      setSwitchingDensity(false);
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

  // -------------------------------------------------------------
  // SWITCH CONFIGURATION BACKUP & DIFF HANDLERS
  // -------------------------------------------------------------
  const getActiveSwitchId = () => {
    return activeSwitch?.config?.id || savedConfigs.find((c) => c.is_active)?.id || savedConfigs[0]?.id || 0;
  };

  const loadBackups = async (overrideSwitchId = null) => {
    setLoadingBackups(true);
    try {
      const swId = overrideSwitchId !== null ? overrideSwitchId : getActiveSwitchId();
      const res = await fetch(`${API_URL}/switches/${swId}/backups`, {
        headers: getAuthHeaders ? getAuthHeaders() : {},
      });
      const data = await res.json();
      if (Array.isArray(data)) {
        setBackups(data);
        if (data.length > 0) {
          setSelectedBackupA((prev) => prev || data[0].id.toString());
          if (data.length > 1) {
            setSelectedBackupB((prev) => prev || data[1].id.toString());
          }
        }
      }
    } catch (err) {
      console.error("Failed to load switch backups:", err);
    } finally {
      setLoadingBackups(false);
    }
  };

  const handleTakeBackup = async (e) => {
    if (e) e.preventDefault();
    setTakingBackup(true);
    try {
      const swId = getActiveSwitchId();
      const res = await fetch(`${API_URL}/switches/${swId}/backups`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...getAuthHeaders() },
        body: JSON.stringify({
          backup_name: backupNameInput.trim() || null,
          backup_type: backupTypeInput,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to create switch configuration backup.");
      showStatus(data.message || "Switch running-configuration backup created successfully!", "success");
      setBackupNameInput("");
      await loadBackups();
    } catch (err) {
      showStatus(err.message, "error");
    } finally {
      setTakingBackup(false);
    }
  };

  const handleViewBackup = async (backupId) => {
    try {
      const res = await fetch(`${API_URL}/switches/backups/${backupId}`, {
        headers: getAuthHeaders ? getAuthHeaders() : {},
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to load backup details.");
      setViewingBackup(data);
      setCopiedConfig(false);
    } catch (err) {
      showStatus(err.message, "error");
    }
  };

  const handleRunDiff = async (baseId, compareId = null, isLive = false) => {
    if (!baseId) {
      showStatus("Please select a base backup to compare.", "error");
      return;
    }
    if (!isLive && !compareId) {
      showStatus("Please select a target backup to compare against.", "error");
      return;
    }
    setDiffLoading(true);
    setShowDiffModal(true);
    setDiffResult(null);
    try {
      const swId = getActiveSwitchId();
      const res = await fetch(`${API_URL}/switches/backups/diff`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...getAuthHeaders() },
        body: JSON.stringify({
          backup_id_a: parseInt(baseId, 10),
          backup_id_b: compareId ? parseInt(compareId, 10) : null,
          compare_with_live: isLive,
          switch_id: swId,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to compute configuration diff.");
      setDiffResult(data.diff);
    } catch (err) {
      showStatus(err.message, "error");
      setDiffResult({ error: err.message });
    } finally {
      setDiffLoading(false);
    }
  };

  const handleDeleteBackup = async (backupId) => {
    if (!isSuperAdmin) {
      showStatus("Permission Denied: Only Super Administrators can delete configuration backups.", "error");
      return;
    }
    if (!window.confirm(`Permanently delete configuration backup #${backupId}? This action cannot be undone.`)) {
      return;
    }
    setDeletingBackupId(backupId);
    try {
      const res = await fetch(`${API_URL}/switches/backups/${backupId}`, {
        method: "DELETE",
        headers: getAuthHeaders ? getAuthHeaders() : {},
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to delete backup.");
      showStatus(`Backup #${backupId} deleted successfully.`, "success");
      await loadBackups();
    } catch (err) {
      showStatus(err.message, "error");
    } finally {
      setDeletingBackupId(null);
    }
  };

  const loadBackupSchedule = async () => {
    try {
      const res = await fetch(`${API_URL}/switches/backups/schedule`, {
        headers: getAuthHeaders ? getAuthHeaders() : {},
      });
      if (res.ok) {
        const data = await res.json();
        setBackupSchedule((prev) => ({ ...prev, ...data }));
      }
    } catch (_) {}
  };

  const handleSaveSchedule = async (updatedFields) => {
    setSavingSchedule(true);
    setCycleFeedback(null);
    try {
      const merged = { ...backupSchedule, ...updatedFields };
      const res = await fetch(`${API_URL}/switches/backups/schedule`, {
        method: "POST",
        headers: getAuthHeaders ? getAuthHeaders({ "Content-Type": "application/json" }) : { "Content-Type": "application/json" },
        body: JSON.stringify(merged),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to save schedule policy.");
      setBackupSchedule(data.settings);
      setCycleFeedback({ type: "success", text: "✅ Automated switch backup policy updated successfully." });
    } catch (err) {
      setCycleFeedback({ type: "error", text: err.message });
    } finally {
      setSavingSchedule(false);
    }
  };

  const handleRunBackupCycle = async () => {
    setRunningCycle(true);
    setCycleFeedback(null);
    try {
      const res = await fetch(`${API_URL}/switches/backups/run-cycle`, {
        method: "POST",
        headers: getAuthHeaders ? getAuthHeaders() : {},
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to execute backup cycle.");
      setCycleFeedback({
        type: "success",
        text: `✅ ${data.message}`,
      });
      await loadBackups();
      await loadBackupSchedule();
    } catch (err) {
      setCycleFeedback({ type: "error", text: err.message });
    } finally {
      setRunningCycle(false);
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
          <span>🔌</span> Switch Panel & Port Matrix ({activeSwitch?.config?.total_ports || (ports.length > 24 ? 48 : 24)}P)
        </button>

        {isAdmin && (
          <button
            type="button"
            onClick={() => {
              setActiveTab("backups");
              loadBackups();
              loadBackupSchedule();
            }}
            style={{
              padding: "10px 18px",
              border: "none",
              background: "transparent",
              fontWeight: activeTab === "backups" ? "800" : "600",
              color: activeTab === "backups" ? "#2563eb" : "#64748b",
              borderBottom: activeTab === "backups" ? "3px solid #2563eb" : "3px solid transparent",
              cursor: "pointer",
              fontSize: "14px",
              display: "flex",
              alignItems: "center",
              gap: "8px",
            }}
          >
            <span>📜</span> Config Backups & CLI Diff
          </button>
        )}

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
            <span>⚙️</span> Multi-Vendor Switch Configuration {!isSuperAdmin && "(Locked)"}
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

                  <div style={{ marginTop: "10px", paddingTop: "8px", borderTop: `1px solid ${theme.border}44`, display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "11px", color: "#475569" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>
                      <span>Devices: <strong>{matchingDevices.length}</strong></span>
                      {matchingDevices.filter((d) => !isTypeAndVlanMatching(d)).length > 0 && (
                        <span style={{ fontSize: "10px", color: "#b45309", background: "rgba(245, 158, 11, 0.15)", padding: "1px 6px", borderRadius: "4px", fontWeight: "700" }}>
                          ⚠️ {matchingDevices.filter((d) => !isTypeAndVlanMatching(d)).length} Mismatched
                        </span>
                      )}
                    </div>
                    {isAdmin && (
                      <button
                        type="button"
                        className="secondary-button small"
                        style={{ padding: "2px 8px", fontSize: "11px", height: "auto", borderColor: theme.border }}
                        onClick={() => handleOpenEditVlan(v)}
                        title="Customize VLAN name and department"
                      >
                        ✏️ Edit
                      </button>
                    )}
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
                  {vlans.length === 0 && (
                    <tr>
                      <td colSpan={isAdmin ? 7 : 6} style={{ textAlign: "center", padding: "32px", color: "#64748b" }}>
                        {loading ? "⏳ Loading VLAN configuration from switch..." : "No VLANs found. Click '+ Create New VLAN' to add one."}
                      </td>
                    </tr>
                  )}
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
                            <div style={{ display: "flex", justifyContent: "flex-end", gap: "6px" }}>
                              <button
                                type="button"
                                className="secondary-button small"
                                onClick={() => handleOpenEditVlan(v)}
                                title="Customize department name, description, and subnet"
                              >
                                ✏️ Edit
                              </button>
                              {isSuperAdmin && !v.is_default && !v.is_quarantine && (
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
      {/* TAB 2: SWITCH MATRIX & FRONT PANEL (24/48-PORT CHASSIS)   */}
      {/* ======================================================== */}
      {activeTab === "ports" && (() => {
        const is48Port = (activeSwitch?.config?.total_ports === 48) || (ports.length > 24);
        const totalChassisPorts = is48Port ? (ports.length > 48 ? ports.length : 48) : 24;

        const getPortNum = (p, fallback) => {
          if (!p) return fallback;
          const match = String(p.port || p.short_name || "").match(/(\d+)$/);
          return match ? parseInt(match[1], 10) : fallback;
        };

        const sortedChassisPorts = [...ports].sort((a, b) => getPortNum(a, 0) - getPortNum(b, 0));
        const copperPorts = sortedChassisPorts.filter((p) => !p.is_sfp && !String(p.port || "").toLowerCase().startsWith("te"));
        const sfpPorts = sortedChassisPorts.filter((p) => p.is_sfp || String(p.port || "").toLowerCase().startsWith("te"));

        const topRowOddPorts = copperPorts.filter((p, i) => getPortNum(p, i + 1) % 2 === 1);
        const bottomRowEvenPorts = copperPorts.filter((p, i) => getPortNum(p, i + 1) % 2 === 0);
        const numCols = Math.max(12, Math.max(topRowOddPorts.length, bottomRowEvenPorts.length));

        const sfpTopRow = sfpPorts.filter((p, i) => i % 2 === 0);
        const sfpBottomRow = sfpPorts.filter((p, i) => i % 2 === 1);

        const filteredPorts = ports.filter((p) => {
          const num = getPortNum(p, 0);
          const isSfp = p.is_sfp || String(p.port || "").toLowerCase().startsWith("te");
          const isTrunkPort = p.mode === "trunk" || !!p.is_uplink;

          if (portTableFilter === "bank1") return !isSfp && num >= 1 && num <= 24;
          if (portTableFilter === "bank2") return !isSfp && num >= 25 && num <= 48;
          if (portTableFilter === "sfp") return isSfp;
          if (portTableFilter === "trunk") return isTrunkPort;
          if (portTableFilter === "quarantine") return p.vlan === 90;
          return true;
        });

        const renderChassisPort = (p) => {
          const isUp = p.status === "connected";
          const isQuarantine = p.vlan === 90;
          const isTrunkPort = p.mode === "trunk" || !!p.is_uplink;
          const theme = getVlanColor(p.vlan);

          return (
            <div
              key={p.port}
              onClick={() => {
                if (isAdmin) {
                  setSelectedPort(p);
                  setTargetVlanId(String(p.vlan || 1));
                  setIsTrunk(p.mode === "trunk" || !!p.is_uplink);
                }
              }}
              style={{
                background: isTrunkPort ? "#2e1065" : "#1e293b",
                border: `2px solid ${isQuarantine ? "#ef4444" : isTrunkPort ? "#8b5cf6" : isUp ? theme.border : "#334155"}`,
                borderRadius: "8px",
                padding: "8px 4px",
                textAlign: "center",
                cursor: isAdmin ? "pointer" : "default",
                transition: "all 0.15s ease",
                boxShadow: isTrunkPort ? "0 0 8px rgba(139, 92, 246, 0.4)" : "none",
                minWidth: is48Port ? "38px" : "48px",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = "translateY(-2px)";
                e.currentTarget.style.boxShadow = "0 4px 6px rgba(0,0,0,0.3)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = "none";
                e.currentTarget.style.boxShadow = isTrunkPort ? "0 0 8px rgba(139, 92, 246, 0.4)" : "none";
              }}
              title={`Click to configure ${p.port} (${isTrunkPort ? "TRUNK UPLINK" : `VLAN ${p.vlan}`})`}
            >
              {/* LINK LED */}
              <div style={{ display: "flex", justifyContent: "center", marginBottom: "4px" }}>
                <span
                  style={{
                    width: "8px",
                    height: "8px",
                    borderRadius: "50%",
                    background: isTrunkPort ? "#a855f7" : isUp ? "#10b981" : "#475569",
                    boxShadow: isTrunkPort ? "0 0 6px #a855f7" : isUp ? "0 0 6px #10b981" : "none",
                    display: "inline-block",
                  }}
                />
              </div>

              {/* PORT NUMBER */}
              <div style={{ fontSize: is48Port ? "10px" : "11px", fontWeight: "800", color: "#f8fafc", whiteSpace: "nowrap" }}>
                {p.short_name || p.port}
              </div>

              {/* CURRENT VLAN / TRUNK BADGE */}
              <div
                style={{
                  marginTop: "6px",
                  fontSize: isTrunkPort ? "9px" : "10px",
                  fontWeight: "800",
                  background: isQuarantine ? "#ef4444" : isTrunkPort ? "#7c3aed" : theme.chip,
                  color: "#ffffff",
                  borderRadius: "4px",
                  padding: "1px 2px",
                  letterSpacing: isTrunkPort ? "0.5px" : "normal",
                  whiteSpace: "nowrap",
                }}
              >
                {isTrunkPort ? "TRUNK" : `V${p.vlan}`}
              </div>
            </div>
          );
        };

        const renderSfpPort = (p) => {
          const isUp = p.status === "connected";
          const isQuarantine = p.vlan === 90;
          const isTrunkPort = p.mode === "trunk" || !!p.is_uplink;

          return (
            <div
              key={p.port}
              onClick={() => {
                if (isAdmin) {
                  setSelectedPort(p);
                  setTargetVlanId(String(p.vlan || 1));
                  setIsTrunk(p.mode === "trunk" || !!p.is_uplink);
                }
              }}
              style={{
                background: "#1e1b4b",
                border: `2px solid ${isQuarantine ? "#ef4444" : isUp ? "#c084fc" : "#4f46e5"}`,
                borderRadius: "8px",
                padding: "8px 6px",
                textAlign: "center",
                cursor: isAdmin ? "pointer" : "default",
                transition: "all 0.15s ease",
                boxShadow: isUp ? "0 0 10px rgba(192, 132, 252, 0.5)" : "none",
                minWidth: "52px",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = "translateY(-2px)";
                e.currentTarget.style.boxShadow = "0 4px 6px rgba(0,0,0,0.3)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = "none";
                e.currentTarget.style.boxShadow = isUp ? "0 0 10px rgba(192, 132, 252, 0.5)" : "none";
              }}
              title={`Click to configure 10G SFP+ Uplink ${p.port} (${p.status})`}
            >
              {/* SFP 10G LED */}
              <div style={{ display: "flex", justifyContent: "center", marginBottom: "4px" }}>
                <span
                  style={{
                    width: "8px",
                    height: "8px",
                    borderRadius: "50%",
                    background: isUp ? "#c084fc" : "#475569",
                    boxShadow: isUp ? "0 0 8px #c084fc" : "none",
                    display: "inline-block",
                  }}
                />
              </div>

              {/* SFP NAME */}
              <div style={{ fontSize: "11px", fontWeight: "800", color: "#f8fafc" }}>
                {p.short_name || p.port}
              </div>

              {/* 10G BADGE */}
              <div
                style={{
                  marginTop: "6px",
                  fontSize: "9px",
                  fontWeight: "800",
                  background: isQuarantine ? "#ef4444" : "#7c3aed",
                  color: "#ffffff",
                  borderRadius: "4px",
                  padding: "1px 2px",
                  letterSpacing: "0.5px",
                }}
              >
                10G SFP+
              </div>
            </div>
          );
        };

        return (
          <div>
            <div className="panel" style={{ marginBottom: "20px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px", flexWrap: "wrap", gap: "10px" }}>
                <div>
                  <div style={{ fontSize: "16px", fontWeight: "800", color: "#0f172a", display: "flex", alignItems: "center", gap: "8px" }}>
                    <span>Physical Switch Front Panel ({totalChassisPorts} Ports)</span>
                    <span
                      style={{
                        fontSize: "11px",
                        fontWeight: "700",
                        padding: "2px 8px",
                        borderRadius: "12px",
                        background: is48Port ? "#ede9fe" : "#eff6ff",
                        color: is48Port ? "#6d28d9" : "#1d4ed8",
                        border: `1px solid ${is48Port ? "#c4b5fd" : "#bfdbfe"}`,
                      }}
                    >
                      {is48Port ? "48-Port Enterprise + 10G SFP+" : "24-Port Standard"}
                    </span>
                  </div>
                  <div style={{ fontSize: "12px", color: "#64748b" }}>
                    Live port visualization. Click any port to change its VLAN assignment without console login.
                  </div>
                </div>

                {/* DENSITY SELECTOR & UPLINKS ACTION */}
                <div style={{ display: "flex", gap: "10px", alignItems: "center", flexWrap: "wrap" }}>
                  {isAdmin && (
                    <div style={{ display: "flex", alignItems: "center", gap: "4px", background: "#f8fafc", padding: "3px", borderRadius: "8px", border: "1px solid #cbd5e1" }}>
                      <span style={{ fontSize: "11px", fontWeight: "700", color: "#64748b", paddingLeft: "6px", paddingRight: "4px" }}>
                        Chassis:
                      </span>
                      <button
                        type="button"
                        onClick={() => handleSwitchDensity(24)}
                        disabled={switchingDensity}
                        style={{
                          padding: "4px 10px",
                          fontSize: "12px",
                          fontWeight: "700",
                          borderRadius: "6px",
                          border: "none",
                          cursor: "pointer",
                          background: !is48Port ? "#2563eb" : "transparent",
                          color: !is48Port ? "#ffffff" : "#64748b",
                          boxShadow: !is48Port ? "0 1px 2px rgba(0,0,0,0.1)" : "none",
                          transition: "all 0.15s ease",
                        }}
                      >
                        24 Ports
                      </button>
                      <button
                        type="button"
                        onClick={() => handleSwitchDensity(48)}
                        disabled={switchingDensity}
                        style={{
                          padding: "4px 10px",
                          fontSize: "12px",
                          fontWeight: "700",
                          borderRadius: "6px",
                          border: "none",
                          cursor: "pointer",
                          background: is48Port ? "#2563eb" : "transparent",
                          color: is48Port ? "#ffffff" : "#64748b",
                          boxShadow: is48Port ? "0 1px 2px rgba(0,0,0,0.1)" : "none",
                          transition: "all 0.15s ease",
                        }}
                      >
                        48 Ports (+ SFP+)
                      </button>
                    </div>
                  )}

                  {isAdmin && (
                    <button
                      type="button"
                      className="secondary-button small"
                      onClick={handleConfigureUplinks}
                      disabled={configuringUplinks}
                      style={{
                        background: "#f5f3ff",
                        color: "#6d28d9",
                        borderColor: "#c4b5fd",
                        fontWeight: "700",
                        display: "flex",
                        alignItems: "center",
                        gap: "6px",
                      }}
                      title="Automatically configure switch uplink ports as 802.1Q Trunk Uplinks"
                    >
                      <span>🔀</span> {configuringUplinks ? "Configuring Uplinks..." : (is48Port ? "Set 10G SFP+ as Trunk Uplinks" : "Set Last 2 Ports as Trunk Uplinks")}
                    </button>
                  )}
                </div>
              </div>

              {/* LEGEND BADGES */}
              <div style={{ display: "flex", gap: "14px", alignItems: "center", fontSize: "12px", flexWrap: "wrap", marginBottom: "14px" }}>
                <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                  <span style={{ width: "10px", height: "10px", borderRadius: "50%", background: "#10b981", display: "inline-block" }}></span> Connected
                </span>
                <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                  <span style={{ width: "10px", height: "10px", borderRadius: "50%", background: "#94a3b8", display: "inline-block" }}></span> Idle / Disconnected
                </span>
                <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                  <span style={{ width: "10px", height: "10px", borderRadius: "50%", background: "#a855f7", display: "inline-block" }}></span> 🔀 Trunk Uplink
                </span>
                {is48Port && (
                  <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                    <span style={{ width: "10px", height: "10px", borderRadius: "50%", background: "#c084fc", display: "inline-block" }}></span> ⚡ 10G SFP+
                  </span>
                )}
                <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                  <span style={{ width: "10px", height: "10px", borderRadius: "50%", background: "#ef4444", display: "inline-block" }}></span> Quarantine (90)
                </span>
              </div>

              {/* SWITCH CHASSIS RACK SIMULATOR */}
              <div
                style={{
                  background: "#0f172a",
                  borderRadius: "12px",
                  padding: "20px",
                  boxShadow: "inset 0 2px 4px rgba(0,0,0,0.5)",
                  border: "2px solid #334155",
                  overflowX: "auto",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", color: "#94a3b8", fontSize: "11px", marginBottom: "16px", fontWeight: "700", letterSpacing: "1px", flexWrap: "wrap", gap: "8px" }}>
                  <span>SWITCH CHASSIS {is48Port ? "48-PORT ENTERPRISE GIGABIT PANEL (+ 4x 10G SFP+)" : "24-PORT GIGABIT PANEL"}</span>
                  <span style={{ color: "#a855f7" }}>
                    {is48Port ? "LAYOUT: TOP = ODD (1-47), BOTTOM = EVEN (2-48) | PORTS 47, 48 & SFP+ Te0/49-52 = TRUNK UPLINKS" : "LAYOUT: TOP = ODD (1-23), BOTTOM = EVEN (2-24) | PORTS 23 & 24 = TRUNK UPLINKS"}
                  </span>
                  <span style={{ color: "#38bdf8" }}>MANAGEMENT: {activeSwitch?.config?.management_ip || "192.168.0.2"}</span>
                </div>

                {/* CHASSIS RACK CONTAINER */}
                <div style={{ display: "flex", gap: "16px", alignItems: "stretch" }}>
                  {/* COPPER GIGABIT MATRIX */}
                  <div style={{ flex: 1 }}>
                    {/* TOP ROW: ODD NUMBERED PORTS */}
                    <div style={{ marginBottom: "6px" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                        <span style={{ fontSize: "10px", fontWeight: "800", color: "#64748b", textTransform: "uppercase", letterSpacing: "1px" }}>
                          ▲ Top Row (Odd Gigabit Ports: 1, 3, 5 ... {topRowOddPorts[topRowOddPorts.length - 1]?.short_name || (is48Port ? "Gi0/47" : "Gi0/23")})
                        </span>
                      </div>
                      <div style={{ display: "grid", gridTemplateColumns: `repeat(${numCols}, minmax(36px, 1fr))`, gap: "6px" }}>
                        {topRowOddPorts.map(renderChassisPort)}
                      </div>
                    </div>

                    {/* CHASSIS SEPARATOR RAIL */}
                    <div
                      style={{
                        height: "6px",
                        background: "linear-gradient(90deg, #1e293b 0%, #334155 50%, #1e293b 100%)",
                        borderRadius: "3px",
                        margin: "10px 0",
                        borderTop: "1px solid #475569",
                        borderBottom: "1px solid #0f172a",
                      }}
                    />

                    {/* BOTTOM ROW: EVEN NUMBERED PORTS */}
                    <div>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                        <span style={{ fontSize: "10px", fontWeight: "800", color: "#64748b", textTransform: "uppercase", letterSpacing: "1px" }}>
                          ▼ Bottom Row (Even Gigabit Ports: 2, 4, 6 ... {bottomRowEvenPorts[bottomRowEvenPorts.length - 1]?.short_name || (is48Port ? "Gi0/48" : "Gi0/24")})
                        </span>
                      </div>
                      <div style={{ display: "grid", gridTemplateColumns: `repeat(${numCols}, minmax(36px, 1fr))`, gap: "6px" }}>
                        {bottomRowEvenPorts.map(renderChassisPort)}
                      </div>
                    </div>
                  </div>

                  {/* SFP+ 10G UPLINK CAGE BAY (Rendered on 48-port enterprise switches or when SFP cages present) */}
                  {sfpPorts.length > 0 && (
                    <div
                      style={{
                        borderLeft: "2px dashed #475569",
                        paddingLeft: "16px",
                        display: "flex",
                        flexDirection: "column",
                        justifyContent: "space-between",
                        background: "rgba(30, 27, 75, 0.4)",
                        borderRadius: "8px",
                        padding: "10px",
                        border: "1px solid #4338ca",
                      }}
                    >
                      {/* SFP TOP ROW */}
                      <div style={{ marginBottom: "6px" }}>
                        <div style={{ fontSize: "10px", fontWeight: "800", color: "#c084fc", textTransform: "uppercase", letterSpacing: "1px", marginBottom: "4px" }}>
                          ⚡ 10G SFP+ (Top)
                        </div>
                        <div style={{ display: "grid", gridTemplateColumns: `repeat(${Math.max(1, sfpTopRow.length)}, minmax(48px, 1fr))`, gap: "6px" }}>
                          {sfpTopRow.map(renderSfpPort)}
                        </div>
                      </div>

                      {/* SFP RAIL */}
                      <div
                        style={{
                          height: "6px",
                          background: "#4338ca",
                          borderRadius: "3px",
                          margin: "8px 0",
                        }}
                      />

                      {/* SFP BOTTOM ROW */}
                      <div>
                        <div style={{ fontSize: "10px", fontWeight: "800", color: "#c084fc", textTransform: "uppercase", letterSpacing: "1px", marginBottom: "4px" }}>
                          ⚡ 10G SFP+ (Bottom)
                        </div>
                        <div style={{ display: "grid", gridTemplateColumns: `repeat(${Math.max(1, sfpBottomRow.length)}, minmax(48px, 1fr))`, gap: "6px" }}>
                          {sfpBottomRow.map(renderSfpPort)}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* PORTS TABLE */}
            <div className="panel" style={{ padding: 0 }}>
              <div style={{ padding: "16px 20px", borderBottom: "1px solid #e2e8f0", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "10px" }}>
                <div>
                  <div style={{ fontSize: "15px", fontWeight: "700", color: "#0f172a" }}>
                    Switch Interface Directory & VLAN Mapping
                  </div>
                  <div style={{ fontSize: "12px", color: "#64748b" }}>
                    Showing {filteredPorts.length} of {ports.length} total interfaces
                  </div>
                </div>

                {/* TABLE FILTER PILLS */}
                <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", alignItems: "center" }}>
                  <button
                    type="button"
                    onClick={() => setPortTableFilter("all")}
                    style={{
                      padding: "4px 10px",
                      fontSize: "12px",
                      fontWeight: "700",
                      borderRadius: "6px",
                      border: "none",
                      cursor: "pointer",
                      background: portTableFilter === "all" ? "#2563eb" : "#f1f5f9",
                      color: portTableFilter === "all" ? "#ffffff" : "#475569",
                    }}
                  >
                    All ({ports.length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setPortTableFilter("bank1")}
                    style={{
                      padding: "4px 10px",
                      fontSize: "12px",
                      fontWeight: "700",
                      borderRadius: "6px",
                      border: "none",
                      cursor: "pointer",
                      background: portTableFilter === "bank1" ? "#2563eb" : "#f1f5f9",
                      color: portTableFilter === "bank1" ? "#ffffff" : "#475569",
                    }}
                  >
                    Ports 1–24
                  </button>
                  {is48Port && (
                    <button
                      type="button"
                      onClick={() => setPortTableFilter("bank2")}
                      style={{
                        padding: "4px 10px",
                        fontSize: "12px",
                        fontWeight: "700",
                        borderRadius: "6px",
                        border: "none",
                        cursor: "pointer",
                        background: portTableFilter === "bank2" ? "#2563eb" : "#f1f5f9",
                        color: portTableFilter === "bank2" ? "#ffffff" : "#475569",
                      }}
                    >
                      Ports 25–48
                    </button>
                  )}
                  {sfpPorts.length > 0 && (
                    <button
                      type="button"
                      onClick={() => setPortTableFilter("sfp")}
                      style={{
                        padding: "4px 10px",
                        fontSize: "12px",
                        fontWeight: "700",
                        borderRadius: "6px",
                        border: "none",
                        cursor: "pointer",
                        background: portTableFilter === "sfp" ? "#7c3aed" : "#f1f5f9",
                        color: portTableFilter === "sfp" ? "#ffffff" : "#475569",
                      }}
                    >
                      ⚡ 10G SFP+ ({sfpPorts.length})
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => setPortTableFilter("trunk")}
                    style={{
                      padding: "4px 10px",
                      fontSize: "12px",
                      fontWeight: "700",
                      borderRadius: "6px",
                      border: "none",
                      cursor: "pointer",
                      background: portTableFilter === "trunk" ? "#7c3aed" : "#f1f5f9",
                      color: portTableFilter === "trunk" ? "#ffffff" : "#475569",
                    }}
                  >
                    Trunks
                  </button>
                  <button
                    type="button"
                    onClick={() => setPortTableFilter("quarantine")}
                    style={{
                      padding: "4px 10px",
                      fontSize: "12px",
                      fontWeight: "700",
                      borderRadius: "6px",
                      border: "none",
                      cursor: "pointer",
                      background: portTableFilter === "quarantine" ? "#ef4444" : "#f1f5f9",
                      color: portTableFilter === "quarantine" ? "#ffffff" : "#475569",
                    }}
                  >
                    Quarantine (90)
                  </button>
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
                    {filteredPorts.map((p) => {
                      const theme = getVlanColor(p.vlan);
                      const isTrunkPort = p.mode === "trunk" || !!p.is_uplink;
                      const isSfp = p.is_sfp || String(p.port || "").toLowerCase().startsWith("te");

                      return (
                        <tr key={p.port}>
                          <td>
                            <strong>{p.port}</strong>
                            {isSfp && (
                              <span style={{ marginLeft: "6px", fontSize: "10px", background: "#f5f3ff", color: "#6d28d9", border: "1px solid #c4b5fd", padding: "1px 5px", borderRadius: "4px", fontWeight: "800" }}>
                                ⚡ 10G SFP+
                              </span>
                            )}
                            {isTrunkPort && !isSfp && (
                              <span style={{ marginLeft: "6px", fontSize: "10px", background: "#f5f3ff", color: "#6d28d9", border: "1px solid #c4b5fd", padding: "1px 5px", borderRadius: "4px", fontWeight: "800" }}>
                                UPLINK
                              </span>
                            )}
                          </td>
                        <td>
                          {p.status === "connected" ? (
                            <span className="status-badge online" style={{ fontSize: "10px" }}>🟢 connected</span>
                          ) : (
                            <span className="status-badge offline" style={{ fontSize: "10px" }}>⚪ notconnect</span>
                          )}
                        </td>
                        <td>
                          {isTrunkPort ? (
                            <span style={{ fontSize: "12px", color: "#6d28d9", fontWeight: "700" }}>
                              Native: VLAN {p.vlan} (Allowed: ALL)
                            </span>
                          ) : (
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
                          )}
                        </td>
                        <td>
                          {isTrunkPort ? (
                            <span style={{ background: "#f5f3ff", color: "#6d28d9", border: "1px solid #c4b5fd", padding: "2px 8px", borderRadius: "12px", fontSize: "11px", fontWeight: "800" }}>
                              🔀 TRUNK (802.1Q)
                            </span>
                          ) : (
                            <span style={{ background: "#f1f5f9", color: "#475569", border: "1px solid #cbd5e1", padding: "2px 8px", borderRadius: "12px", fontSize: "11px", fontWeight: "600" }}>
                              ACCESS
                            </span>
                          )}
                        </td>
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
                                  setTargetVlanId(String(p.vlan || 1));
                                  setIsTrunk(p.mode === "trunk" || !!p.is_uplink);
                                }}
                              >
                                ✏️ Configure Port
                              </button>
                              {p.vlan !== 90 && !isTrunkPort && (
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
      );
    })()}

      {/* ======================================================== */}
      {/* TAB 3: MULTI-VENDOR SWITCH CONFIGURATION (SETTINGS)      */}
      {/* ======================================================== */}
      {activeTab === "switch_settings" && isAdmin && (
        <div>
          {/* SECURITY LOCKDOWN BANNER FOR ADMINISTRATORS */}
          {!isSuperAdmin && (
            <div className="panel" style={{ background: "#fff1f2", border: "1px solid #fecdd3", padding: "18px 20px", borderRadius: "10px", marginBottom: "20px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "10px", color: "#9f1239", fontWeight: "800", fontSize: "16px" }}>
                <span>🔒</span> Cisco &amp; Enterprise Switch Secrets Locked (Developer Only)
              </div>
              <div style={{ fontSize: "13px", color: "#881337", marginTop: "8px", lineHeight: "1.5" }}>
                Modifying Cisco Switch SSH credentials, enable secrets, switch management IPs, and hardware profiles is strictly restricted to the <strong>Developer / Super Administrator</strong>. Administrators have full access to configure VLANs, assign switch ports, and isolate devices, but core hardware connection secrets are locked against tampering.
              </div>
            </div>
          )}

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

                <div className="form-group">
                  <label className="form-label">Chassis Density & Port Count</label>
                  <select
                    className="login-input"
                    value={switchForm.total_ports || 24}
                    onChange={(e) => setSwitchForm({ ...switchForm, total_ports: parseInt(e.target.value, 10) || 24 })}
                  >
                    <option value={24}>24 Ports (Standard 1U Access Switch)</option>
                    <option value={48}>48 Ports (Enterprise High-Density + 4x 10G SFP+ Uplinks)</option>
                  </select>
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
                  disabled={testingSwitch || !isSuperAdmin}
                  title={!isSuperAdmin ? "Only Super Admin can test switch credentials" : "Test switch reachability and credentials"}
                  style={{ display: "flex", alignItems: "center", gap: "6px" }}
                >
                  <span>🔌</span> {testingSwitch ? "Testing Switch Connection..." : "Test Switch Connection"}
                </button>

                <button
                  type="submit"
                  className="primary-button"
                  disabled={savingSwitch || !isSuperAdmin}
                  title={!isSuperAdmin ? "Only Super Admin can save switch credentials" : "Save switch profile"}
                  style={{ display: "flex", alignItems: "center", gap: "6px", opacity: !isSuperAdmin ? 0.6 : 1 }}
                >
                  <span>{isSuperAdmin ? "💾" : "🔒"}</span> {savingSwitch ? "Saving & Activating..." : isSuperAdmin ? "Save & Activate Switch Profile" : "Switch Secrets Locked (Developer Only)"}
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
                          {!cfg.is_active && isSuperAdmin && (
                            <button
                              type="button"
                              className="secondary-button small"
                              onClick={() => handleActivateSwitch(cfg.id, cfg.name)}
                              style={{ marginRight: "6px" }}
                            >
                              ⚡ Activate
                            </button>
                          )}
                          {!isSuperAdmin && (
                            <span style={{ fontSize: "11px", color: "#94a3b8" }}>🔒 Read-Only</span>
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
      {/* TAB 4: CONFIG BACKUPS & CLI DIFF TRACKING                 */}
      {/* ======================================================== */}
      {activeTab === "backups" && (
        <div>
          {/* TOP ACTION BAR & SNAPSHOT CREATION */}
          <div className="panel" style={{ marginBottom: "20px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "16px", marginBottom: "16px" }}>
              <div>
                <div style={{ fontSize: "17px", fontWeight: "800", color: "#0f172a", display: "flex", alignItems: "center", gap: "8px" }}>
                  <span>📜</span>
                  <span>Switch Running-Configuration Backups & CLI Diff Inspector</span>
                </div>
                <div style={{ fontSize: "13px", color: "#64748b", marginTop: "4px" }}>
                  Active Target: <strong>{activeSwitch?.config?.name || "Core Switch 1"}</strong> (<code>{activeSwitch?.config?.management_ip || "192.168.0.2"}</code>) • Automated SHA-256 Checksumming & CLI Diff
                </div>
              </div>

              <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                <button
                  type="button"
                  className="secondary-button small"
                  onClick={handleRunBackupCycle}
                  disabled={runningCycle}
                  style={{ display: "inline-flex", alignItems: "center", gap: "6px", background: "#f0fdf4", borderColor: "#86efac", color: "#15803d", fontWeight: "700" }}
                  title="Run instant automated backup and drift inspection across all switches"
                >
                  <span>⚡</span> {runningCycle ? "Auditing Switches..." : "Run Auto-Backup Cycle"}
                </button>
                <button
                  type="button"
                  className="secondary-button small"
                  onClick={() => { loadBackups(); loadBackupSchedule(); }}
                  disabled={loadingBackups}
                  style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}
                >
                  <span>🔄</span> {loadingBackups ? "Refreshing..." : "Refresh Backups"}
                </button>
              </div>
            </div>

            {/* AUTOMATED BACKUP POLICY & DRIFT CONTROLS */}
            <div style={{ background: "#f8fafc", border: "1px solid #cbd5e1", borderRadius: "10px", padding: "14px 16px", marginBottom: "16px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "10px", marginBottom: "10px" }}>
                <div style={{ fontSize: "13px", fontWeight: "800", color: "#1e293b", display: "flex", alignItems: "center", gap: "6px" }}>
                  <span>⏰</span> Automated Switch Backup &amp; CLI Drift Detection Daemon
                </div>
                <div style={{ display: "flex", gap: "12px", alignItems: "center" }}>
                  <label style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "12px", fontWeight: "700", cursor: "pointer", color: backupSchedule.enabled ? "#15803d" : "#64748b" }}>
                    <input
                      type="checkbox"
                      checked={Boolean(backupSchedule.enabled)}
                      onChange={(e) => handleSaveSchedule({ enabled: e.target.checked })}
                      disabled={savingSchedule}
                    />
                    {backupSchedule.enabled ? "Auto-Scheduler: Active" : "Auto-Scheduler: Paused"}
                  </label>
                  <select
                    value={backupSchedule.interval_minutes || 60}
                    onChange={(e) => handleSaveSchedule({ interval_minutes: Number(e.target.value) })}
                    disabled={savingSchedule || !backupSchedule.enabled}
                    style={{ padding: "4px 8px", fontSize: "12px", border: "1px solid #cbd5e1", borderRadius: "6px", background: "#fff", color: "#0f172a" }}
                  >
                    <option value={15}>Every 15 Minutes</option>
                    <option value={60}>Every 1 Hour (Standard)</option>
                    <option value={360}>Every 6 Hours</option>
                    <option value={1440}>Every 24 Hours (Daily)</option>
                  </select>
                </div>
              </div>

              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "8px", fontSize: "11px", color: "#64748b" }}>
                <div style={{ display: "flex", gap: "16px", alignItems: "center", flexWrap: "wrap" }}>
                  <label style={{ display: "flex", alignItems: "center", gap: "4px", cursor: "pointer" }}>
                    <input
                      type="checkbox"
                      checked={Boolean(backupSchedule.backup_only_on_change)}
                      onChange={(e) => handleSaveSchedule({ backup_only_on_change: e.target.checked })}
                      disabled={savingSchedule}
                    />
                    Save only when CLI changes occur
                  </label>
                  <label style={{ display: "flex", alignItems: "center", gap: "4px", cursor: "pointer" }}>
                    <input
                      type="checkbox"
                      checked={Boolean(backupSchedule.alert_on_drift)}
                      onChange={(e) => handleSaveSchedule({ alert_on_drift: e.target.checked })}
                      disabled={savingSchedule}
                    />
                    Alert via Webhook &amp; Email on CLI drift
                  </label>
                </div>
                <div>
                  Last cycle: <strong>{backupSchedule.last_run_at ? new Date(backupSchedule.last_run_at).toLocaleString() : "Never run"}</strong>
                </div>
              </div>

              {cycleFeedback && (
                <div
                  style={{
                    marginTop: "10px",
                    padding: "8px 12px",
                    borderRadius: "6px",
                    fontSize: "12px",
                    background: cycleFeedback.type === "success" ? "#f0fdf4" : "#fef2f2",
                    color: cycleFeedback.type === "success" ? "#166534" : "#991b1b",
                    border: `1px solid ${cycleFeedback.type === "success" ? "#bbf7d0" : "#fecaca"}`,
                  }}
                >
                  {cycleFeedback.text}
                </div>
              )}
            </div>

            {/* QUICK SNAPSHOT CREATOR */}
            <form onSubmit={handleTakeBackup} style={{ background: "#f8fafc", border: "1px solid #e2e8f0", borderRadius: "10px", padding: "14px 16px" }}>
              <div style={{ fontSize: "13px", fontWeight: "700", color: "#334155", marginBottom: "10px", display: "flex", alignItems: "center", gap: "6px" }}>
                <span>📸</span> Create On-Demand Configuration Snapshot
              </div>
              <div style={{ display: "flex", gap: "12px", flexWrap: "wrap", alignItems: "center" }}>
                <input
                  type="text"
                  placeholder="Snapshot label (e.g. Pre-Maintenance VLAN Change, Weekly Baseline)..."
                  value={backupNameInput}
                  onChange={(e) => setBackupNameInput(e.target.value)}
                  disabled={takingBackup}
                  style={{
                    flex: "1 1 300px",
                    padding: "8px 12px",
                    border: "1px solid #cbd5e1",
                    borderRadius: "6px",
                    fontSize: "13px",
                  }}
                />
                <select
                  value={backupTypeInput}
                  onChange={(e) => setBackupTypeInput(e.target.value)}
                  disabled={takingBackup}
                  style={{
                    padding: "8px 12px",
                    border: "1px solid #cbd5e1",
                    borderRadius: "6px",
                    fontSize: "13px",
                    background: "#fff",
                  }}
                >
                  <option value="manual">Manual Snapshot</option>
                  <option value="pre-change">Pre-Change Snapshot</option>
                  <option value="post-change">Post-Change Snapshot</option>
                  <option value="scheduled">Scheduled Baseline</option>
                </select>
                <button
                  type="submit"
                  className="primary-button small"
                  disabled={takingBackup}
                  style={{ display: "inline-flex", alignItems: "center", gap: "6px", padding: "8px 16px", fontWeight: "700" }}
                >
                  <span>📥</span> {takingBackup ? "Pulling Running-Config..." : "Backup Running-Config Now"}
                </button>
              </div>
            </form>
          </div>

          {/* QUICK DIFF INSPECTOR LAUNCHER */}
          {backups.length > 0 && (
            <div className="panel" style={{ marginBottom: "20px", background: "linear-gradient(135deg, #f8fafc 0%, #eff6ff 100%)", border: "1px solid #bfdbfe" }}>
              <div style={{ fontSize: "15px", fontWeight: "800", color: "#1e3a8a", display: "flex", alignItems: "center", gap: "8px", marginBottom: "8px" }}>
                <span>🔍</span> Interactive CLI Diff Comparator
              </div>
              <div style={{ fontSize: "12px", color: "#475569", marginBottom: "14px" }}>
                Compare live running configuration against a known baseline, or compare two historical snapshots to identify exact command additions, removals, or unauthorized modifications.
              </div>

              <div style={{ display: "flex", gap: "14px", flexWrap: "wrap", alignItems: "center" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <label style={{ fontSize: "12px", fontWeight: "700", color: "#334155" }}>Base Version (Old):</label>
                  <select
                    value={selectedBackupA}
                    onChange={(e) => setSelectedBackupA(e.target.value)}
                    style={{ padding: "6px 10px", borderRadius: "6px", border: "1px solid #cbd5e1", fontSize: "12px", background: "#fff" }}
                  >
                    {backups.map((b) => (
                      <option key={b.id} value={b.id}>
                        #{b.id} - {b.backup_name} ({b.created_at?.slice(0, 16)})
                      </option>
                    ))}
                  </select>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <label style={{ fontSize: "12px", fontWeight: "700", color: "#334155" }}>Compare Mode:</label>
                  <select
                    value={diffCompareMode}
                    onChange={(e) => setDiffCompareMode(e.target.value)}
                    style={{ padding: "6px 10px", borderRadius: "6px", border: "1px solid #cbd5e1", fontSize: "12px", background: "#fff", fontWeight: "600" }}
                  >
                    <option value="live">⚡ Live Active Switch vs Base</option>
                    <option value="two_backups">⚖️ Compare Two Saved Backups</option>
                  </select>
                </div>

                {diffCompareMode === "two_backups" && (
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <label style={{ fontSize: "12px", fontWeight: "700", color: "#334155" }}>Target Version (New):</label>
                    <select
                      value={selectedBackupB}
                      onChange={(e) => setSelectedBackupB(e.target.value)}
                      style={{ padding: "6px 10px", borderRadius: "6px", border: "1px solid #cbd5e1", fontSize: "12px", background: "#fff" }}
                    >
                      {backups.map((b) => (
                        <option key={b.id} value={b.id}>
                          #{b.id} - {b.backup_name} ({b.created_at?.slice(0, 16)})
                        </option>
                      ))}
                    </select>
                  </div>
                )}

                <button
                  type="button"
                  className="primary-button small"
                  style={{ background: "#2563eb", borderColor: "#1d4ed8", fontWeight: "700", display: "inline-flex", alignItems: "center", gap: "6px" }}
                  onClick={() => {
                    if (diffCompareMode === "live") {
                      handleRunDiff(selectedBackupA, null, true);
                    } else {
                      handleRunDiff(selectedBackupA, selectedBackupB, false);
                    }
                  }}
                  disabled={diffLoading}
                >
                  <span>🔍</span> {diffLoading ? "Analyzing Diff..." : (diffCompareMode === "live" ? "Compare Live Switch vs Base" : "Compare Two Snapshots")}
                </button>
              </div>
            </div>
          )}

          {/* HISTORICAL BACKUPS TABLE */}
          <div className="panel">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px" }}>
              <div>
                <div style={{ fontSize: "15px", fontWeight: "700", color: "#0f172a" }}>Configuration History ({backups.length} Backups)</div>
                <div style={{ fontSize: "12px", color: "#64748b" }}>Immutable configuration archives with cryptographic checksums and change summaries.</div>
              </div>
            </div>

            <div className="table-responsive">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Snapshot ID & Label</th>
                    <th>Type</th>
                    <th>Timestamp & Operator</th>
                    <th>Size & Lines</th>
                    <th>SHA-256 Checksum</th>
                    <th>Change vs Preceding</th>
                    <th style={{ textAlign: "right" }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {backups.length === 0 ? (
                    <tr>
                      <td colSpan="7" style={{ textAlign: "center", padding: "28px", color: "#64748b" }}>
                        {loadingBackups ? "Loading switch backups..." : "No configuration backups found. Click 'Backup Running-Config Now' above to take the initial baseline snapshot."}
                      </td>
                    </tr>
                  ) : (
                    backups.map((b, idx) => {
                      const prevB = backups[idx + 1];
                      return (
                        <tr key={b.id}>
                          <td>
                            <div style={{ fontWeight: "700", color: "#0f172a", fontSize: "13px" }}>{b.backup_name}</div>
                            <div style={{ fontSize: "11px", color: "#64748b" }}>Snapshot #{b.id}</div>
                          </td>
                          <td>
                            <span
                              style={{
                                fontSize: "11px",
                                fontWeight: "700",
                                padding: "2px 8px",
                                borderRadius: "12px",
                                background:
                                  b.backup_type === "pre-change"
                                    ? "#fef3c7"
                                    : b.backup_type === "post-change"
                                    ? "#ecfdf5"
                                    : b.backup_type === "scheduled"
                                    ? "#eff6ff"
                                    : "#f1f5f9",
                                color:
                                  b.backup_type === "pre-change"
                                    ? "#92400e"
                                    : b.backup_type === "post-change"
                                    ? "#065f46"
                                    : b.backup_type === "scheduled"
                                    ? "#1e40af"
                                    : "#475569",
                                border: "1px solid rgba(0,0,0,0.06)",
                              }}
                            >
                              {b.backup_type}
                            </span>
                          </td>
                          <td>
                            <div style={{ fontSize: "12px", color: "#1e293b", fontWeight: "600" }}>{b.created_at?.slice(0, 19).replace("T", " ")}</div>
                            <div style={{ fontSize: "11px", color: "#64748b" }}>By: <strong>{b.created_by || "System"}</strong></div>
                          </td>
                          <td>
                            <div style={{ fontSize: "12px", color: "#1e293b", fontWeight: "600" }}>{b.lines_count} lines</div>
                            <div style={{ fontSize: "11px", color: "#64748b" }}>{(b.size_bytes / 1024).toFixed(1)} KB</div>
                          </td>
                          <td>
                            <code style={{ fontSize: "11px", background: "#f8fafc", padding: "2px 6px", borderRadius: "4px", color: "#475569" }} title={b.checksum}>
                              {b.checksum?.slice(0, 10)}...{b.checksum?.slice(-6)}
                            </code>
                          </td>
                          <td>
                            <span style={{ fontSize: "12px", color: b.change_summary?.includes("Identical") ? "#64748b" : (b.change_summary?.includes("Baseline") ? "#2563eb" : "#059669"), fontWeight: "600" }}>
                              {b.change_summary || "—"}
                            </span>
                          </td>
                          <td style={{ textAlign: "right" }}>
                            <div style={{ display: "inline-flex", gap: "6px", alignItems: "center" }}>
                              <button
                                type="button"
                                className="secondary-button small"
                                onClick={() => handleViewBackup(b.id)}
                                title="View full running-configuration text"
                              >
                                👁️ View
                              </button>
                              <a
                                href={`${API_URL}/switches/backups/${b.id}/download`}
                                className="secondary-button small"
                                style={{ textDecoration: "none", display: "inline-flex", alignItems: "center" }}
                                title="Download .cfg file"
                                target="_blank"
                                rel="noreferrer"
                              >
                                💾 Download
                              </a>
                              {prevB && (
                                <button
                                  type="button"
                                  className="secondary-button small"
                                  style={{ borderColor: "#93c5fd", color: "#1d4ed8" }}
                                  onClick={() => handleRunDiff(prevB.id, b.id, false)}
                                  title={`Compare changes between #${prevB.id} and #${b.id}`}
                                >
                                  🔍 Diff vs Prev
                                </button>
                              )}
                              <button
                                type="button"
                                className="secondary-button small"
                                style={{ borderColor: "#a7f3d0", color: "#065f46" }}
                                onClick={() => handleRunDiff(b.id, null, true)}
                                title="Diff live active switch against this backup"
                              >
                                ⚡ Diff vs Live
                              </button>
                              {isSuperAdmin && (
                                <button
                                  type="button"
                                  className="secondary-button small"
                                  style={{ color: "#dc2626", borderColor: "#fca5a5" }}
                                  onClick={() => handleDeleteBackup(b.id)}
                                  disabled={deletingBackupId === b.id}
                                  title="Permanently delete this backup (Super Admin only)"
                                >
                                  {deletingBackupId === b.id ? "..." : "🗑️"}
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })
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
      {/* MODAL: EDIT VLAN (CUSTOMIZE DEPARTMENT NAME & SUBNET)    */}
      {/* ======================================================== */}
      {editingVlan && (
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
              maxWidth: "520px",
              padding: "24px",
              boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.25)",
              maxHeight: "90vh",
              overflowY: "auto",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
              <div style={{ fontSize: "16px", fontWeight: "800", color: "#0f172a", display: "flex", alignItems: "center", gap: "8px" }}>
                <span>✏️</span>
                <span>Customize VLAN {editingVlan.vlan_id} Department Name</span>
              </div>
              <button
                type="button"
                onClick={() => setEditingVlan(null)}
                style={{ background: "transparent", border: "none", fontSize: "18px", color: "#64748b", cursor: "pointer" }}
              >
                ×
              </button>
            </div>

            <div style={{ fontSize: "12px", color: "#64748b", marginBottom: "16px", lineHeight: "1.5" }}>
              Rename this VLAN to match your company structure (e.g. <strong>HR Management</strong>, <strong>IT Operations</strong>, <strong>Finance</strong>). The new name will be updated live on the switch and NETOPS.
            </div>

            {/* QUICK DEPARTMENT PRESET BADGES */}
            <div style={{ marginBottom: "16px" }}>
              <label style={{ display: "block", fontSize: "11px", fontWeight: "700", color: "#475569", marginBottom: "6px", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                1-Click Department Presets
              </label>
              <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                {DEPARTMENT_PRESETS.map((dept) => (
                  <button
                    key={dept.name}
                    type="button"
                    onClick={() => {
                      setEditVlanName(dept.name);
                      setEditVlanDescription(dept.desc);
                      if (dept.subnet) {
                        setEditVlanSubnet(dept.subnet);
                      }
                    }}
                    style={{
                      background: editVlanName === dept.name ? "#eff6ff" : "#f8fafc",
                      border: `1px solid ${editVlanName === dept.name ? "#2563eb" : "#cbd5e1"}`,
                      color: editVlanName === dept.name ? "#1d4ed8" : "#334155",
                      padding: "4px 10px",
                      borderRadius: "6px",
                      fontSize: "11px",
                      fontWeight: "700",
                      cursor: "pointer",
                      transition: "all 0.15s ease",
                    }}
                  >
                    {dept.name.replace(/_/g, " ")}
                  </button>
                ))}
              </div>
            </div>

            <form onSubmit={handleSaveEditVlan}>
              <div style={{ marginBottom: "12px" }}>
                <label style={{ display: "block", fontSize: "12px", fontWeight: "600", color: "#334155", marginBottom: "4px" }}>
                  VLAN ID (Locked)
                </label>
                <input
                  type="text"
                  value={`VLAN ${editingVlan.vlan_id}`}
                  disabled
                  style={{ width: "100%", padding: "8px 12px", borderRadius: "6px", border: "1px solid #e2e8f0", background: "#f1f5f9", fontSize: "13px", fontWeight: "800", color: "#475569" }}
                />
              </div>

              <div style={{ marginBottom: "12px" }}>
                <label style={{ display: "block", fontSize: "12px", fontWeight: "600", color: "#334155", marginBottom: "4px" }}>
                  Department / VLAN Name *
                </label>
                <input
                  type="text"
                  style={{ width: "100%", padding: "8px 12px", borderRadius: "6px", border: "1px solid #cbd5e1", fontSize: "13px" }}
                  placeholder="e.g. HR_Management or IT_Operations"
                  value={editVlanName}
                  onChange={(e) => setEditVlanName(e.target.value)}
                  disabled={savingEditVlan}
                  required
                />
              </div>

              <div style={{ marginBottom: "12px" }}>
                <label style={{ display: "block", fontSize: "12px", fontWeight: "600", color: "#334155", marginBottom: "4px" }}>
                  Subnet CIDR (Optional)
                </label>
                <input
                  type="text"
                  style={{ width: "100%", padding: "8px 12px", borderRadius: "6px", border: "1px solid #cbd5e1", fontSize: "13px" }}
                  placeholder="e.g. 192.168.10.0/24"
                  value={editVlanSubnet}
                  onChange={(e) => setEditVlanSubnet(e.target.value)}
                  disabled={savingEditVlan}
                />
              </div>

              <div style={{ marginBottom: "16px" }}>
                <label style={{ display: "block", fontSize: "12px", fontWeight: "600", color: "#334155", marginBottom: "4px" }}>
                  Purpose / Department Description
                </label>
                <input
                  type="text"
                  style={{ width: "100%", padding: "8px 12px", borderRadius: "6px", border: "1px solid #cbd5e1", fontSize: "13px" }}
                  placeholder="e.g. Human Resources staff, recruitment & onboarding"
                  value={editVlanDescription}
                  onChange={(e) => setEditVlanDescription(e.target.value)}
                  disabled={savingEditVlan}
                />
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px" }}>
                <button
                  type="button"
                  className="secondary-button small"
                  onClick={() => setEditingVlan(null)}
                  disabled={savingEditVlan}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="primary-button small"
                  disabled={savingEditVlan}
                >
                  {savingEditVlan ? "Updating Switch..." : "💾 Save & Deploy to Switch"}
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
              Configure VLAN and port mode for interface <strong>{selectedPort.port}</strong>.
            </div>

            <form onSubmit={handleAssignPort}>
              {/* TRUNK CHECKBOX / TOGGLE */}
              <div
                style={{
                  background: isTrunk ? "#f5f3ff" : "#f8fafc",
                  border: `1.5px solid ${isTrunk ? "#8b5cf6" : "#cbd5e1"}`,
                  borderRadius: "8px",
                  padding: "12px",
                  marginBottom: "16px",
                  transition: "all 0.15s ease",
                }}
              >
                <label style={{ display: "flex", alignItems: "center", gap: "10px", cursor: "pointer", fontWeight: "700", color: isTrunk ? "#6d28d9" : "#334155", fontSize: "13px" }}>
                  <input
                    type="checkbox"
                    checked={isTrunk}
                    onChange={(e) => setIsTrunk(e.target.checked)}
                    style={{ width: "18px", height: "18px", cursor: "pointer", accentColor: "#7c3aed" }}
                  />
                  <span>🔀 Tick to Configure as Trunk Port (802.1Q Uplink)</span>
                </label>
                {isTrunk ? (
                  <div style={{ fontSize: "11px", color: "#6d28d9", marginTop: "6px", marginLeft: "28px", lineHeight: "1.4" }}>
                    ✓ <strong>802.1Q Trunk Uplink Enabled:</strong> Carries multiple tagged VLANs between switches or to a firewall/router uplink.
                  </div>
                ) : (
                  <div style={{ fontSize: "11px", color: "#64748b", marginTop: "4px", marginLeft: "28px" }}>
                    Standard Access port mode for individual workstations, VoIP phones, or printers.
                  </div>
                )}
              </div>

              {/* TARGET / NATIVE VLAN SELECTOR */}
              <div style={{ marginBottom: "16px" }}>
                <label style={{ display: "block", fontSize: "12px", fontWeight: "600", color: "#334155", marginBottom: "4px" }}>
                  {isTrunk ? "Native / Untagged VLAN (Default: VLAN 1) *" : "Target Access VLAN *"}
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
                      VLAN {v.vlan_id} — {v.name} {v.vlan_id === 90 ? "(Quarantine)" : (v.vlan_id === 1 ? "(Default Native)" : "")}
                    </option>
                  ))}
                </select>
                {isTrunk && (
                  <div style={{ fontSize: "11px", color: "#6d28d9", marginTop: "4px", fontWeight: "600" }}>
                    Allowed VLANs: <strong>ALL Active VLANs (1 – 4094)</strong>
                  </div>
                )}
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
                  style={isTrunk ? { background: "#7c3aed", borderColor: "#6d28d9" } : {}}
                >
                  {assigningPort ? "Applying..." : (isTrunk ? "🔀 Apply Trunk Uplink" : "Apply Access VLAN")}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ======================================================== */}
      {/* MODAL: VIEW SWITCH RUNNING-CONFIG                         */}
      {/* ======================================================== */}
      {viewingBackup && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: "rgba(15, 23, 42, 0.7)",
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
              maxWidth: "850px",
              maxHeight: "90vh",
              display: "flex",
              flexDirection: "column",
              overflow: "hidden",
              boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.25)",
            }}
          >
            <div style={{ padding: "16px 20px", borderBottom: "1px solid #e2e8f0", display: "flex", justifyContent: "space-between", alignItems: "center", background: "#f8fafc" }}>
              <div>
                <div style={{ fontSize: "16px", fontWeight: "800", color: "#0f172a" }}>
                  📜 {viewingBackup.backup_name}
                </div>
                <div style={{ fontSize: "12px", color: "#64748b", marginTop: "2px" }}>
                  Snapshot #{viewingBackup.id} • {viewingBackup.lines_count} lines • {(viewingBackup.size_bytes / 1024).toFixed(1)} KB • Checksum: <code>{viewingBackup.checksum?.slice(0, 16)}...</code>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setViewingBackup(null)}
                style={{ background: "transparent", border: "none", fontSize: "18px", cursor: "pointer", color: "#64748b" }}
              >
                ✕
              </button>
            </div>

            <div style={{ flex: 1, overflowY: "auto", padding: "16px", background: "#0f172a" }}>
              <pre style={{ margin: 0, color: "#f8fafc", fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace", fontSize: "12px", lineHeight: "1.6" }}>
                {viewingBackup.config_text}
              </pre>
            </div>

            <div style={{ padding: "12px 20px", borderTop: "1px solid #e2e8f0", background: "#f8fafc", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div style={{ fontSize: "12px", color: "#64748b" }}>
                Archived: {viewingBackup.created_at?.slice(0, 19).replace("T", " ")} by {viewingBackup.created_by}
              </div>
              <div style={{ display: "flex", gap: "8px" }}>
                <button
                  type="button"
                  className="secondary-button small"
                  onClick={() => {
                    navigator.clipboard.writeText(viewingBackup.config_text);
                    setCopiedConfig(true);
                    setTimeout(() => setCopiedConfig(false), 2500);
                  }}
                >
                  {copiedConfig ? "✓ Copied!" : "📋 Copy Config"}
                </button>
                <a
                  href={`${API_URL}/switches/backups/${viewingBackup.id}/download`}
                  className="primary-button small"
                  style={{ textDecoration: "none" }}
                  target="_blank"
                  rel="noreferrer"
                >
                  💾 Download .cfg
                </a>
                <button
                  type="button"
                  className="secondary-button small"
                  onClick={() => setViewingBackup(null)}
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ======================================================== */}
      {/* MODAL: CLI DIFF INSPECTOR                                 */}
      {/* ======================================================== */}
      {showDiffModal && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: "rgba(15, 23, 42, 0.7)",
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
              maxWidth: "920px",
              maxHeight: "92vh",
              display: "flex",
              flexDirection: "column",
              overflow: "hidden",
              boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.25)",
            }}
          >
            <div style={{ padding: "16px 20px", borderBottom: "1px solid #e2e8f0", display: "flex", justifyContent: "space-between", alignItems: "center", background: "#f8fafc" }}>
              <div>
                <div style={{ fontSize: "16px", fontWeight: "800", color: "#0f172a", display: "flex", alignItems: "center", gap: "8px" }}>
                  <span>🔍</span> CLI Configuration Diff Analysis
                </div>
                {diffResult && !diffResult.error && (
                  <div style={{ fontSize: "12px", color: "#64748b", marginTop: "3px", display: "flex", gap: "10px", alignItems: "center" }}>
                    <span style={{ color: "#16a34a", fontWeight: "700" }}>+{diffResult.additions} Additions</span>
                    <span style={{ color: "#dc2626", fontWeight: "700" }}>-{diffResult.deletions} Removals</span>
                    <span>{diffResult.identical ? "✅ Configurations are 100% Identical" : "⚠️ Configuration Discrepancies Detected"}</span>
                  </div>
                )}
              </div>
              <button
                type="button"
                onClick={() => setShowDiffModal(false)}
                style={{ background: "transparent", border: "none", fontSize: "18px", cursor: "pointer", color: "#64748b" }}
              >
                ✕
              </button>
            </div>

            {/* SECURITY ALERTS IN DIFF */}
            {diffResult?.security_alerts && diffResult.security_alerts.length > 0 && (
              <div style={{ padding: "12px 20px", background: "#fffbeb", borderBottom: "1px solid #fde68a" }}>
                <div style={{ fontSize: "12px", fontWeight: "700", color: "#92400e", marginBottom: "4px" }}>
                  🚨 Security Discrepancies Flagged by NETOPS Inspector:
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                  {diffResult.security_alerts.map((alert, i) => (
                    <div key={i} style={{ fontSize: "12px", color: "#78350f" }}>{alert}</div>
                  ))}
                </div>
              </div>
            )}

            {/* DIFF CODE CONTAINER */}
            <div style={{ flex: 1, overflowY: "auto", padding: "16px", background: "#0f172a" }}>
              {diffLoading ? (
                <div style={{ textAlign: "center", padding: "40px", color: "#94a3b8" }}>
                  Analyzing live running-configuration and computing line differences...
                </div>
              ) : diffResult?.error ? (
                <div style={{ padding: "16px", background: "#450a0a", color: "#fca5a5", borderRadius: "8px" }}>
                  Error calculating diff: {diffResult.error}
                </div>
              ) : diffResult?.diff_items ? (
                <div style={{ fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace", fontSize: "12px", lineHeight: "1.5" }}>
                  {diffResult.diff_items.map((item, idx) => {
                    const isAdded = item.type === "added";
                    const isRemoved = item.type === "removed";
                    return (
                      <div
                        key={idx}
                        style={{
                          display: "flex",
                          background: isAdded ? "rgba(16, 185, 129, 0.18)" : (isRemoved ? "rgba(239, 68, 68, 0.22)" : "transparent"),
                          color: isAdded ? "#34d399" : (isRemoved ? "#f87171" : "#94a3b8"),
                          padding: "1px 8px",
                          borderLeft: isAdded ? "3px solid #10b981" : (isRemoved ? "3px solid #ef4444" : "3px solid transparent"),
                        }}
                      >
                        <span style={{ width: "40px", textAlign: "right", paddingRight: "10px", color: "#475569", userSelect: "none" }}>
                          {item.line_old || ""}
                        </span>
                        <span style={{ width: "40px", textAlign: "right", paddingRight: "12px", color: "#475569", userSelect: "none" }}>
                          {item.line_new || ""}
                        </span>
                        <span style={{ width: "20px", fontWeight: "700", userSelect: "none" }}>
                          {isAdded ? "+" : (isRemoved ? "-" : " ")}
                        </span>
                        <span style={{ flex: 1, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                          {item.text}
                        </span>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div style={{ color: "#94a3b8", textAlign: "center", padding: "20px" }}>No diff data available.</div>
              )}
            </div>

            <div style={{ padding: "12px 20px", borderTop: "1px solid #e2e8f0", background: "#f8fafc", display: "flex", justifyContent: "flex-end" }}>
              <button
                type="button"
                className="secondary-button small"
                onClick={() => setShowDiffModal(false)}
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
