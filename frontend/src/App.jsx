import React, { useEffect, useState } from "react";
import LoginPage from "./components/LoginPage";
import UsersPage from "./components/UsersPage";

const API_URL =
  window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1"
    ? (import.meta.env.VITE_API_URL || "http://127.0.0.1:8000")
    : `${window.location.protocol}//${window.location.hostname}:8000`;

const WS_URL =
  window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1"
    ? (import.meta.env.VITE_WS_URL || "ws://127.0.0.1:8000/ws/events")
    : `${window.location.protocol === "https:" ? "wss:" : "ws:"}//${window.location.hostname}:8000/ws/events`;

function App() {
  const [currentUser, setCurrentUser] = useState(() => {
    try {
      const token = localStorage.getItem("netops_token");
      const user = localStorage.getItem("netops_user");
      if (token && user) {
        return JSON.parse(user);
      }
      return null;
    } catch {
      return null;
    }
  });

  const [activationToken] = useState(() => {
    try {
      const params = new URLSearchParams(window.location.search);
      return params.get("activation_token");
    } catch {
      return null;
    }
  });

  const isAdmin = currentUser?.role === "admin" || currentUser?.role === "super_admin";
  const isSuperAdmin = currentUser?.role === "super_admin";

  const getAuthHeaders = (extra = {}) => {
    const token = localStorage.getItem("netops_token");
    const headers = { ...extra };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    return headers;
  };

  const handleLoginSuccess = (user, token) => {
    localStorage.setItem("netops_token", token);
    localStorage.setItem("netops_user", JSON.stringify(user));
    setCurrentUser(user);
    setActivePage("dashboard");
  };

  const handleLogout = () => {
    const token = localStorage.getItem("netops_token");
    if (token) {
      fetch(`${API_URL}/auth/logout`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      }).catch(() => {});
    }
    localStorage.removeItem("netops_token");
    localStorage.removeItem("netops_user");
    setCurrentUser(null);
    setActivePage("dashboard");
  };

  // Keep active user session duration updated in real time via heartbeat
  useEffect(() => {
    if (!currentUser) return;
    const interval = setInterval(() => {
      const token = localStorage.getItem("netops_token");
      if (!token) return;
      fetch(`${API_URL}/auth/heartbeat`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      }).catch(() => {});
    }, 30000);
    return () => clearInterval(interval);
  }, [currentUser]);

  useEffect(() => {
    const token = localStorage.getItem("netops_token");
    if (!token) {
      setCurrentUser(null);
      return;
    }
    fetch(`${API_URL}/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => {
        if (!res.ok) throw new Error("Invalid session");
        return res.json();
      })
      .then((userData) => {
        setCurrentUser(userData);
        localStorage.setItem("netops_user", JSON.stringify(userData));
      })
      .catch(() => {
        localStorage.removeItem("netops_token");
        localStorage.removeItem("netops_user");
        setCurrentUser(null);
      });
  }, []);

  const [activePage, setActivePage] = useState("dashboard");
  const [devices, setDevices] = useState([]);
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(null);
  const [wsConnected, setWsConnected] = useState(false);
  const [newDeviceAlert, setNewDeviceAlert] = useState(null);
  const [highlightedDeviceId, setHighlightedDeviceId] =
    useState(null);
  const [automationResult, setAutomationResult] = useState(null);
  const [accessSchedules, setAccessSchedules] = useState({});
  const [scheduleLoading, setScheduleLoading] = useState(null);
  const [scheduleForm, setScheduleForm] = useState({
    schedule_id: null,
    device_id: null,
    start_time: "08:00:00",
    end_time: "17:00:00",
    days: "daily",
    enabled: true,
  });
  const [deviceFilter, setDeviceFilter] = useState("all");
  const [vlanFilter, setVlanFilter] = useState("all");
  const [eventTypeFilter, setEventTypeFilter] = useState("all");
  const [eventLimit, setEventLimit] = useState(50);
  const [eventOffset, setEventOffset] = useState(0);
  const [lanScanLoading, setLanScanLoading] = useState(false);
  const [lanScanResult, setLanScanResult] = useState(null);
  const [lanDevicesScanning, setLanDevicesScanning] = useState(false);
  const [lanDevicesResult, setLanDevicesResult] = useState(null);
  const [detectedSubnet, setDetectedSubnet] = useState("192.168.0.0/24");
  const [detectedInterfaces, setDetectedInterfaces] = useState([]);
  const [lanSearchQuery, setLanSearchQuery] = useState("");
  const [lanFilterStatus, setLanFilterStatus] = useState("all");

  const openScheduleModal = (device) => {
    if (!isAdmin) {
      alert("Permission Denied: Standard users cannot configure access schedules. Only Administrators and Super Administrators can manage schedules.");
      return;
    }
    if (!device) return;
    const existingSchedule = accessSchedules[device.id]?.[0];
    setScheduleForm({
      schedule_id: existingSchedule?.id || null,
      device_id: device.id,
      start_time: existingSchedule?.start_time || "08:00:00",
      end_time: existingSchedule?.end_time || "17:00:00",
      days: existingSchedule?.days || "daily",
      enabled: existingSchedule?.is_active ?? true,
    });
  };

  const loadDetectedSubnets = async () => {
    try {
      const response = await fetch(`${API_URL}/discovery/local-subnets`);
      if (response.ok) {
        const data = await response.json();
        if (data.default_network) {
          setDetectedSubnet(data.default_network);
        }
        if (Array.isArray(data.interfaces)) {
          setDetectedInterfaces(data.interfaces);
        }
      }
    } catch (err) {
      console.warn("Could not fetch detected subnets:", err);
    }
  };

  const scanAllLanDevices = async (overrideNetwork = null) => {
    if (!isAdmin) {
      alert("Permission Denied: Standard users cannot trigger active network scanning. Only Administrators can run LAN discovery.");
      return;
    }
    const targetNetwork = (overrideNetwork || detectedSubnet || "192.168.0.0/24").trim();
    setLanDevicesScanning(true);
    try {
      const response = await fetch(`${API_URL}/discovery/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ network: targetNetwork }),
      });
      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || `Scan failed: ${response.status}`);
      }
      const data = await response.json();
      setLanDevicesResult(data);
      await loadDevices();
      await loadEvents();
      await loadAccessSchedules();
    } catch (err) {
      console.error("Discovery scan error:", err);
      alert("LAN Discovery scan failed: " + err.message);
    } finally {
      setLanDevicesScanning(false);
    }
  };

  const scanLanUpdates = async () => {
    if (!isAdmin) {
      alert("Permission Denied: Standard users cannot initiate endpoint update scans.");
      return;
    }
    setLanScanLoading(true);
    setLanScanResult(null);
    try {
      const response = await fetch(`${API_URL}/endpoint-updates/scan-lan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      if (!response.ok) {
        throw new Error(`LAN scan failed: ${response.status}`);
      }
      const data = await response.json();
      setLanScanResult(data);
      await loadDevices();
    } catch (err) {
      console.error("LAN scan error:", err);
      alert("Failed to complete LAN update scan: " + err.message);
    } finally {
      setLanScanLoading(false);
    }
  };



  const [patchJobs, setPatchJobs] = useState([]);
  const [deployModalDevice, setDeployModalDevice] = useState(null);
  const [deployingStatus, setDeployingStatus] = useState(null);
  const [showJobsModal, setShowJobsModal] = useState(false);
  const [selectedJobDetails, setSelectedJobDetails] = useState(null);
  const [scheduleMode, setScheduleMode] = useState("now");
  const [scheduledDateTime, setScheduledDateTime] = useState("");

  const loadPatchJobs = async () => {
    try {
      const response = await fetch(`${API_URL}/endpoint-updates/jobs?limit=50`);
      if (response.ok) {
        const data = await response.json();
        setPatchJobs(Array.isArray(data) ? data : []);
      }
    } catch (err) {
      console.error("Failed to load patch jobs:", err);
    }
  };

  const getActiveJobForDevice = (device) => {
    if (!device || !Array.isArray(patchJobs)) return null;
    return patchJobs.find(
      (job) =>
        (job.status === "PENDING" || job.status === "IN_PROGRESS" || job.status === "SCHEDULED") &&
        ((device.hostname && job.hostname && device.hostname.toLowerCase() === job.hostname.toLowerCase()) ||
         (device.mac_address && job.mac_address && device.mac_address.replace(/[:-]/g, "").toUpperCase() === job.mac_address.replace(/[:-]/g, "").toUpperCase()) ||
         (device.id && job.device_id && device.id === job.device_id))
    );
  };

  const openDeployModal = (device) => {
    if (!isAdmin) {
      alert("Permission Denied: Standard users cannot deploy central updates. Only Administrators can manage patch remediation.");
      return;
    }
    setScheduleMode("now");
    setScheduledDateTime("");
    setDeployModalDevice(device);
  };

  const deployUpdates = async (target, scheduledTime = null) => {
    const hostname = target.hostname || "local";
    const ip_address = target.ip_address || target.device_ip || null;
    const mac_address = target.mac_address || null;
    const machine_id = target.machine_id || null;
    const device_id = target.device_id || (target.vlan_id !== undefined ? target.id : null);
    const scheduled_at = scheduledTime ? new Date(scheduledTime).toISOString() : null;

    setDeployingStatus("dispatching");
    try {
      const response = await fetch(`${API_URL}/endpoint-updates/jobs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          hostname,
          ip_address,
          mac_address,
          machine_id,
          device_id,
          action: "INSTALL_ALL_UPDATES",
          initiated_by: "Admin Console",
          scheduled_at,
        }),
      });

      if (!response.ok) {
        throw new Error(`Failed to queue update job (${response.status})`);
      }

      const job = await response.json();
      setDeployingStatus("success");
      setSelectedJobDetails(job);
      await loadPatchJobs();
      await loadDevices();
      return job;
    } catch (err) {
      console.error("Deploy updates error:", err);
      alert("Failed to deploy updates: " + err.message);
      setDeployingStatus("error");
      return null;
    }
  };

  const runJobNow = async (jobId) => {
    try {
      const response = await fetch(`${API_URL}/endpoint-updates/jobs/${jobId}/run-now`, {
        method: "POST",
      });
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.detail || `Server error (${response.status})`);
      }
      const updatedJob = await response.json();
      setSelectedJobDetails(updatedJob);
      await loadPatchJobs();
      await loadDevices();
      return updatedJob;
    } catch (err) {
      console.error("Run job error:", err);
      alert("Failed to start update: " + err.message);
      return null;
    }
  };

  // ------------------------------------------------------------
  // LOAD DEVICES
  // ------------------------------------------------------------
  
  const totalDevices = devices.length;
  const onlineDevices = devices.filter((device) => device.status === "online").length;
  const pendingDevices = devices.filter(
    (device) => device.approval_status === "pending"
  ).length;

const rejectedDevices = devices.filter(
  (device) => device.approval_status === "rejected"
).length;  

const quarantinedDevices = devices.filter(
    (device) => device.enforcement_status === "quarantined"
  ).length;

  const loadDevices = async () => {
    try {
      const response = await fetch(`${API_URL}/devices/`);

      if (!response.ok) {
        throw new Error("Failed to load devices");
      }

      const data = await response.json();

      setDevices(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error("Device loading error:", error);
    } finally {
      setLoading(false);
    }
  };

  // ------------------------------------------------------------
  // LOAD EVENTS
  // ------------------------------------------------------------

const loadEvents = async () => {
  try {
    const params = new URLSearchParams();

    params.set("limit", String(eventLimit));
    params.set("offset", String(eventOffset));

    if (eventTypeFilter !== "all") {
      params.set("event_type", eventTypeFilter);
    }

    const response = await fetch(
      `${API_URL}/events/?${params.toString()}`
    );

    if (!response.ok) {
      throw new Error("Failed to load events");
    }

    const data = await response.json();

    setEvents(Array.isArray(data) ? data : []);
  } catch (error) {
    console.error("Event loading error:", error);
  }
};



  // ------------------------------------------------------------
  // CREATE ACCESS SCHEDULE
  // ------------------------------------------------------------

    const createAccessSchedule = async () => {
    if (!scheduleForm.device_id) {
      return;
    }

    setScheduleLoading(scheduleForm.device_id);

    try {
      const isEditing = Boolean(scheduleForm.schedule_id);

      const response = await fetch(
        isEditing
          ? `${API_URL}/access-schedules/${scheduleForm.schedule_id}`
          : `${API_URL}/access-schedules/`,
        {
          method: isEditing ? "PUT" : "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            device_id: scheduleForm.device_id,
            start_time: scheduleForm.start_time,
            end_time: scheduleForm.end_time,
            days: scheduleForm.days,
            enabled: scheduleForm.enabled,
          }),
        }
      );

      if (!response.ok) {
        throw new Error(
          isEditing
            ? "Failed to update access schedule"
            : "Failed to create access schedule"
        );
      }

      await loadAccessSchedules();
      await loadDevices();
      await loadEvents();

      setScheduleForm({
        schedule_id: null,
        device_id: null,
        start_time: "08:00:00",
        end_time: "17:00:00",
        days: "daily",
        enabled: true,
      });
    } catch (error) {
      console.error(
        "Access schedule save error:",
        error
      );
    } finally {
      setScheduleLoading(null);
    }
  };
  // ------------------------------------------------------------
  // RESET ACCESS SCHEDULE
  // ------------------------------------------------------------

  const resetAccessSchedule = async (deviceId) => {
    const schedules = accessSchedules[deviceId] || [];

    if (schedules.length === 0) {
      return;
    }

    const confirmed = window.confirm(
      `Reset the access schedule for device #${deviceId}?`
    );

    if (!confirmed) {
      return;
    }

    setScheduleLoading(deviceId);

    try {
      for (const schedule of schedules) {
        const response = await fetch(
          `${API_URL}/access-schedules/${schedule.id}`,
          {
            method: "DELETE",
          }
        );

        if (!response.ok) {
          throw new Error(
            `Failed to delete schedule ${schedule.id}`
          );
        }
      }

      await loadAccessSchedules();
      await deviceAction(deviceId, "enforce");
      setScheduleForm((current) => {
        if (current.device_id === deviceId) {
          return {
            schedule_id: null,
            device_id: null,
            start_time: "08:00",
            end_time: "17:00",
            days: "daily",
            enabled: true,
          };
        }

        return current;
      });
    } catch (error) {
      console.error(
        "Access schedule reset error:",
        error
      );
    } finally {
      setScheduleLoading(null);
    }
  };
  // ------------------------------------------------------------
  // LOAD ACCESS SCHEDULES
  // ------------------------------------------------------------

  const loadAccessSchedules = async () => {
    try {
      const response = await fetch(
        `${API_URL}/access-schedules/`
      );

      if (!response.ok) {
        throw new Error(
          "Failed to load access schedules"
        );
      }

      const data = await response.json();

      const groupedSchedules = {};

      if (Array.isArray(data)) {
        data.forEach((schedule) => {
          if (!groupedSchedules[schedule.device_id]) {
            groupedSchedules[schedule.device_id] = [];
          }

          groupedSchedules[schedule.device_id].push(
            schedule
          );
        });
      }

      setAccessSchedules(groupedSchedules);
    } catch (error) {
      console.error(
        "Access schedule loading error:",
        error
      );
    }
  };
  // ------------------------------------------------------------
  // INITIAL LOAD + AUTO REFRESH
  // ------------------------------------------------------------

  useEffect(() => {
    if (!currentUser) return;
    loadDevices();
    loadEvents();
    loadAccessSchedules();
    loadPatchJobs();
    loadDetectedSubnets();
  }, [currentUser]);

  useEffect(() => {
    if (!currentUser) return;
    const hasActiveJob = patchJobs.some((j) => j.status === "PENDING" || j.status === "IN_PROGRESS");
    if (!hasActiveJob) return;

    const timer = setInterval(() => {
      loadPatchJobs();
      loadDevices();
    }, 4000);

    return () => clearInterval(timer);
  }, [currentUser, patchJobs]);

  useEffect(() => {
    if (!currentUser) return;
    loadEvents();
  }, [currentUser, eventTypeFilter, eventLimit, eventOffset]);

  // ------------------------------------------------------------
  // WEBSOCKET
  // ------------------------------------------------------------

  useEffect(() => {
    if (!currentUser) return;
    let socket;
    let reconnectTimer;

    const connect = () => {
      try {
        socket = new WebSocket(WS_URL);

        socket.onopen = () => {
          console.log("NETOPS WebSocket connected");
          setWsConnected(true);
        };

        socket.onmessage = (message) => {
          try {
            const event = JSON.parse(message.data);

            setEvents((previous) => {
              const exists = previous.some(
                (item) =>
                  item.id &&
                  event.id &&
                  item.id === event.id
              );

              if (exists) {
                return previous;
              }

              return [event, ...previous];
            });

            if (event.event_type && event.event_type.startsWith("patch_job_")) {
              loadPatchJobs();
              loadDevices();
            }

            if (event.event_type === "new_device") {
              setNewDeviceAlert(event);
              setHighlightedDeviceId(event.device_id);

              loadDevices();

              setTimeout(() => {
                setNewDeviceAlert(null);
                setHighlightedDeviceId(null);
              }, 8000);
            }
          } catch (error) {
            console.error(
              "WebSocket event error:",
              error
            );
          }
        };

        socket.onerror = () => {
          setWsConnected(false);
        };

        socket.onclose = () => {
          setWsConnected(false);

          reconnectTimer = setTimeout(
            connect,
            5000
          );
        };
      } catch (error) {
        console.error(
          "WebSocket connection error:",
          error
        );

        reconnectTimer = setTimeout(
          connect,
          5000
        );
      }
    };

    connect();

    return () => {
      clearTimeout(reconnectTimer);

      if (socket) {
        socket.close();
      }
    };
  }, []);

  // ------------------------------------------------------------
  // DEVICE ACTION
  // ------------------------------------------------------------

  const deviceAction = async (
  deviceId,
  action,
  value = null
) => {
  if (!isAdmin) {
    alert("Permission Denied: Standard users have read-only access. Only Administrators and Super Administrators can approve devices, alter VLANs, or change Internet access.");
    return;
  }
  const actionKey = `${action}-${deviceId}`;

  try {
    setActionLoading(actionKey);

    let url = `${API_URL}/devices/${deviceId}`;
    let method = "PATCH";
    let body = null;

    // ----------------------------------------------------------
    // APPROVE DEVICE
    // ----------------------------------------------------------

    if (action === "approve") {
      url += "/approve";
      method = "PATCH";
    }

    // ----------------------------------------------------------
    // REJECT DEVICE
    // ----------------------------------------------------------

    else if (action === "reject") {
      url += "/reject";
      method = "PATCH";
    }

    // ----------------------------------------------------------
    // CLASSIFY DEVICE
    // computer -> VLAN 20
    // cctv     -> VLAN 30
    // printer  -> VLAN 40
    // unknown  -> VLAN 90
    // ----------------------------------------------------------

    else if (action === "type") {
      url += "/type";
      method = "PATCH";

      body = JSON.stringify({
        device_type: value,
      });
    }

    // ----------------------------------------------------------
    // UPDATE VLAN DIRECTLY
    // ----------------------------------------------------------

    else if (action === "vlan") {
      url += "/vlan";
      method = "PATCH";

      body = JSON.stringify({
        vlan_id: parseInt(value, 10),
      });
    }

    // ----------------------------------------------------------
    // ALLOW INTERNET ACCESS
    // ----------------------------------------------------------

    else if (action === "allow") {
      url += "/allow";
      method = "POST";
    }

    // ----------------------------------------------------------
    // DISALLOW / QUARANTINE INTERNET ACCESS
    // ----------------------------------------------------------

    else if (
      action === "disallow" ||
      action === "quarantine"
    ) {
      url += "/disallow";
      method = "POST";
    }

    // ----------------------------------------------------------
    // ENFORCE CURRENT POLICY
    // ----------------------------------------------------------

    else if (action === "enforce") {
      url += "/enforce";
      method = "POST";
    }

    // ----------------------------------------------------------
    // AUTOMATIC VLAN ASSIGNMENT
    // ----------------------------------------------------------

    else if (action === "automate-vlan") {
      url += "/automate-vlan";
      method = "POST";
    }

    else {
      throw new Error(
        `Unsupported action: ${action}`
      );
    }

    const options = {
      method,
      headers: {
        "Content-Type": "application/json",
      },
    };

    if (body !== null) {
      options.body = body;
    }

    const response = await fetch(
      url,
      options
    );

    const responseText =
      await response.text();

    if (!response.ok) {
      throw new Error(
        responseText ||
          `HTTP ${response.status}`
      );
    }

    let result = {};

    if (responseText) {
      try {
        result = JSON.parse(
          responseText
        );
      } catch {
        result = {
          message: responseText,
        };
      }
    }

    console.log(
      "NETOPS action successful:",
      result
    );

    // Save VLAN automation result
    if (action === "automate-vlan") {
      setAutomationResult(result);
    }

    // Refresh devices and events
    await loadDevices();
    await loadEvents();

  } catch (error) {
    console.error(
      `Device action ${action} failed:`,
      error
    );

    alert(
      `Action failed: ${
        error.message ||
        "Unknown error"
      }`
    );

  } finally {
    setActionLoading(null);
  }
};
// ------------------------------------------------------------
// TIME SCHEDULE HELPERS
// ------------------------------------------------------------

const HOURS_24 = Array.from({ length: 24 }, (_, i) => String(i).padStart(2, "0"));
const MINUTES_60 = Array.from({ length: 60 }, (_, i) => String(i).padStart(2, "0"));
const SECONDS_60 = Array.from({ length: 60 }, (_, i) => String(i).padStart(2, "0"));

const parseTimeParts = (timeStr, fallbackH = "08", fallbackM = "00", fallbackS = "00") => {
  if (!timeStr) return { h: fallbackH, m: fallbackM, s: fallbackS };
  const parts = String(timeStr).split(":");
  return {
    h: (parts[0] || fallbackH).padStart(2, "0"),
    m: (parts[1] || fallbackM).padStart(2, "0"),
    s: (parts[2] || fallbackS).padStart(2, "0"),
  };
};

// ------------------------------------------------------------
// DEVICES PAGE
// ------------------------------------------------------------

const DevicesPage = () => {
  const getDeviceIcon = (type) => {
    switch (type) {
      case "computer":
        return "💻";
      case "cctv":
        return "📹";
      case "printer":
        return "🖨️";
      default:
        return "⚠️";
    }
  };

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <div className="page-title">
            Connected Devices
          </div>

          <div className="page-description">
            Devices detected on the LAN and their current
            classification, VLAN and Internet access state.
          </div>
        </div>

        <div style={{ display: "flex", gap: "8px" }}>
          <button
            className="primary-button"
            type="button"
            onClick={scanLanUpdates}
            disabled={lanScanLoading}
            style={{ display: "flex", alignItems: "center", gap: "6px" }}
          >
            {lanScanLoading ? "⏳ Scanning LAN Machines..." : "⚡ Scan LAN for Updates (Agentless)"}
          </button>
          <button
            className="secondary-button"
            type="button"
            onClick={() => { loadPatchJobs(); setShowJobsModal(true); }}
            style={{ display: "flex", alignItems: "center", gap: "6px" }}
          >
            📋 Update Jobs ({patchJobs.length})
          </button>
          <button
            className="secondary-button"
            type="button"
            onClick={loadDevices}
            disabled={lanScanLoading}
          >
            Refresh Devices
          </button>
        </div>
      </div>

      {!isAdmin && (
        <div style={{ background: "rgba(59, 130, 246, 0.12)", border: "1px solid rgba(59, 130, 246, 0.4)", borderRadius: "8px", padding: "10px 16px", marginBottom: "16px", display: "flex", alignItems: "center", gap: "10px", fontSize: "13px", color: "#93c5fd" }}>
          <span>👁️</span>
          <div><strong>Standard User (Read-Only Monitoring):</strong> You have view-only access to network devices and telemetry. Administrative actions (Approve, Disconnect, VLAN reassignments, Patch Deployment) require Administrator privileges.</div>
        </div>
      )}

      {lanScanResult && (
        <div className="panel" style={{ background: "rgba(16, 185, 129, 0.12)", border: "1px solid #10b981", margin: "12px 0 16px", padding: "12px 16px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <div style={{ fontWeight: "600", color: "#10b981" }}>
                ✓ Agentless LAN Scan Complete ({lanScanResult.network})
              </div>
              <div style={{ fontSize: "13px", color: "var(--text-secondary, #9ca3af)", marginTop: "4px" }}>
                Assessed {lanScanResult.machines_assessed} machine(s) across the LAN: <strong>{lanScanResult.updates_available_count} need updates</strong>, <strong>{lanScanResult.up_to_date_count} up to date</strong>.
              </div>
            </div>
            <button
              className="secondary-button small"
              onClick={() => setLanScanResult(null)}
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {pendingDevices > 0 && (
        <div className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">
                ⚠️ New Devices Require Attention
              </div>

              <div className="panel-subtitle">
                {pendingDevices} device(s) are waiting
                for administrator approval.
              </div>
            </div>
          </div>
        </div>
      )}
      {devices.filter(
        (device) => device.approval_status === "rejected"
      ).length > 0 && (
        <div className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">
                🚫 Rejected Devices
              </div>

              <div className="panel-subtitle">
                Devices rejected by the administrator and
                available for later review.
              </div>
            </div>

            <div className="settings-status">
              <span className="status-dot offline" />
              {
                devices.filter(
                  (device) =>
                    device.approval_status === "rejected"
                ).length
              } Rejected
            </div>
          </div>
        

          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>DEVICE</th>
                  <th>TYPE</th>
                  <th>VLAN</th>
                  <th>INTERNET</th>
                  <th>ACTION</th>
                </tr>
              </thead>

              <tbody>
                {devices
                  .filter(
                    (device) =>
                      device.approval_status === "rejected"
                  )
                  .map((device) => (
                    <tr key={device.id}>
                      <td>
                        <strong>
                          {device.hostname ||
                            device.ip_address ||
                            device.mac_address}
                        </strong>
                      </td>

                      <td>
                        {getDeviceIcon(device.device_type)}{" "}
                        {device.device_type || "Unknown"}
                      </td>

                      <td>
                        VLAN {device.vlan_id || "—"}
                      </td>

                      <td>
                        <span className="status-badge rejected">
                          Blocked
                        </span>
                      </td>

                      <td>
                        <button
                          className="approve-button"
                          type="button"
                          onClick={() =>
                            deviceAction(
                              device.id,
                              "approve"
                            )
                          }
                          disabled={
                            actionLoading ===
                            `approve-${device.id}`
                          }
                        >
                          {actionLoading ===
                          `approve-${device.id}`
                            ? "Approving..."
                            : "Approve"}
                        </button>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="panel">
        <div className="panel-header">
          <div>
            <div className="panel-title">
              LAN Device Inventory
            </div>

            <div className="panel-subtitle">
              Manage classification, approval and Internet
              access for devices detected on the LAN.
            </div>
          </div>

          <div className="settings-status">
            <span className="status-dot online" />
            {totalDevices} Devices
          </div>
        </div>
        
        <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", padding: "12px 0", borderBottom: "1px solid var(--border-color, #27272a)", marginBottom: "16px" }}>
          <button
            type="button"
            className={`secondary-button small ${deviceFilter === "all" ? "active" : ""}`}
            style={deviceFilter === "all" ? { background: "var(--accent-color, #3b82f6)", color: "#fff" } : {}}
            onClick={() => setDeviceFilter("all")}
          >
            All LAN Devices ({devices.length})
          </button>
          <button
            type="button"
            className={`secondary-button small ${deviceFilter === "needs_updates" ? "active" : ""}`}
            style={deviceFilter === "needs_updates" ? { background: "#d97706", color: "#fff" } : { borderColor: "#f59e0b" }}
            onClick={() => setDeviceFilter("needs_updates")}
          >
            ⚠️ Needs Updates ({devices.filter(d => d.update_status === "updates_available").length})
          </button>
          <button
            type="button"
            className={`secondary-button small ${deviceFilter === "queued" ? "active" : ""}`}
            style={deviceFilter === "queued" ? { background: "#f59e0b", color: "#000", fontWeight: "700" } : { borderColor: "#f59e0b", color: "#f59e0b" }}
            onClick={() => setDeviceFilter("queued")}
          >
            ⚡ Queued / Updating ({devices.filter(d => Boolean(getActiveJobForDevice(d))).length})
          </button>
          <button
            type="button"
            className={`secondary-button small ${deviceFilter === "up_to_date" ? "active" : ""}`}
            style={deviceFilter === "up_to_date" ? { background: "#059669", color: "#fff" } : { borderColor: "#10b981" }}
            onClick={() => setDeviceFilter("up_to_date")}
          >
            ✓ Up to Date ({devices.filter(d => d.update_status === "up_to_date").length})
          </button>
          <button
            type="button"
            className={`secondary-button small ${deviceFilter === "unmonitored" ? "active" : ""}`}
            style={deviceFilter === "unmonitored" ? { background: "#4b5563", color: "#fff" } : {}}
            onClick={() => setDeviceFilter("unmonitored")}
          >
            ⚪ Unmonitored ({devices.filter(d => !d.update_status || d.update_status === "unmonitored").length})
          </button>
          <button
            type="button"
            className={`secondary-button small ${deviceFilter === "online" ? "active" : ""}`}
            style={deviceFilter === "online" ? { background: "var(--accent-color, #3b82f6)", color: "#fff" } : {}}
            onClick={() => setDeviceFilter("online")}
          >
            🟢 Online ({devices.filter(d => d.status === "online").length})
          </button>
          <button
            type="button"
            className={`secondary-button small ${deviceFilter === "offline" ? "active" : ""}`}
            style={deviceFilter === "offline" ? { background: "#dc2626", color: "#fff" } : { borderColor: "#ef4444", color: "#f87171" }}
            onClick={() => setDeviceFilter("offline")}
          >
            🔴 Offline ({devices.filter(d => d.status === "offline").length})
          </button>
          <button
            type="button"
            className={`secondary-button small ${deviceFilter === "pending" ? "active" : ""}`}
            style={deviceFilter === "pending" ? { background: "#d97706", color: "#fff" } : {}}
            onClick={() => setDeviceFilter("pending")}
          >
            Pending ({pendingDevices})
          </button>
          <button
            type="button"
            className={`secondary-button small ${deviceFilter === "quarantined" ? "active" : ""}`}
            style={deviceFilter === "quarantined" ? { background: "#dc2626", color: "#fff" } : {}}
            onClick={() => setDeviceFilter("quarantined")}
          >
            Quarantined ({quarantinedDevices})
          </button>
        </div>
        {scheduleForm.device_id && (
          <div
            className="panel"
            style={{
              margin: "16px 0",
              padding: "16px",
            }}
          >
            <div className="panel-header">
              <div>
                <div className="panel-title">
                  Access Schedule
                </div>

                <div className="panel-subtitle">
                  Configure Internet access hours for device #
                  {scheduleForm.device_id}
                </div>
              </div>
            </div>

            <div
              style={{
                display: "flex",
                gap: "16px",
                flexWrap: "wrap",
                alignItems: "end",
              }}
            >
              {/* START TIME (HOURS, MINUTES, SECONDS) */}
              <div>
                <label style={{ display: "block", marginBottom: "4px", fontSize: "12px", fontWeight: "700", color: "#93c5fd" }}>
                  Start Time (Hours : Minutes : Seconds)
                </label>
                <div style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}>
                  <select
                    value={parseTimeParts(scheduleForm.start_time, "08", "00", "00").h}
                    onChange={(e) => {
                      const cur = parseTimeParts(scheduleForm.start_time, "08", "00", "00");
                      setScheduleForm({
                        ...scheduleForm,
                        start_time: `${e.target.value}:${cur.m}:${cur.s}`,
                      });
                    }}
                    style={{
                      padding: "6px 8px",
                      borderRadius: "6px",
                      background: "#1e293b",
                      color: "#f8fafc",
                      border: "1px solid #475569",
                      fontFamily: "monospace",
                      fontWeight: "700",
                      fontSize: "13px",
                    }}
                    title="Select Start Hour (00-23)"
                  >
                    {HOURS_24.map((h) => (
                      <option key={`sh-${h}`} value={h}>{h} hr</option>
                    ))}
                  </select>
                  <span style={{ fontWeight: "800", color: "#94a3b8" }}>:</span>
                  <select
                    value={parseTimeParts(scheduleForm.start_time, "08", "00", "00").m}
                    onChange={(e) => {
                      const cur = parseTimeParts(scheduleForm.start_time, "08", "00", "00");
                      setScheduleForm({
                        ...scheduleForm,
                        start_time: `${cur.h}:${e.target.value}:${cur.s}`,
                      });
                    }}
                    style={{
                      padding: "6px 8px",
                      borderRadius: "6px",
                      background: "#1e293b",
                      color: "#f8fafc",
                      border: "1px solid #475569",
                      fontFamily: "monospace",
                      fontWeight: "700",
                      fontSize: "13px",
                    }}
                    title="Select Start Minute (00-59)"
                  >
                    {MINUTES_60.map((m) => (
                      <option key={`sm-${m}`} value={m}>{m} min</option>
                    ))}
                  </select>
                  <span style={{ fontWeight: "800", color: "#94a3b8" }}>:</span>
                  <select
                    value={parseTimeParts(scheduleForm.start_time, "08", "00", "00").s}
                    onChange={(e) => {
                      const cur = parseTimeParts(scheduleForm.start_time, "08", "00", "00");
                      setScheduleForm({
                        ...scheduleForm,
                        start_time: `${cur.h}:${cur.m}:${e.target.value}`,
                      });
                    }}
                    style={{
                      padding: "6px 8px",
                      borderRadius: "6px",
                      background: "#1e293b",
                      color: "#f8fafc",
                      border: "1px solid #475569",
                      fontFamily: "monospace",
                      fontWeight: "700",
                      fontSize: "13px",
                    }}
                    title="Select Start Second (00-59)"
                  >
                    {SECONDS_60.map((s) => (
                      <option key={`ss-${s}`} value={s}>{s} sec</option>
                    ))}
                  </select>
                </div>
              </div>

              {/* END TIME (HOURS, MINUTES, SECONDS) */}
              <div>
                <label style={{ display: "block", marginBottom: "4px", fontSize: "12px", fontWeight: "700", color: "#fca5a5" }}>
                  End Time (Hours : Minutes : Seconds)
                </label>
                <div style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}>
                  <select
                    value={parseTimeParts(scheduleForm.end_time, "17", "00", "00").h}
                    onChange={(e) => {
                      const cur = parseTimeParts(scheduleForm.end_time, "17", "00", "00");
                      setScheduleForm({
                        ...scheduleForm,
                        end_time: `${e.target.value}:${cur.m}:${cur.s}`,
                      });
                    }}
                    style={{
                      padding: "6px 8px",
                      borderRadius: "6px",
                      background: "#1e293b",
                      color: "#f8fafc",
                      border: "1px solid #475569",
                      fontFamily: "monospace",
                      fontWeight: "700",
                      fontSize: "13px",
                    }}
                    title="Select End Hour (00-23)"
                  >
                    {HOURS_24.map((h) => (
                      <option key={`eh-${h}`} value={h}>{h} hr</option>
                    ))}
                  </select>
                  <span style={{ fontWeight: "800", color: "#94a3b8" }}>:</span>
                  <select
                    value={parseTimeParts(scheduleForm.end_time, "17", "00", "00").m}
                    onChange={(e) => {
                      const cur = parseTimeParts(scheduleForm.end_time, "17", "00", "00");
                      setScheduleForm({
                        ...scheduleForm,
                        end_time: `${cur.h}:${e.target.value}:${cur.s}`,
                      });
                    }}
                    style={{
                      padding: "6px 8px",
                      borderRadius: "6px",
                      background: "#1e293b",
                      color: "#f8fafc",
                      border: "1px solid #475569",
                      fontFamily: "monospace",
                      fontWeight: "700",
                      fontSize: "13px",
                    }}
                    title="Select End Minute (00-59)"
                  >
                    {MINUTES_60.map((m) => (
                      <option key={`em-${m}`} value={m}>{m} min</option>
                    ))}
                  </select>
                  <span style={{ fontWeight: "800", color: "#94a3b8" }}>:</span>
                  <select
                    value={parseTimeParts(scheduleForm.end_time, "17", "00", "00").s}
                    onChange={(e) => {
                      const cur = parseTimeParts(scheduleForm.end_time, "17", "00", "00");
                      setScheduleForm({
                        ...scheduleForm,
                        end_time: `${cur.h}:${cur.m}:${e.target.value}`,
                      });
                    }}
                    style={{
                      padding: "6px 8px",
                      borderRadius: "6px",
                      background: "#1e293b",
                      color: "#f8fafc",
                      border: "1px solid #475569",
                      fontFamily: "monospace",
                      fontWeight: "700",
                      fontSize: "13px",
                    }}
                    title="Select End Second (00-59)"
                  >
                    {SECONDS_60.map((s) => (
                      <option key={`es-${s}`} value={s}>{s} sec</option>
                    ))}
                  </select>
                </div>
              </div>

              {/* DAYS */}
              <div>
                <label style={{ display: "block", marginBottom: "4px", fontSize: "12px", fontWeight: "700" }}>Days</label>
                <select
                  value={scheduleForm.days}
                  onChange={(e) =>
                    setScheduleForm({
                      ...scheduleForm,
                      days: e.target.value,
                    })
                  }
                  style={{
                    padding: "6px 10px",
                    borderRadius: "6px",
                    background: "#1e293b",
                    color: "#f8fafc",
                    border: "1px solid #475569",
                    fontWeight: "600",
                    fontSize: "13px",
                  }}
                >
                  <option value="daily">Daily (Every Day)</option>
                  <option value="weekdays">Weekdays (Mon - Fri)</option>
                  <option value="weekends">Weekends (Sat - Sun)</option>
                  <option value="monday">Monday Only</option>
                  <option value="tuesday">Tuesday Only</option>
                  <option value="wednesday">Wednesday Only</option>
                  <option value="thursday">Thursday Only</option>
                  <option value="friday">Friday Only</option>
                  <option value="saturday">Saturday Only</option>
                  <option value="sunday">Sunday Only</option>
                </select>
              </div>

              {/* ENABLED */}
              <label
                style={{
                  display: "flex",
                  gap: "6px",
                  alignItems: "center",
                  cursor: "pointer",
                  fontSize: "13px",
                  fontWeight: "600",
                }}
              >
                <input
                  type="checkbox"
                  checked={scheduleForm.enabled}
                  onChange={(e) =>
                    setScheduleForm({
                      ...scheduleForm,
                      enabled: e.target.checked,
                    })
                  }
                />
                Enabled
              </label>

              {/* QUICK PRESETS */}
              <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                <button
                  type="button"
                  className="secondary-button small"
                  style={{ fontSize: "11px", padding: "4px 8px" }}
                  onClick={() => {
                    const now = new Date();
                    const sH = String(now.getHours()).padStart(2, "0");
                    const sM = String(now.getMinutes()).padStart(2, "0");
                    const sS = String(now.getSeconds()).padStart(2, "0");
                    const end = new Date(now.getTime() + 30 * 1000);
                    const eH = String(end.getHours()).padStart(2, "0");
                    const eM = String(end.getMinutes()).padStart(2, "0");
                    const eS = String(end.getSeconds()).padStart(2, "0");
                    setScheduleForm({
                      ...scheduleForm,
                      start_time: `${sH}:${sM}:${sS}`,
                      end_time: `${eH}:${eM}:${eS}`,
                      enabled: true,
                    });
                  }}
                  title="Quick test: Allow internet for the next 30 seconds"
                >
                  ⚡ +30s Test
                </button>
                <button
                  type="button"
                  className="secondary-button small"
                  style={{ fontSize: "11px", padding: "4px 8px" }}
                  onClick={() => {
                    const now = new Date();
                    const sH = String(now.getHours()).padStart(2, "0");
                    const sM = String(now.getMinutes()).padStart(2, "0");
                    const sS = String(now.getSeconds()).padStart(2, "0");
                    const end = new Date(now.getTime() + 60 * 1000);
                    const eH = String(end.getHours()).padStart(2, "0");
                    const eM = String(end.getMinutes()).padStart(2, "0");
                    const eS = String(end.getSeconds()).padStart(2, "0");
                    setScheduleForm({
                      ...scheduleForm,
                      start_time: `${sH}:${sM}:${sS}`,
                      end_time: `${eH}:${eM}:${eS}`,
                      enabled: true,
                    });
                  }}
                  title="Quick test: Allow internet for the next 1 minute"
                >
                  ⚡ +1m Test
                </button>
                <button
                  type="button"
                  className="secondary-button small"
                  style={{ fontSize: "11px", padding: "4px 8px" }}
                  onClick={() => {
                    setScheduleForm({
                      ...scheduleForm,
                      start_time: "08:00:00",
                      end_time: "17:00:00",
                      days: "weekdays",
                      enabled: true,
                    });
                  }}
                  title="Standard work hours 08:00 - 17:00 (Weekdays)"
                >
                  💼 Work Hours
                </button>
              </div>

              {/* ACTION BUTTONS */}
              <div style={{ display: "flex", gap: "6px", marginLeft: "auto" }}>
                <button
                  type="button"
                  className="primary-button small"
                  onClick={createAccessSchedule}
                  disabled={
                    scheduleLoading === scheduleForm.device_id
                  }
                  style={{ fontWeight: "700" }}
                >
                  {scheduleLoading === scheduleForm.device_id
                    ? "Saving..."
                    : "💾 Save Schedule"}
                </button>

                <button
                  type="button"
                  className="secondary-button small"
                  onClick={() =>
                    setScheduleForm({
                      device_id: null,
                      start_time: "08:00:00",
                      end_time: "17:00:00",
                      days: "daily",
                      enabled: true,
                    })
                  }
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>DEVICE</th>
                <th>CONNECTION</th>
                <th>TYPE</th>
                <th>VLAN</th>
                <th>UPDATE STATUS</th>
                <th>APPROVAL</th>
                <th>INTERNET</th>
                <th>ENFORCEMENT</th>
                <th>SCHEDULE</th>
                <th>ACTIONS</th>
              </tr>
            </thead>

            <tbody>
              {devices.length === 0 ? (
                <tr>
                  <td colSpan="10">
                    <div className="empty-state">
                      No devices detected.
                    </div>
                  </td>
                </tr>
              ) : (
                devices
  .filter((device) => {
    if (deviceFilter === "all") return true;

    if (deviceFilter === "online") {
      return device.status === "online";
    }

    if (deviceFilter === "offline") {
      return device.status === "offline";
    }

    if (deviceFilter === "needs_updates") {
      return device.update_status === "updates_available";
    }

    if (deviceFilter === "queued") {
      return Boolean(getActiveJobForDevice(device));
    }

    if (deviceFilter === "up_to_date") {
      return device.update_status === "up_to_date";
    }

    if (deviceFilter === "unmonitored") {
      return !device.update_status || device.update_status === "unmonitored";
    }

    if (deviceFilter === "pending") {
      return device.approval_status === "pending";
    }

if (deviceFilter === "rejected") {
  return device.approval_status === "rejected";
}    
if (deviceFilter === "quarantined") {
  return device.enforcement_status === "quarantined";
}
    return true;
  })
  .map((device) => (
                  <tr key={device.id}>
                    <td>
                      <div className="device-primary">
                        <span
                          style={{
                            marginRight: "8px",
                            fontSize: "18px",
                          }}
                        >
                          {getDeviceIcon(
                            device.device_type
                          )}
                        </span>

                        {device.hostname ||
                          "Unknown Device"}
                      </div>

                      <div className="device-secondary">
                        {device.ip_address || "-"}
                      </div>

                      <div className="device-secondary">
                        {device.mac_address || "-"}
                      </div>
                    </td>

                    <td>
                      {device.status === "online" ? (
                        <span
                          className="status-badge allowed"
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: "5px",
                            fontSize: "11px",
                            fontWeight: "700",
                            padding: "2px 8px",
                          }}
                        >
                          <span className="status-dot online" /> ONLINE
                        </span>
                      ) : (
                        <span
                          className="status-badge blocked"
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: "5px",
                            fontSize: "11px",
                            fontWeight: "700",
                            padding: "2px 8px",
                          }}
                        >
                          <span className="status-dot offline" /> OFFLINE
                        </span>
                      )}
                    </td>

                    <td>
                      <select
                        value={
                          device.device_type ||
                          "unknown"
                        }
                        disabled={
                          actionLoading ===
                          `type-${device.id}`
                        }
                        onChange={(event) =>
                          deviceAction(
                            device.id,
                            "type",
                            event.target.value
                          )
                        }
                      >
                        <option value="unknown">
                          🚨 Unknown (Quarantine VLAN 90)
                        </option>

                        <option value="computer">
                          💻 Computer (VLAN 20)
                        </option>

                        <option value="cctv">
                          📹 CCTV (VLAN 30)
                        </option>

                        <option value="printer">
                          🖨️ Printer (VLAN 40)
                        </option>
                      </select>
                    </td>

                    <td>
                      <select
                        value={device.vlan_id || 90}
                        disabled={
                          actionLoading ===
                          `vlan-${device.id}`
                        }
                        onChange={(event) =>
                          deviceAction(
                            device.id,
                            "vlan",
                            event.target.value
                          )
                        }
                        style={{
                          padding: "4px 8px",
                          borderRadius: "6px",
                          border:
                            device.vlan_id === 90 || !device.vlan_id
                              ? "1px solid #ef4444"
                              : "1px solid #3b82f6",
                          background:
                            device.vlan_id === 90 || !device.vlan_id
                              ? "#450a0a"
                              : "#1e293b",
                          color:
                            device.vlan_id === 90 || !device.vlan_id
                              ? "#fca5a5"
                              : "#93c5fd",
                          fontWeight: "600",
                          cursor: "pointer",
                        }}
                        title="Change VLAN: VLAN 90 immediately disconnects internet"
                      >
                        <option value="20">VLAN 20 - Workstation</option>
                        <option value="30">VLAN 30 - CCTV</option>
                        <option value="40">VLAN 40 - Printers</option>
                        <option value="90">🚨 VLAN 90 - Quarantine</option>
                      </select>
                    </td>

                    <td>
                      {(() => {
                        const activeJob = getActiveJobForDevice(device);
                        if (activeJob) {
                          return (
                            <div>
                              <span
                                className="status-badge warning"
                                style={{
                                  cursor: "pointer",
                                  display: "inline-flex",
                                  alignItems: "center",
                                  gap: "5px",
                                  background: activeJob.status === "SCHEDULED" ? "#6366f1" : "#f59e0b",
                                  color: activeJob.status === "SCHEDULED" ? "#ffffff" : "#000",
                                  fontWeight: "700",
                                }}
                                onClick={() => {
                                  setSelectedJobDetails(activeJob);
                                  setShowJobsModal(true);
                                }}
                                title="Click to view update progress and logs"
                              >
                                <span>{activeJob.status === "SCHEDULED" ? "📅" : "⚡"}</span>
                                {activeJob.status === "IN_PROGRESS"
                                  ? `UPDATING ${activeJob.progress_percent}%`
                                  : activeJob.status === "SCHEDULED"
                                  ? "SCHEDULED"
                                  : "QUEUED"}
                              </span>
                              <div className="device-secondary" style={{ fontSize: "11px", marginTop: "3px" }}>
                                Job #{activeJob.id} {activeJob.status === "SCHEDULED" && activeJob.scheduled_at ? `(At ${new Date(activeJob.scheduled_at.endsWith("Z") ? activeJob.scheduled_at : activeJob.scheduled_at + "Z").toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })})` : activeJob.is_local ? "(Local)" : "(Remote Agent)"}
                              </div>
                              {(activeJob.status === "PENDING" || activeJob.status === "SCHEDULED") && (
                                <button
                                  type="button"
                                  className="primary-button small"
                                  style={{
                                    marginTop: "5px",
                                    fontSize: "11px",
                                    padding: "3px 8px",
                                    backgroundColor: "#10b981",
                                    borderColor: "#059669",
                                    display: "inline-flex",
                                    alignItems: "center",
                                    gap: "4px",
                                    fontWeight: "600",
                                  }}
                                  onClick={async (e) => {
                                    e.stopPropagation();
                                    await runJobNow(activeJob.id);
                                    setShowJobsModal(true);
                                  }}
                                  title="Continue update deployment immediately"
                                >
                                  ▶️ Continue Update
                                </button>
                              )}
                            </div>
                          );
                        }

                        if (device.update_status === "up_to_date") {
                          return (
                            <div>
                              <span className="status-badge allowed" title={`Last checked: ${device.last_update_check || 'recently'}`}>
                                ✓ UP TO DATE
                              </span>
                              {device.operating_system && (
                                <div className="device-secondary" style={{ fontSize: "11px", marginTop: "3px" }}>
                                  {device.operating_system} {device.os_version || ""}
                                </div>
                              )}
                            </div>
                          );
                        }

                        if (device.update_status === "updates_available") {
                          return (
                            <div>
                              <span className="status-badge warning" title={`${device.pending_updates} updates pending`}>
                                ⚠️ {device.pending_updates ?? "—"} UPDATES
                              </span>
                              {device.operating_system && (
                                <div className="device-secondary" style={{ fontSize: "11px", marginTop: "3px" }}>
                                  {device.operating_system} {device.os_version || ""}
                                </div>
                              )}
                              <button
                                type="button"
                                className="primary-button small"
                                style={{
                                  marginTop: "6px",
                                  fontSize: "11px",
                                  padding: "3px 8px",
                                  backgroundColor: "#10b981",
                                  borderColor: "#059669",
                                  display: "inline-flex",
                                  alignItems: "center",
                                  gap: "4px",
                                  fontWeight: "600",
                                }}
                                onClick={() => openDeployModal(device)}
                                title="Centrally deploy pending updates to this machine"
                              >
                                ⚡ Deploy Updates
                              </button>
                            </div>
                          );
                        }

                        return (
                          <div>
                            <span className="status-badge offline" style={{ opacity: 0.6 }} title="No telemetry agent reporting for this LAN machine">
                              ⚪ NO AGENT
                            </span>
                          </div>
                        );
                      })()}
                    </td>

                    <td>
                      {device.approval_status ===
                      "approved" ? (
                        <span className="status-badge allowed">
                          Approved
                        </span>
                      ) : device.approval_status ===
                        "rejected" ? (
                        <span className="status-badge blocked">
                          Rejected
                        </span>
                      ) : (
                        <span className="status-badge pending">
                          Pending
                        </span>
                      )}
                    </td>
                    <td>
                      {device.internet_access_authorized ? (
                        <span className="status-badge allowed">
                          Authorized
                        </span>
                      ) : (
                        <span className="status-badge blocked">
                          Not Authorized
                        </span>
                      )}
                    </td>

                    <td>
                      {device.enforcement_status ===
                      "allowed" ? (
                        <span className="status-badge allowed">
                          Allowed
                        </span>
                      ) : (
                        <span className="status-badge blocked">
                          Quarantined
                        </span>
                      )}
                    </td>
                    <td>
                      {accessSchedules[device.id] &&
                      accessSchedules[device.id].length > 0 ? (
                        <div>
                          {accessSchedules[device.id].map(
                            (schedule) => (
                              <div
                                key={schedule.id}
                                style={{
                                  marginBottom: "4px",
                                }}
                              >
                                <span className="status-badge allowed" style={{ fontFamily: "monospace", fontSize: "11px" }}>
                                  {schedule.start_time} - {schedule.end_time}
                                </span>
                                <div className="device-secondary">
                                  {schedule.days}
                                </div>
                              </div>
                            )
                          )}
                        </div>
                      ) : (
                        <span className="status-badge blocked">
                          No Schedule
                        </span>
                      )}
                      {accessSchedules[device.id] &&
                        accessSchedules[device.id].length > 0 && (
                          <button
                            type="button"
                            className="secondary-button small"
                            style={{ marginTop: "6px" }}
                            onClick={() =>
                              resetAccessSchedule(device.id)
                            }
                            disabled={
                              scheduleLoading === device.id
                            }
                          >
                            {scheduleLoading === device.id
                              ? "Resetting..."
                              : "Reset Schedule"}
                          </button>
                        )}
                    </td>
                    <td>
                      <div
                        style={{
                          display: "flex",
                          gap: "6px",
                          flexWrap: "wrap",
                        }}
                      >
                        <button
                          type="button"
                          className="secondary-button small"
onClick={() => {
  const existingSchedule =
    accessSchedules[device.id]?.[0];

  setScheduleForm({
    schedule_id: existingSchedule?.id || null,
    device_id: device.id,
    start_time:
      existingSchedule?.start_time ||
      "08:00:00",
    end_time:
      existingSchedule?.end_time ||
      "17:00:00",
    days:
      existingSchedule?.days ||
      "daily",
    enabled:
      existingSchedule?.enabled ??
      true,
  });
}}
                        >
                          Set Schedule
                        </button>
                        {device.approval_status !==
                          "approved" && (
                          <button
                            type="button"
                            className="primary-button small"
                            disabled={
                              actionLoading ===
                              `approve-${device.id}`
                            }
                            onClick={() =>
                              deviceAction(
                                device.id,
                                "approve"
                              )
                            }
                          >
                            {actionLoading ===
                            `approve-${device.id}`
                              ? "..."
                              : "Approve"}
                          </button>
                        )}

                        {device.approval_status !==
                          "rejected" && (
                          <button
                            type="button"
                            className="secondary-button small"
                            disabled={
                              actionLoading ===
                              `reject-${device.id}`
                            }
                            onClick={() =>
                              deviceAction(
                                device.id,
                                "reject"
                              )
                            }
                          >
                            {actionLoading ===
                            `reject-${device.id}`
                              ? "..."
                              : "Reject"}
                          </button>
                        )}

                        {device.approval_status ===
                          "approved" &&
                          device.enforcement_status !==
                            "allowed" && (
                          <button
                            type="button"
                            className="primary-button small"
                            disabled={
                              actionLoading ===
                              `allow-${device.id}`
                            }
                            onClick={() =>
                              deviceAction(
                                device.id,
                                "allow"
                              )
                            }
                          >
                            {actionLoading ===
                            `allow-${device.id}`
                              ? "..."
                              : "Allow Internet"}
                          </button>
                        )}

                        {device.approval_status ===
                          "approved" &&
                          device.enforcement_status ===
                            "allowed" && (
                          <button
                            type="button"
                            className="secondary-button small"
                            disabled={
                              actionLoading ===
                              `disallow-${device.id}`
                            }
                            onClick={() =>
                              deviceAction(
                                device.id,
                                "disallow"
                              )
                            }
                          >
                            {actionLoading ===
                            `disallow-${device.id}`
                              ? "..."
                              : "Disconnect"}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

// ------------------------------------------------------------
// LAN SCANNER & DYNAMIC DISCOVERY PAGE
// ------------------------------------------------------------

const LanScannerPage = () => {
  const onlineDevices = devices.filter((d) => d.status === "online");
  const offlineDevices = devices.filter((d) => d.status === "offline");
  const ipChangedEvents = events.filter((e) => e.event_type === "ip_address_changed");
  const ipChangedDeviceIds = new Set(ipChangedEvents.map((e) => e.device_id));

  // Filter devices
  const filteredDevices = devices.filter((device) => {
    // Status filter
    if (lanFilterStatus === "all" && device.status !== "online") return false;
    if (lanFilterStatus === "offline" && device.status !== "offline") return false;
    if (lanFilterStatus === "ip-changed" && !ipChangedDeviceIds.has(device.id)) return false;
    if (lanFilterStatus === "allowed" && (device.enforcement_status !== "allowed" || device.status !== "online")) return false;
    if (lanFilterStatus === "quarantined" && (device.enforcement_status === "allowed" || device.status !== "online")) return false;
    if (lanFilterStatus === "pending" && device.approval_status !== "pending") return false;

    // Search query
    if (lanSearchQuery.trim()) {
      const q = lanSearchQuery.toLowerCase();
      const ip = (device.ip_address || "").toLowerCase();
      const mac = (device.mac_address || "").toLowerCase();
      const host = (device.hostname || "").toLowerCase();
      const vendor = (device.vendor || "").toLowerCase();
      return ip.includes(q) || mac.includes(q) || host.includes(q) || vendor.includes(q);
    }

    return true;
  });

  const getDeviceIcon = (type) => {
    switch (type) {
      case "computer": return "💻";
      case "cctv": return "📹";
      case "printer": return "🖨️";
      case "router": return "🌐";
      case "firewall": return "🛡️";
      default: return "🖥️";
    }
  };

  const allowedCount = onlineDevices.filter((d) => d.enforcement_status === "allowed").length;
  const quarantinedCount = onlineDevices.filter((d) => d.enforcement_status !== "allowed").length;

  return (
    <div className="page">
      {/* HEADER */}
      <div className="page-header">
        <div>
          <div className="page-title" style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <span>📡</span> LAN Device Scanner & Dynamic Discovery
          </div>
          <div className="page-description">
            Scan your physical local network, discover all connected machines, automatically reconcile dynamic DHCP IP changes, and enforce firewall rules on the fly.
          </div>
        </div>

        <button
          className="secondary-button"
          onClick={() => {
            loadDevices();
            loadEvents();
            loadDetectedSubnets();
          }}
          disabled={lanDevicesScanning}
        >
          🔄 Refresh
        </button>
      </div>

      {!isAdmin && (
        <div style={{ background: "rgba(59, 130, 246, 0.12)", border: "1px solid rgba(59, 130, 246, 0.4)", borderRadius: "8px", padding: "10px 16px", marginBottom: "16px", display: "flex", alignItems: "center", gap: "10px", fontSize: "13px", color: "#93c5fd" }}>
          <span>👁️</span>
          <div><strong>Standard User (Read-Only Scanner View):</strong> You have read-only visibility into discovered LAN devices. Triggering network sweeps and updating device approvals require Administrator privileges.</div>
        </div>
      )}

      {/* CONTROL & SCAN PANEL */}
      <div className="panel" style={{ background: "linear-gradient(180deg, #1e293b 0%, #0f172a 100%)", borderColor: "#334155", marginBottom: "16px" }}>
        <div style={{ display: "flex", flexWrap: "wrap", justifyContent: "space-between", alignItems: "center", gap: "16px" }}>
          <div>
            <div style={{ fontSize: "12px", textTransform: "uppercase", letterSpacing: "0.08em", color: "#94a3b8", fontWeight: "700" }}>
              TARGET LAN INTERFACE & SUBNET
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "8px", flexWrap: "wrap" }}>
              {detectedInterfaces.map((iface) => (
                <button
                  key={iface.interface}
                  type="button"
                  onClick={() => setDetectedSubnet(iface.network)}
                  style={{
                    padding: "6px 12px",
                    borderRadius: "6px",
                    fontSize: "12px",
                    fontWeight: "600",
                    background: detectedSubnet === iface.network ? "rgba(59, 130, 246, 0.25)" : "rgba(15, 23, 42, 0.6)",
                    border: detectedSubnet === iface.network ? "1px solid #3b82f6" : "1px solid #334155",
                    color: detectedSubnet === iface.network ? "#60a5fa" : "#94a3b8",
                    cursor: "pointer",
                    display: "inline-flex",
                    alignItems: "center",
                    gap: "6px",
                  }}
                >
                  <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: iface.is_virtual ? "#64748b" : "#10b981" }} />
                  {iface.interface} ({iface.ip}) - {iface.network}
                </button>
              ))}

              <div style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}>
                <input
                  type="text"
                  value={detectedSubnet}
                  onChange={(e) => setDetectedSubnet(e.target.value)}
                  placeholder="e.g. 192.168.0.0/24"
                  style={{
                    background: "#0b1120",
                    border: "1px solid #334155",
                    color: "#f8fafc",
                    padding: "6px 12px",
                    borderRadius: "6px",
                    fontSize: "13px",
                    fontFamily: "monospace",
                    width: "140px",
                  }}
                />
              </div>
            </div>
          </div>

          <div>
            <button
              className="primary-button"
              type="button"
              onClick={() => scanAllLanDevices()}
              disabled={lanDevicesScanning}
              style={{
                fontSize: "14px",
                fontWeight: "700",
                padding: "12px 24px",
                display: "inline-flex",
                alignItems: "center",
                gap: "10px",
                background: lanDevicesScanning ? "#2563eb" : "#3b82f6",
                boxShadow: "0 4px 14px rgba(59, 130, 246, 0.35)",
                cursor: lanDevicesScanning ? "not-allowed" : "pointer",
              }}
            >
              {lanDevicesScanning ? (
                <>
                  <span style={{ display: "inline-block", animation: "spin 1s linear infinite" }}>🔄</span>
                  Scanning LAN ({detectedSubnet})...
                </>
              ) : (
                <>
                  <span style={{ fontSize: "16px" }}>📡</span>
                  Scan All LAN Devices
                </>
              )}
            </button>
          </div>
        </div>

        {/* SCAN RESULT BANNER */}
        {lanDevicesResult && (
          <div
            style={{
              marginTop: "16px",
              padding: "10px 14px",
              borderRadius: "6px",
              background: "rgba(16, 185, 129, 0.12)",
              border: "1px solid #10b981",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <div style={{ fontSize: "13px", color: "#10b981" }}>
              ✓ <strong>LAN Scan Completed:</strong> Discovered <strong>{lanDevicesResult.devices_discovered}</strong> active device(s) on network <code>{lanDevicesResult.network}</code>. Reconciled and synced with NETOPS database.
            </div>
            <button
              className="secondary-button small"
              onClick={() => setLanDevicesResult(null)}
              style={{ padding: "2px 8px", fontSize: "11px" }}
            >
              Dismiss
            </button>
          </div>
        )}
      </div>

      {/* METRICS KPI CARDS */}
      <div className="report-grid">
        <ReportCard
          title="Online on LAN"
          value={onlineDevices.length}
          description="Active physical and virtual devices discovered on this subnet."
        />
        <ReportCard
          title="Offline / Disconnected"
          value={offlineDevices.length}
          description="Previously registered devices not responding to active ARP/ICMP probes."
        />
        <ReportCard
          title="Dynamic IP Changes"
          value={ipChangedDeviceIds.size}
          description="Devices that acquired new dynamic DHCP IP addresses."
        />
        <ReportCard
          title="Allowed Internet"
          value={allowedCount}
          description="Devices authorized and actively passing traffic through Sophos."
        />
        <ReportCard
          title="Quarantined on Sophos"
          value={quarantinedCount}
          description="Devices dropped by Sophos firewall top quarantine rule."
        />
      </div>

      {/* FILTER & SEARCH BAR */}
      <div className="panel" style={{ padding: "14px 18px", margin: "16px 0 12px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
            <button
              type="button"
              className={lanFilterStatus === "all" ? "primary-button small" : "secondary-button small"}
              onClick={() => setLanFilterStatus("all")}
            >
              🟢 All Online ({onlineDevices.length})
            </button>
            <button
              type="button"
              className={lanFilterStatus === "offline" ? "primary-button small" : "secondary-button small"}
              onClick={() => setLanFilterStatus("offline")}
              style={lanFilterStatus !== "offline" && offlineDevices.length > 0 ? { borderColor: "#ef4444", color: "#f87171" } : {}}
            >
              🔴 Offline ({offlineDevices.length})
            </button>
            <button
              type="button"
              className={lanFilterStatus === "ip-changed" ? "primary-button small" : "secondary-button small"}
              onClick={() => setLanFilterStatus("ip-changed")}
              style={lanFilterStatus !== "ip-changed" && ipChangedDeviceIds.size > 0 ? { borderColor: "#f59e0b", color: "#fbbf24" } : {}}
            >
              🔄 IP Changed ({ipChangedDeviceIds.size})
            </button>
            <button
              type="button"
              className={lanFilterStatus === "allowed" ? "primary-button small" : "secondary-button small"}
              onClick={() => setLanFilterStatus("allowed")}
            >
              🟢 Allowed ({allowedCount})
            </button>
            <button
              type="button"
              className={lanFilterStatus === "quarantined" ? "primary-button small" : "secondary-button small"}
              onClick={() => setLanFilterStatus("quarantined")}
            >
              🔴 Quarantined ({quarantinedCount})
            </button>
            <button
              type="button"
              className={lanFilterStatus === "registered" ? "primary-button small" : "secondary-button small"}
              onClick={() => setLanFilterStatus("registered")}
            >
              All Registered ({devices.length})
            </button>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "8px", flex: "1", maxWidth: "320px" }}>
            <input
              type="text"
              placeholder="Search by IP, MAC, hostname, vendor..."
              value={lanSearchQuery}
              onChange={(e) => setLanSearchQuery(e.target.value)}
              style={{
                width: "100%",
                padding: "7px 12px",
                background: "#0f172a",
                border: "1px solid #334155",
                borderRadius: "6px",
                color: "#f8fafc",
                fontSize: "13px",
              }}
            />
          </div>
        </div>
      </div>

      {/* DISCOVERED DEVICES TABLE */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <div className="panel-title">
              Connected LAN Devices ({filteredDevices.length})
            </div>
            <div className="panel-subtitle">
              Live machines connected to {detectedSubnet}. Click any action button to manage access, reassign VLANs, or schedule access in real time.
            </div>
          </div>
        </div>

        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>DEVICE / HOSTNAME</th>
                <th>CONNECTION</th>
                <th>CURRENT IP ADDRESS</th>
                <th>MAC ADDRESS</th>
                <th>VLAN SEGMENT</th>
                <th>FIREWALL ACCESS</th>
                <th style={{ textAlign: "right" }}>ACTIONS ("START FROM HERE")</th>
              </tr>
            </thead>
            <tbody>
              {filteredDevices.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: "center", padding: "32px", color: "#94a3b8" }}>
                    No devices match the selected filter. Click <strong>"Scan All LAN Devices"</strong> above to discover live machines on the subnet.
                  </td>
                </tr>
              ) : (
                filteredDevices.map((device) => {
                  const hasIpChange = ipChangedDeviceIds.has(device.id);
                  const isAllowed = device.enforcement_status === "allowed";
                  const schedule = accessSchedules[device.id]?.[0];

                  return (
                    <tr
                      key={device.id}
                      style={
                        highlightedDeviceId === device.id || hasIpChange
                            ? { background: "rgba(59, 130, 246, 0.08)" }
                            : {}
                      }
                    >
                      {/* DEVICE / HOSTNAME */}
                      <td>
                        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                          <span style={{ fontSize: "20px" }}>
                            {getDeviceIcon(device.device_type)}
                          </span>
                          <div>
                            <div style={{ fontWeight: "700", color: "#f8fafc" }}>
                              {device.hostname || `Device #${device.id}`}
                            </div>
                            <div style={{ display: "flex", gap: "6px", marginTop: "3px" }}>
                              {device.vendor && (
                                <span
                                  style={{
                                    fontSize: "10px",
                                    padding: "1px 6px",
                                    borderRadius: "4px",
                                    background: "#334155",
                                    color: "#cbd5e1",
                                    fontWeight: "600",
                                  }}
                                >
                                  {device.vendor}
                                </span>
                              )}
                              <span
                                style={{
                                  fontSize: "10px",
                                  padding: "1px 6px",
                                  borderRadius: "4px",
                                  background:
                                    device.approval_status === "approved"
                                      ? "rgba(16, 185, 129, 0.2)"
                                      : "rgba(245, 158, 11, 0.2)",
                                  color:
                                    device.approval_status === "approved"
                                      ? "#34d399"
                                      : "#fbbf24",
                                  fontWeight: "600",
                                }}
                              >
                                {device.approval_status?.toUpperCase()}
                              </span>
                            </div>
                          </div>
                        </div>
                      </td>

                      {/* CONNECTION */}
                      <td>
                        {device.status === "online" ? (
                          <span
                            className="status-badge allowed"
                            style={{
                              display: "inline-flex",
                              alignItems: "center",
                              gap: "5px",
                              fontSize: "11px",
                              fontWeight: "700",
                              padding: "2px 8px",
                            }}
                          >
                            <span className="status-dot online" /> ONLINE
                          </span>
                        ) : (
                          <span
                            className="status-badge blocked"
                            style={{
                              display: "inline-flex",
                              alignItems: "center",
                              gap: "5px",
                              fontSize: "11px",
                              fontWeight: "700",
                              padding: "2px 8px",
                            }}
                          >
                            <span className="status-dot offline" /> OFFLINE
                          </span>
                        )}
                      </td>

                      {/* CURRENT IP ADDRESS */}
                      <td>
                        <div>
                          <span
                            style={{
                              fontSize: "14px",
                              fontWeight: "700",
                              fontFamily: "monospace",
                              color: "#60a5fa",
                            }}
                          >
                            {device.ip_address || "No IP Assigned"}
                          </span>
                          {hasIpChange && (
                            <div
                              style={{
                                fontSize: "11px",
                                color: "#f59e0b",
                                fontWeight: "700",
                                marginTop: "2px",
                                display: "inline-flex",
                                alignItems: "center",
                                gap: "4px",
                              }}
                            >
                              <span>🔄</span> IP Reassigned (Auto-Synced)
                            </div>
                          )}
                        </div>
                      </td>

                      {/* MAC ADDRESS */}
                      <td>
                        <span
                          style={{
                            fontFamily: "monospace",
                            fontSize: "12px",
                            color: "#94a3b8",
                          }}
                        >
                          {device.mac_address}
                        </span>
                      </td>

                      {/* VLAN SEGMENT */}
                      <td>
                        <select
                          value={device.vlan_id || 90}
                          onChange={(e) =>
                            deviceAction(device.id, "vlan", e.target.value)
                          }
                          disabled={actionLoading === `vlan-${device.id}`}
                          style={{
                            background: "#0f172a",
                            color: device.vlan_id === 90 ? "#f87171" : "#38bdf8",
                            border:
                              device.vlan_id === 90
                                ? "1px solid rgba(239, 68, 68, 0.4)"
                                : "1px solid #334155",
                            borderRadius: "5px",
                            padding: "4px 8px",
                            fontSize: "12px",
                            fontWeight: "600",
                            cursor: "pointer",
                          }}
                        >
                          <option value={20}>VLAN 20 (Workstations)</option>
                          <option value={30}>VLAN 30 (CCTV)</option>
                          <option value={40}>VLAN 40 (Printers)</option>
                          <option value={90}>VLAN 90 (Quarantine)</option>
                        </select>
                      </td>

                      {/* FIREWALL ACCESS */}
                      <td>
                        <div>
                          {isAllowed ? (
                            <span
                              style={{
                                color: "#10b981",
                                fontWeight: "700",
                                display: "inline-flex",
                                alignItems: "center",
                                gap: "6px",
                                fontSize: "12px",
                              }}
                            >
                              <span className="status-dot online" /> Allowed
                            </span>
                          ) : (
                            <span
                              style={{
                                color: "#ef4444",
                                fontWeight: "700",
                                display: "inline-flex",
                                alignItems: "center",
                                gap: "6px",
                                fontSize: "12px",
                              }}
                            >
                              <span className="status-dot offline" /> Quarantined
                            </span>
                          )}

                          <div
                            style={{
                              fontSize: "11px",
                              color: "#64748b",
                              marginTop: "2px",
                            }}
                          >
                            {isAllowed
                              ? "Sophos: Active Traffic"
                              : "Sophos: Dropped by Rule"}
                          </div>
                          {schedule && schedule.is_active && (
                            <div
                              style={{
                                fontSize: "11px",
                                color: "#a855f7",
                                marginTop: "1px",
                                fontWeight: "600",
                              }}
                            >
                              ⏱️ {schedule.start_time} - {schedule.end_time}
                            </div>
                          )}
                        </div>
                      </td>

                      {/* ACTIONS */}
                      <td style={{ textAlign: "right" }}>
                        <div
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: "6px",
                            flexWrap: "wrap",
                            justifyContent: "flex-end",
                          }}
                        >
                          {/* TOGGLE INTERNET */}
                          {isAllowed ? (
                            <button
                              className="danger-button small"
                              type="button"
                              onClick={() =>
                                deviceAction(device.id, "disallow")
                              }
                              disabled={
                                actionLoading === `disallow-${device.id}`
                              }
                              title="Instantly block Internet access on Sophos Firewall"
                            >
                              {actionLoading === `disallow-${device.id}`
                                ? "Blocking..."
                                : "🚫 Disconnect"}
                            </button>
                          ) : (
                            <button
                              className="primary-button small"
                              type="button"
                              onClick={() =>
                                deviceAction(device.id, "allow")
                              }
                              disabled={
                                actionLoading === `allow-${device.id}`
                              }
                              style={{
                                background: "#10b981",
                                borderColor: "#10b981",
                              }}
                              title="Allow Internet access on Sophos Firewall"
                            >
                              {actionLoading === `allow-${device.id}`
                                ? "Allowing..."
                                : "✓ Allow Internet"}
                            </button>
                          )}

                          {/* SET ACCESS SCHEDULE */}
                          <button
                            className="secondary-button small"
                            type="button"
                            onClick={() => openScheduleModal(device)}
                            title="Set access schedule with Hours, Minutes, Seconds dropdowns"
                          >
                            ⏱️ Schedule
                          </button>

                          {/* MOVE TO QUARANTINE VLAN */}
                          {device.vlan_id !== 90 && (
                            <button
                              className="secondary-button small"
                              type="button"
                              onClick={() =>
                                deviceAction(device.id, "vlan", 90)
                              }
                              style={{
                                color: "#f87171",
                                borderColor: "rgba(239, 68, 68, 0.4)",
                              }}
                              title="Move device to Quarantine VLAN 90"
                            >
                              🛡️ Quarantine
                            </button>
                          )}

                          {/* APPROVE IF PENDING */}
                          {device.approval_status === "pending" && (
                            <button
                              className="primary-button small"
                              type="button"
                              onClick={() =>
                                deviceAction(device.id, "approve")
                              }
                              disabled={
                                actionLoading === `approve-${device.id}`
                              }
                            >
                              Approve
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
  );
};

// ------------------------------------------------------------
// ACCESS CONTROL PAGE
// ------------------------------------------------------------

const AccessPage = () => {
  const totalDevices = devices.length;

  const pendingDevices = devices.filter(
    (device) => device.approval_status === "pending"
  ).length;
  const allowed = devices.filter(
    (device) =>
      device.enforcement_status ===
      "allowed"
  );

  const quarantined = devices.filter(
    (device) =>
      device.enforcement_status !==
      "allowed"
  );

  return (
    <div className="page">

      <div className="page-header">

        <div>

          <div className="page-title">
            Access Control
          </div>

          <div className="page-description">
            Control administrator approval and
            Internet access for LAN devices.
          </div>

        </div>

        <button
          className="secondary-button"
          onClick={loadDevices}
        >
          Refresh
        </button>

      </div>

      {!isAdmin && (
        <div style={{ background: "rgba(59, 130, 246, 0.12)", border: "1px solid rgba(59, 130, 246, 0.4)", borderRadius: "8px", padding: "10px 16px", marginBottom: "16px", display: "flex", alignItems: "center", gap: "10px", fontSize: "13px", color: "#93c5fd" }}>
          <span>👁️</span>
          <div><strong>Standard User (Read-Only Access Monitoring):</strong> You have read-only visibility into device access rules and enforcement. Access control changes and schedules require Administrator privileges.</div>
        </div>
      )}


      {/* SUMMARY */}

<div className="report-section">
  <div className="panel-title">
    Device Overview
  </div>
  <div className="panel-subtitle">
    Current LAN device status and access state.
  </div>
</div>      
<div className="report-grid">

        <ReportCard
          title="Allowed"
          value={allowed.length}
          description="Devices currently allowed Internet access."
        />

        <ReportCard
          title="Quarantined"
          value={quarantined.length}
          description="Devices currently blocked from Internet access."
        />

        <ReportCard
          title="Pending"
          value={pendingDevices}
          description="Devices awaiting administrator approval."
        />

        <ReportCard
          title="Total Devices"
          value={totalDevices}
          description="Devices detected by NETOPS."
        />

      </div>


      {/* ACCESS TABLE */}

      <div className="panel">

        <div className="panel-header">

          <div>

            <div className="panel-title">
              Internet Access Control
            </div>

            <div className="panel-subtitle">
              Approval and Internet enforcement
              are controlled separately.
            </div>

          </div>

        </div>


        <div className="table-container">

          <table className="data-table">

            <thead>

              <tr>
                <th>DEVICE</th>
                <th>TYPE</th>
                <th>VLAN</th>
                <th>APPROVAL</th>
                <th>AUTHORIZATION</th>
                <th>ACCESS</th>
                <th>ACTION</th>
              </tr>

            </thead>


            <tbody>

              {devices.length === 0 ? (

                <tr>

                  <td colSpan="8">

                    <div className="empty-state">
                      No devices found.
                    </div>

                  </td>

                </tr>

              ) : (

                devices.map((device) => (

                  <tr key={device.id}>

                    <td>

                      <div className="device-primary">

                        {device.device_type ===
                        "computer"
                          ? "💻"
                          : device.device_type ===
                            "cctv"
                          ? "📹"
                          : device.device_type ===
                            "printer"
                          ? "🖨️"
                          : "⚠️"}

                        {" "}

                        {device.hostname ||
                          "Unknown Device"}

                      </div>

                      <div className="device-secondary">
                        {device.ip_address}
                      </div>

                    </td>


                    <td>

                      <TypeBadge
                        type={
                          device.device_type
                        }
                      />

                    </td>


                    <td>
                      <select
                        value={device.vlan_id || 90}
                        disabled={
                          actionLoading ===
                          `vlan-${device.id}`
                        }
                        onChange={(event) =>
                          deviceAction(
                            device.id,
                            "vlan",
                            event.target.value
                          )
                        }
                        style={{
                          padding: "4px 8px",
                          borderRadius: "6px",
                          border:
                            device.vlan_id === 90 || !device.vlan_id
                              ? "1px solid #ef4444"
                              : "1px solid #3b82f6",
                          background:
                            device.vlan_id === 90 || !device.vlan_id
                              ? "#450a0a"
                              : "#1e293b",
                          color:
                            device.vlan_id === 90 || !device.vlan_id
                              ? "#fca5a5"
                              : "#93c5fd",
                          fontWeight: "600",
                          cursor: "pointer",
                        }}
                        title="Change VLAN: VLAN 90 immediately disconnects internet"
                      >
                        <option value="20">VLAN 20</option>
                        <option value="30">VLAN 30</option>
                        <option value="40">VLAN 40</option>
                        <option value="90">🚨 VLAN 90 (Quarantine)</option>
                      </select>
                    </td>


                    <td>

                      {device.approval_status ===
                      "approved" ? (

                        <span className="status-badge allowed">
                          Approved
                        </span>

                      ) : device.approval_status ===
                        "rejected" ? (

                        <span className="status-badge blocked">
                          Rejected
                        </span>

                      ) : (

                        <span className="status-badge pending">
                          Pending
                        </span>

                      )}

                    </td>


                    <td>

                      {device.enforcement_status ===
                      "allowed" ? (

                        <span className="status-badge allowed">
                          Internet Allowed
                        </span>

                      ) : (

                        <span className="status-badge blocked">
                          ⚠️ Quarantined
                        </span>

                      )}

                    </td>


                    <td>

                      <div
                        style={{
                          display: "flex",
                          gap: "6px",
                          flexWrap: "wrap",
                        }}
                      >

                        {device.approval_status !==
                          "approved" && (

                          <button
                            className="primary-button small"
                            onClick={() =>
                              deviceAction(
                                device.id,
                                "approve"
                              )
                            }
                          >
                            Approve
                          </button>

                        )}


                        {device.approval_status ===
                          "approved" &&
                          device.enforcement_status !==
                            "allowed" && (

                          <button
                            className="primary-button small"
                            onClick={() =>
                              deviceAction(
                                device.id,
                                "allow"
                              )
                            }
                          >
                            Allow Internet
                          </button>

                        )}


                        {device.approval_status ===
                          "approved" &&
                          device.enforcement_status ===
                            "allowed" && (

                          <button
                            className="secondary-button small"
                            onClick={() =>
                              deviceAction(
                                device.id,
                                "disallow"
                              )
                            }
                          >
                            Disconnect
                          </button>

                        )}


                        {device.approval_status !==
                          "rejected" && (

                          <button
                            className="secondary-button small"
                            onClick={() =>
                              deviceAction(
                                device.id,
                                "reject"
                              )
                            }
                          >
                            Reject
                          </button>

                        )}

                      </div>

                    </td>

                  </tr>

                ))

              )}

            </tbody>

          </table>

        </div>

      </div>

    </div>
  );
};
  // ------------------------------------------------------------
  // VLAN PAGE
  // ------------------------------------------------------------
                 

  const VLANPage = () => {
    const vlanDevices =
      vlanFilter === "all"
        ? devices
        : devices.filter(
            (device) =>
              String(
                device.vlan_id
              ) === String(vlanFilter)
          );

    const vlan20 = devices.filter(
      (device) => device.vlan_id === 20
    );

    const vlan30 = devices.filter(
      (device) => device.vlan_id === 30
    );

    const vlan40 = devices.filter(
      (device) => device.vlan_id === 40
    );

    const vlan90 = devices.filter(
      (device) => device.vlan_id === 90
    );

    return (
      <div className="page">
        <div className="page-header">
          <div>
            <div className="page-title">
              VLAN Automation
            </div>

            <div className="page-description">
              Centralized device segmentation
              and simulated switch configuration.
            </div>
          </div>
        </div>

        <div className="vlan-card-grid">
          <VLANCard
            vlan="20"
            name="Computers"
            description="LAN computers and workstations"
            devices={vlan20}
            selected={
              vlanFilter === "20"
            }
            onClick={() =>
              setVlanFilter("20")
            }
          />

          <VLANCard
            vlan="30"
            name="CCTV"
            description="Cameras and surveillance equipment"
            devices={vlan30}
            selected={
              vlanFilter === "30"
            }
            onClick={() =>
              setVlanFilter("30")
            }
          />

          <VLANCard
            vlan="40"
            name="Printers"
            description="Network printing devices"
            devices={vlan40}
            selected={
              vlanFilter === "40"
            }
            onClick={() =>
              setVlanFilter("40")
            }
          />

          <VLANCard
            vlan="90"
            name="Quarantine"
            description="Unknown or restricted devices"
            devices={vlan90}
            selected={
              vlanFilter === "90"
            }
            quarantine
            onClick={() =>
              setVlanFilter("90")
            }
          />
        </div>

        <FilterBar
          label={
            vlanFilter === "all"
              ? "All VLAN Devices"
              : `VLAN ${vlanFilter} Devices`
          }
          count={vlanDevices.length}
          active={vlanFilter !== "all"}
          clear={() =>
            setVlanFilter("all")
          }
        />

        <div className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">
                VLAN Assignment
              </div>

              <div className="panel-subtitle">
                Current device-to-VLAN mapping
              </div>
            </div>

            <div className="settings-status">
              <span className="status-dot online" />
              Policy Active
            </div>
          </div>

          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>DEVICE</th>
                  <th>TYPE</th>
                  <th>VLAN</th>
                  <th>SWITCH</th>
                  <th>PORT</th>
                  <th>AUTOMATION</th>
                </tr>
              </thead>

              <tbody>
                {vlanDevices.length === 0 ? (
                  <tr>
                    <td colSpan="6">
                      <div className="empty-state">
                        No devices found.
                      </div>
                    </td>
                  </tr>
                ) : (
                  vlanDevices.map(
                    (device) => (
                      <tr key={device.id}>
                        <td>
                          <div className="device-primary">
                            {device.hostname ||
                              "Unknown Device"}
                          </div>

                          <div className="device-secondary">
                            {device.ip_address ||
                              "-"}
                          </div>
                        </td>

                        <td>
                          <TypeBadge
                            type={
                              device.device_type
                            }
                          />
                        </td>

                        <td>
                          <select
                            value={device.vlan_id || 90}
                            disabled={
                              actionLoading ===
                              `vlan-${device.id}`
                            }
                            onChange={(event) =>
                              deviceAction(
                                device.id,
                                "vlan",
                                event.target.value
                              )
                            }
                            style={{
                              padding: "4px 8px",
                              borderRadius: "6px",
                              border:
                                device.vlan_id === 90 || !device.vlan_id
                                  ? "1px solid #ef4444"
                                  : "1px solid #3b82f6",
                              background:
                                device.vlan_id === 90 || !device.vlan_id
                                  ? "#450a0a"
                                  : "#1e293b",
                              color:
                                device.vlan_id === 90 || !device.vlan_id
                                  ? "#fca5a5"
                                  : "#93c5fd",
                              fontWeight: "600",
                              cursor: "pointer",
                            }}
                            title="Change VLAN. Selecting VLAN 90 immediately disconnects internet access."
                          >
                            <option value="20">VLAN 20 (Computers)</option>
                            <option value="30">VLAN 30 (CCTV)</option>
                            <option value="40">VLAN 40 (Printers)</option>
                            <option value="90">🚨 VLAN 90 (Quarantine)</option>
                          </select>
                        </td>

                        <td>
                          {device.switch_name ||
                            "Not identified"}
                        </td>

                        <td>
                          {device.switch_port ||
                            "Not identified"}
                        </td>

                        <td>
                          <div style={{ display: "flex", gap: "6px" }}>
                            <button
                              className="primary-button small"
                              disabled={
                                actionLoading ===
                                `automate-vlan-${device.id}`
                              }
                              onClick={() =>
                                deviceAction(
                                  device.id,
                                  "automate-vlan"
                                )
                              }
                            >
                              {actionLoading ===
                              `automate-vlan-${device.id}`
                                ? "Running..."
                                : "Auto VLAN"}
                            </button>
                            {device.vlan_id !== 90 && (
                              <button
                                className="secondary-button small"
                                style={{
                                  backgroundColor: "#7f1d1d",
                                  borderColor: "#ef4444",
                                  color: "#fecaca",
                                  fontWeight: "600",
                                }}
                                disabled={
                                  actionLoading ===
                                  `vlan-${device.id}`
                                }
                                onClick={() =>
                                  deviceAction(
                                    device.id,
                                    "vlan",
                                    90
                                  )
                                }
                                title="Instantly isolate into Quarantine VLAN 90 & disconnect internet"
                              >
                                🚨 Quarantine
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    )
                  )
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">
                VLAN Automation Policy
              </div>

              <div className="panel-subtitle">
                Device classification determines
                the target VLAN
              </div>
            </div>
          </div>

          <PolicyRow
            vlan="20"
            name="Computers"
            description="Approved LAN computers and workstations"
            count={vlan20.length}
          />

          <PolicyRow
            vlan="30"
            name="CCTV"
            description="Cameras and surveillance equipment"
            count={vlan30.length}
          />

          <PolicyRow
            vlan="40"
            name="Printers"
            description="Network printing devices"
            count={vlan40.length}
          />

          <PolicyRow
            vlan="90"
            name="Quarantine"
            description="Unknown, rejected, or restricted devices"
            count={vlan90.length}
            quarantine
          />
        </div>
      </div>
    );
  };

  // ------------------------------------------------------------
  // EVENTS
  // ------------------------------------------------------------

  const EventsPage = () => (
    <div className="page">
      <div className="page-header">
        <div>
          <div className="page-title">
            Network Events
          </div>

          <div className="page-description">
            Audit trail of NETOPS activity.
          </div>
        </div>

        <button
          className="secondary-button"
          onClick={loadEvents}
        >
          Refresh Events
        </button>
      </div>


<div className="panel">
  <div className="page-description">
    Filter events and choose how many to display per page.
  </div>

  <div className="form-grid">
    <label>
      Event type
      <select
        value={eventTypeFilter}
        onChange={(event) => {
          setEventTypeFilter(event.target.value);
          setEventOffset(0);
        }}
      >
        <option value="all">All event types</option>
        <option value="endpoint_stale">Endpoint stale</option>
        <option value="endpoint_recovered">Endpoint recovered</option>
        <option value="device_detected">Device detected</option>
        <option value="unrecognized_endpoint">Unrecognized endpoint</option>
        <option value="access_enforcement">Access enforcement</option>
        <option value="vlan_automation">VLAN automation</option>
      </select>
    </label>

    <label>
      Events per page
      <select
        value={eventLimit}
        onChange={(event) => {
          setEventLimit(Number(event.target.value));
          setEventOffset(0);
        }}
      >
        <option value={10}>10</option>
        <option value={25}>25</option>
        <option value={50}>50</option>
        <option value={100}>100</option>
        <option value={200}>200</option>
      </select>
    </label>
  </div>

  <div className="button-row">
    <button
      className="secondary-button"
      disabled={eventOffset === 0}
      onClick={() => setEventOffset(Math.max(0, eventOffset - eventLimit))}
    >
      Previous
    </button>

    <button
      className="secondary-button"
      onClick={() => setEventOffset(eventOffset + eventLimit)}
      disabled={events.length < eventLimit}
    >
      Next
    </button>
  </div>
</div>


      <div className="panel">
        {events.length === 0 ? (
          <div className="empty-state">
            No events found.
          </div>
        ) : (
          <div className="event-list large">
            {events.map(
              (event, index) => (
                <EventRow
                  key={
                    event.id ||
                    `${event.event_type}-${index}`
                  }
                  event={event}
                />
              )
            )}
          </div>
        )}
      </div>
    </div>
  );

  // ------------------------------------------------------------
  // REPORTS
  // ------------------------------------------------------------

  const ReportsPage = () => {
  const [reportType, setReportType] = useState("network_activity");
  const [reportPeriod, setReportPeriod] = useState("daily");
  const [reportDate, setReportDate] = useState(
    new Date().toISOString().slice(0, 10)
  );
  const [reportStartDate, setReportStartDate] = useState(
  new Date().toISOString().slice(0, 10)
  );
  const [reportEndDate, setReportEndDate] = useState(
  new Date().toISOString().slice(0, 10)
  );
  const [reportStartTime, setReportStartTime] = useState("00:00");
  const [reportEndTime, setReportEndTime] = useState("23:59");
  const [reportData, setReportData] = useState(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [reportError, setReportError] = useState("");

  const computerDevices = devices.filter(
    (device) => device.device_type === "computer"
  ).length;

  const cctvDevices = devices.filter(
    (device) => device.device_type === "cctv"
  ).length;

  const printerDevices = devices.filter(
    (device) => device.device_type === "printer"
  ).length;

  const unknownDevices = devices.filter(
    (device) =>
      !["computer", "cctv", "printer"].includes(
        device.device_type
      )
  ).length;

 const rejectedDevices = devices.filter(
    (device) => device.approval_status === "rejected"
  ).length;
const vlan20Devices = devices.filter(
    (device) => Number(device.vlan_id) === 20
  ).length;

  const vlan30Devices = devices.filter(
    (device) => Number(device.vlan_id) === 30
  ).length;

  const vlan40Devices = devices.filter(
    (device) => Number(device.vlan_id) === 40
  ).length;

  const vlan90Devices = devices.filter(
    (device) => Number(device.vlan_id) === 90
  ).length;
const enforcedAllowed = devices.filter(
    (device) =>
      device.enforcement_status === "allowed" ||
      device.access_decision === "allow"
  ).length;

  const enforcedQuarantined = devices.filter(
    (device) =>
      device.enforcement_status === "quarantined" ||
      device.access_decision === "quarantine"
  ).length;

 const generateReport = async () => {
    setReportLoading(true);
    setReportError("");
    setReportData(null);
    const today = new Date().toISOString().slice(0, 10);
if (reportPeriod === "custom") {
      if (
        reportStartDate > today ||
        reportEndDate > today ||
        reportEndDate < reportStartDate
      ) {
        setReportError(
          "Date input invalid, please select a valid date."
        );
        setReportLoading(false);
        return;
      }
    } else {
      if (reportDate > today) {
        setReportError(
          "Date input invalid, please select a valid date."
        );
        setReportLoading(false);
        return;
      }
    }


    try {
      const params = new URLSearchParams({
    report_type: reportType,
    period: reportPeriod,
  });

if (reportPeriod === "custom") {
  params.append(
    "start_datetime",
    `${reportStartDate}T${reportStartTime}`
  );
  params.append(
    "end_datetime",
    `${reportEndDate}T${reportEndTime}`
  );
} else {
  params.append("date", reportDate);
}
      const response = await fetch(
        `${API_URL}/reports/generate?${params.toString()}`
      );

      if (!response.ok) {
        throw new Error("Failed to generate report.");
      }

      const data = await response.json();
      setReportData(data);
    } catch (error) {
      setReportError(error.message || "Failed to generate report.");
    } finally {
      setReportLoading(false);
    }
  };

return (
  <div className="page">
      <div className="page-header">
        <div>
          <div className="page-title">
            Reports
          </div>

          <div className="page-description">
            Network operations reporting and
            analytics.
          </div>
        </div>
      </div>

      <div className="report-grid">
        <ReportCard
          title="Device Inventory"
          value={totalDevices}
          description="Current LAN device inventory."
 onClick={() => {
    setDeviceFilter("all");
    setActivePage("devices");
  }}
        />

        <ReportCard
          title="Online Devices"
          value={onlineDevices}
          description="Devices currently detected online."
         
           onClick={() => {
    setDeviceFilter("online");
    setActivePage("devices");
  }}
        />

        <ReportCard
          title="Pending Approvals"
          value={pendingDevices}
          description="Devices awaiting administrator action."
 onClick={() => {
    setDeviceFilter("pending");
    setActivePage("devices");
  }}
        />

<ReportCard
  title="Rejected Devices"
  value={rejectedDevices}
  description="Devices rejected by the administrator."
  onClick={() => {
    setDeviceFilter("rejected");
    setActivePage("devices");
  }}
/>        
<ReportCard
          title="Quarantine"
          value={quarantinedDevices}
          description="Devices blocked from network access."
  onClick={() => {
    setDeviceFilter("quarantined");
    setActivePage("devices");
  }}
        />
       
<div className="report-section">
  <div className="panel-title">
    Device Classification
  </div>
  <div className="panel-subtitle">
    Devices grouped by detected type.
  </div>
</div>         
<ReportCard
          title="Computers"
          value={computerDevices}
          description="Detected computer devices."
 onClick={() => {
    setDeviceFilter("computer");
    setActivePage("devices");
  }}
        />

        <ReportCard
          title="CCTV"
          value={cctvDevices}
          description="Detected CCTV devices."
  onClick={() => {
    setDeviceFilter("cctv");
    setActivePage("devices");
  }}
        />

        <ReportCard
          title="Printers"
          value={printerDevices}
          description="Detected printer devices."
 onClick={() => {
    setDeviceFilter("printer");
    setActivePage("devices");
  }}
        />

        <ReportCard
          title="Unknown"
          value={unknownDevices}
          description="Devices not yet classified."
 onClick={() => {
    setDeviceFilter("unknown");
    setActivePage("devices");
  }}
        />
<div className="report-section">
  <div className="panel-title">
    VLAN Distribution
  </div>
  <div className="panel-subtitle">
    Devices assigned to each network segment.
  </div>
</div>

<ReportCard
          title="VLAN 20"
          value={vlan20Devices}
          description="Devices assigned to VLAN 20."
 onClick={() => {
    setDeviceFilter("vlan20");
    setActivePage("devices");
  }}
        />

        <ReportCard
          title="VLAN 30"
          value={vlan30Devices}
          description="Devices assigned to VLAN 30."
 onClick={() => {
    setDeviceFilter("vlan30");
    setActivePage("devices");
  }}
        />

        <ReportCard
          title="VLAN 40"
          value={vlan40Devices}
          description="Devices assigned to VLAN 40."
 onClick={() => {
    setDeviceFilter("vlan40");
    setActivePage("devices");
  }}
        />

        <ReportCard
          title="VLAN 90"
          value={vlan90Devices}
          description="Devices assigned to VLAN 90."
 onClick={() => {
    setDeviceFilter("vlan90");
    setActivePage("devices");
  }}
        />
      </div>

      <div className="panel">
        <div className="panel-header">
          <div>
            <div className="panel-title">
              Enforcement Summary
            </div>

            <div className="panel-subtitle">
              Current simulated enforcement state
            </div>
          </div>
        </div>

        <div className="classification-list">
          <ClassificationRow
            label="Allowed"
            icon="OK"
            type="computer"
            value={enforcedAllowed}
          />

          <ClassificationRow
            label="Quarantined"
            icon="Q"
            type="unknown"
            value={enforcedQuarantined}
          />
          </div>
        </div>

      <div className="panel">
        <div className="panel-header">
          <div>
            <div className="panel-title">
              Historical Reports
            </div>
            <div className="panel-subtitle">
              Generate reports from recorded NETOPS events.
            </div>
          </div>
        </div>

        <div className="settings-grid">
          <div className="settings-row">
            <label>Report Type</label>
            <select
              value={reportType}
              onChange={(event) => setReportType(event.target.value)}
            >
              <option value="user_activity">
                User Access & Audit Report
              </option>
              <option value="network_activity">
                Network Activity
              </option>
              <option value="device_inventory">
                Device Inventory
              </option>
              <option value="device_discovery">
                Device Discovery
              </option>
              <option value="network_events">
                Network Events
              </option>
              <option value="access_enforcement">
                Access Enforcement
              </option>
              <option value="approvals">
                Approvals
              </option>
              <option value="quarantine">
                Quarantine
              </option>
              <option value="device_classification">
                Device Classification
              </option>
              <option value="vlan_automation">
                VLAN Automation
              </option>
              <option value="system_activity">
                System Activity
              </option>
            </select>
          </div>

          <div className="settings-row">
            <label>Period</label>
            <select
              value={reportPeriod}
              onChange={(event) => setReportPeriod(event.target.value)}
            >
              <option value="hourly">Hourly</option>
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
              <option value="monthly">Monthly</option>
              <option value="annually">Annually</option>
              <option value="custom">Custom Range</option>
            </select>
          </div>

{reportPeriod === "custom" ? (
  <>
    <div className="settings-row">
      <label>Starting</label>
      <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
        <input
          type="date"
          value={reportStartDate}
          onChange={(event) => setReportStartDate(event.target.value)}
        />
        <input
          type="time"
          value={reportStartTime}
          onChange={(event) => setReportStartTime(event.target.value)}
        />
      </div>
    </div>

    <div className="settings-row">
      <label>Ending</label>
      <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
        <input
          type="date"
          value={reportEndDate}
          onChange={(event) => setReportEndDate(event.target.value)}
        />
        <input
          type="time"
          value={reportEndTime}
          onChange={(event) => setReportEndTime(event.target.value)}
        />
      </div>
    </div>
  </>
) : (
  <div className="settings-row">
    <label>Date</label>
    <input
      type="date"
      value={reportDate}
      onChange={(event) => setReportDate(event.target.value)}
    />
  </div>
)}
        </div>

        <div style={{ marginTop: "16px" }}>
          <button
            className="primary-button"
            onClick={generateReport}
            disabled={reportLoading}
          >
            {reportLoading ? "Generating..." : "Generate Report"}
          </button>
        </div>

        {reportError && (
          <div className="panel" style={{ marginTop: "16px" }}>
            <div className="panel-title">
              Report Error
            </div>
            <div className="panel-subtitle">
              {reportError}
            </div>
          </div>
        )}

        {reportData && (
          <div className="panel" style={{ marginTop: "16px" }}>
            <div className="panel-title">
              Report Results
            </div>
            <div className="panel-subtitle">
              {reportData.report_type} · {reportData.period}
            </div>

             <div
              style={{
                display: "flex",
                gap: "10px",
                marginTop: "16px",
                flexWrap: "wrap",
              }}
            >
              <button
                type="button"
                className="primary-button"
                onClick={() => {
                  const today = new Date().toISOString().slice(0, 10);

                  if (reportPeriod === "custom") {
                    if (
                      reportStartDate > today ||
                      reportEndDate > today ||
                      reportEndDate < reportStartDate
                    ) {
                      setReportError(
                        "Date input invalid, please select a valid date."
                      );
                      return;
                    }
                  } else {
                    if (reportDate > today) {
                      setReportError(
                        "Date input invalid, please select a valid date."
                      );
                      return;
                    }
                  }
                  const params = new URLSearchParams({
                    report_type: reportType,
                    period: reportPeriod,
                  });

                  if (reportPeriod === "custom") {
  params.append(
    "start_datetime",
    `${reportStartDate}T${reportStartTime}`
  );
  params.append(
    "end_datetime",
    `${reportEndDate}T${reportEndTime}`
  );
} else if (reportDate) {
  params.append("date", reportDate);
}

                  window.open(
                    `${API_URL}/reports/export/excel?${params.toString()}`,
                    "_blank"
                  );
                }}
              >
                Download Excel
              </button>

              <button
                type="button"
                className="secondary-button"
                onClick={() => {
                  const today = new Date().toISOString().slice(0, 10);

                  if (reportPeriod === "custom") {
                    if (
                      reportStartDate > today ||
                      reportEndDate > today ||
                      reportEndDate < reportStartDate
                    ) {
                      setReportError(
                        "Date input invalid, please select a valid date."
                      );
                      return;
                    }
                  } else {
                    if (reportDate > today) {
                      setReportError(
                        "Date input invalid, please select a valid date."
                      );
                      return;
                    }
                  }
                  const params = new URLSearchParams({
                    report_type: reportType,
                    period: reportPeriod,
                  });

                  if (reportPeriod === "custom") {
                   params.append(
    "start_datetime",
    `${reportStartDate}T${reportStartTime}`
  );
  params.append(
    "end_datetime",
    `${reportEndDate}T${reportEndTime}`
  );
                  } else if (reportDate) {
                    params.append("date", reportDate);
                  }
                  window.open(
                    `${API_URL}/reports/export/pdf?${params.toString()}`,
                    "_blank"
                  );
                }}
              >
                Download PDF
              </button>
            </div>
            {reportData.report_type === "user_activity" ? (
              <div style={{ marginTop: "20px" }}>
                {/* 6 Executive Summary Cards */}
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                    gap: "14px",
                    marginBottom: "24px",
                  }}
                >
                  <div
                    style={{
                      background: "#0d1526",
                      border: "1px solid #1e293b",
                      borderRadius: "10px",
                      padding: "16px",
                    }}
                  >
                    <div style={{ fontSize: "12px", color: "#94a3b8", textTransform: "uppercase", fontWeight: 600 }}>
                      Total Registered Users
                    </div>
                    <div style={{ fontSize: "24px", fontWeight: 800, color: "#60a5fa", marginTop: "6px" }}>
                      {reportData.summary?.total_users ?? 0}
                    </div>
                  </div>

                  <div
                    style={{
                      background: "#0d1526",
                      border: "1px solid #1e293b",
                      borderRadius: "10px",
                      padding: "16px",
                    }}
                  >
                    <div style={{ fontSize: "12px", color: "#94a3b8", textTransform: "uppercase", fontWeight: 600 }}>
                      Users Created in Period
                    </div>
                    <div style={{ fontSize: "24px", fontWeight: 800, color: "#34d399", marginTop: "6px" }}>
                      {reportData.summary?.users_created_in_period ?? 0}
                    </div>
                  </div>

                  <div
                    style={{
                      background: "#0d1526",
                      border: "1px solid #1e293b",
                      borderRadius: "10px",
                      padding: "16px",
                    }}
                  >
                    <div style={{ fontSize: "12px", color: "#94a3b8", textTransform: "uppercase", fontWeight: 600 }}>
                      Total User Logins
                    </div>
                    <div style={{ fontSize: "24px", fontWeight: 800, color: "#a78bfa", marginTop: "6px" }}>
                      {reportData.summary?.total_sessions ?? 0}
                    </div>
                  </div>

                  <div
                    style={{
                      background: "#0d1526",
                      border: "1px solid #1e293b",
                      borderRadius: "10px",
                      padding: "16px",
                    }}
                  >
                    <div style={{ fontSize: "12px", color: "#94a3b8", textTransform: "uppercase", fontWeight: 600 }}>
                      Active Sessions Now
                    </div>
                    <div style={{ fontSize: "24px", fontWeight: 800, color: "#fbbf24", marginTop: "6px" }}>
                      {reportData.summary?.active_sessions ?? 0}
                    </div>
                  </div>

                  <div
                    style={{
                      background: "#0d1526",
                      border: "1px solid #1e293b",
                      borderRadius: "10px",
                      padding: "16px",
                    }}
                  >
                    <div style={{ fontSize: "12px", color: "#94a3b8", textTransform: "uppercase", fontWeight: 600 }}>
                      Total Access Duration
                    </div>
                    <div style={{ fontSize: "20px", fontWeight: 800, color: "#38bdf8", marginTop: "6px" }}>
                      {reportData.summary?.total_duration_formatted || "0s"}
                    </div>
                  </div>

                  <div
                    style={{
                      background: "#0d1526",
                      border: "1px solid #1e293b",
                      borderRadius: "10px",
                      padding: "16px",
                    }}
                  >
                    <div style={{ fontSize: "12px", color: "#94a3b8", textTransform: "uppercase", fontWeight: 600 }}>
                      Average Session Duration
                    </div>
                    <div style={{ fontSize: "20px", fontWeight: 800, color: "#cbd5e1", marginTop: "6px" }}>
                      {reportData.summary?.average_duration_formatted || "0s"}
                    </div>
                  </div>
                </div>

                {/* Section 1: Users Created in Period */}
                <div style={{ marginBottom: "28px" }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "12px" }}>
                    <div>
                      <div className="panel-title" style={{ fontSize: "16px", display: "flex", alignItems: "center", gap: "8px" }}>
                        <span>👤</span> Users Created in Period
                      </div>
                      <div className="panel-subtitle">
                        Accounts provisioned between {reportData.start.replace("T", " ").slice(0, 19)} and {reportData.end.replace("T", " ").slice(0, 19)}
                      </div>
                    </div>
                    <span style={{ fontSize: "12px", color: "#94a3b8" }}>
                      {reportData.users_created?.length || 0} user{reportData.users_created?.length === 1 ? "" : "s"}
                    </span>
                  </div>

                  {reportData.users_created && reportData.users_created.length > 0 ? (
                    <div className="table-container">
                      <table className="data-table">
                        <thead>
                          <tr>
                            <th>USER</th>
                            <th>EMAIL</th>
                            <th>PHONE</th>
                            <th>ROLE</th>
                            <th>CREATED AT</th>
                            <th>VERIFIED</th>
                            <th>STATUS</th>
                          </tr>
                        </thead>
                        <tbody>
                          {reportData.users_created.map((u) => (
                            <tr key={u.id}>
                              <td>
                                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                                  <div
                                    style={{
                                      width: "28px",
                                      height: "28px",
                                      borderRadius: "50%",
                                      background: u.role === "super_admin" ? "#f59e0b" : u.role === "admin" ? "#2563eb" : "#475569",
                                      color: "#fff",
                                      fontSize: "12px",
                                      fontWeight: 700,
                                      display: "flex",
                                      alignItems: "center",
                                      justifyContent: "center",
                                    }}
                                  >
                                    {(u.username || "U").charAt(0).toUpperCase()}
                                  </div>
                                  <strong>{u.username}</strong>
                                </div>
                              </td>
                              <td>{u.email}</td>
                              <td>{u.phone_number || <span style={{ color: "#64748b" }}>N/A</span>}</td>
                              <td>
                                <span
                                  style={{
                                    display: "inline-block",
                                    padding: "3px 8px",
                                    borderRadius: "6px",
                                    fontSize: "11px",
                                    fontWeight: 700,
                                    textTransform: "uppercase",
                                    background:
                                      u.role === "super_admin"
                                        ? "rgba(245, 158, 11, 0.15)"
                                        : u.role === "admin"
                                        ? "rgba(37, 99, 235, 0.15)"
                                        : "rgba(148, 163, 184, 0.15)",
                                    color:
                                      u.role === "super_admin"
                                        ? "#fbbf24"
                                        : u.role === "admin"
                                        ? "#60a5fa"
                                        : "#cbd5e1",
                                    border: `1px solid ${
                                      u.role === "super_admin"
                                        ? "rgba(245, 158, 11, 0.4)"
                                        : u.role === "admin"
                                        ? "rgba(37, 99, 235, 0.4)"
                                        : "rgba(148, 163, 184, 0.3)"
                                    }`,
                                  }}
                                >
                                  {u.role === "super_admin" ? "SUPER ADMIN" : u.role.toUpperCase()}
                                </span>
                              </td>
                              <td>{u.created_at ? u.created_at.replace("T", " ").slice(0, 19) : "—"}</td>
                              <td>
                                <span
                                  style={{
                                    color: u.is_verified ? "#34d399" : "#f59e0b",
                                    fontWeight: 600,
                                    fontSize: "12px",
                                  }}
                                >
                                  {u.is_verified ? "✓ Verified" : "⏳ Pending"}
                                </span>
                              </td>
                              <td>
                                <span
                                  style={{
                                    color: u.is_active ? "#34d399" : "#f87171",
                                    fontWeight: 600,
                                    fontSize: "12px",
                                  }}
                                >
                                  {u.is_active ? "Active" : "Inactive"}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div
                      style={{
                        padding: "20px",
                        textAlign: "center",
                        background: "#0d1526",
                        border: "1px dashed #1e293b",
                        borderRadius: "10px",
                        color: "#64748b",
                        fontSize: "13px",
                      }}
                    >
                      No new users were created during this selected period.
                    </div>
                  )}
                </div>

                {/* Section 2: When Each User Accessed the System & For How Long */}
                <div>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "12px" }}>
                    <div>
                      <div className="panel-title" style={{ fontSize: "16px", display: "flex", alignItems: "center", gap: "8px" }}>
                        <span>⏱️</span> User Access & Session Duration History
                      </div>
                      <div className="panel-subtitle">
                        When each user accessed the system, IP address, and for how long each session lasted
                      </div>
                    </div>
                    <span style={{ fontSize: "12px", color: "#94a3b8" }}>
                      {reportData.sessions?.length || 0} session{reportData.sessions?.length === 1 ? "" : "s"}
                    </span>
                  </div>

                  {reportData.sessions && reportData.sessions.length > 0 ? (
                    <div className="table-container">
                      <table className="data-table">
                        <thead>
                          <tr>
                            <th>USER</th>
                            <th>ROLE</th>
                            <th>LOGIN TIME</th>
                            <th>LAST ACTIVITY</th>
                            <th>LOGOUT TIME</th>
                            <th>DURATION</th>
                            <th>IP ADDRESS</th>
                            <th>STATUS</th>
                          </tr>
                        </thead>
                        <tbody>
                          {reportData.sessions.map((s) => (
                            <tr key={s.id}>
                              <td>
                                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                                  <div
                                    style={{
                                      width: "28px",
                                      height: "28px",
                                      borderRadius: "50%",
                                      background: s.role === "super_admin" ? "#f59e0b" : s.role === "admin" ? "#2563eb" : "#475569",
                                      color: "#fff",
                                      fontSize: "12px",
                                      fontWeight: 700,
                                      display: "flex",
                                      alignItems: "center",
                                      justifyContent: "center",
                                    }}
                                  >
                                    {(s.username || "U").charAt(0).toUpperCase()}
                                  </div>
                                  <strong>{s.username}</strong>
                                </div>
                              </td>
                              <td>
                                <span
                                  style={{
                                    display: "inline-block",
                                    padding: "3px 8px",
                                    borderRadius: "6px",
                                    fontSize: "11px",
                                    fontWeight: 700,
                                    textTransform: "uppercase",
                                    background:
                                      s.role === "super_admin"
                                        ? "rgba(245, 158, 11, 0.15)"
                                        : s.role === "admin"
                                        ? "rgba(37, 99, 235, 0.15)"
                                        : "rgba(148, 163, 184, 0.15)",
                                    color:
                                      s.role === "super_admin"
                                        ? "#fbbf24"
                                        : s.role === "admin"
                                        ? "#60a5fa"
                                        : "#cbd5e1",
                                    border: `1px solid ${
                                      s.role === "super_admin"
                                        ? "rgba(245, 158, 11, 0.4)"
                                        : s.role === "admin"
                                        ? "rgba(37, 99, 235, 0.4)"
                                        : "rgba(148, 163, 184, 0.3)"
                                    }`,
                                  }}
                                >
                                  {s.role === "super_admin" ? "SUPER ADMIN" : s.role.toUpperCase()}
                                </span>
                              </td>
                              <td>{s.login_at ? s.login_at.replace("T", " ").slice(0, 19) : "—"}</td>
                              <td>{s.last_activity_at ? s.last_activity_at.replace("T", " ").slice(0, 19) : "—"}</td>
                              <td>
                                {s.logout_at ? (
                                  s.logout_at.replace("T", " ").slice(0, 19)
                                ) : s.is_active ? (
                                  <span style={{ color: "#34d399", fontWeight: 600 }}>Active Now</span>
                                ) : (
                                  <span style={{ color: "#64748b" }}>Ended</span>
                                )}
                              </td>
                              <td>
                                <strong style={{ color: "#38bdf8", fontFamily: "monospace", fontSize: "13px" }}>
                                  {s.duration_formatted}
                                </strong>
                              </td>
                              <td>
                                <code style={{ fontSize: "12px", color: "#cbd5e1" }}>{s.ip_address || "127.0.0.1"}</code>
                              </td>
                              <td>
                                {s.is_active ? (
                                  <span
                                    style={{
                                      display: "inline-flex",
                                      alignItems: "center",
                                      gap: "5px",
                                      padding: "3px 8px",
                                      borderRadius: "6px",
                                      fontSize: "11px",
                                      fontWeight: 700,
                                      background: "rgba(16, 185, 129, 0.15)",
                                      color: "#34d399",
                                      border: "1px solid rgba(16, 185, 129, 0.3)",
                                    }}
                                  >
                                    <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: "#34d399" }}></span>
                                    ONLINE
                                  </span>
                                ) : (
                                  <span
                                    style={{
                                      display: "inline-flex",
                                      alignItems: "center",
                                      gap: "5px",
                                      padding: "3px 8px",
                                      borderRadius: "6px",
                                      fontSize: "11px",
                                      fontWeight: 600,
                                      background: "rgba(148, 163, 184, 0.1)",
                                      color: "#94a3b8",
                                      border: "1px solid rgba(148, 163, 184, 0.2)",
                                    }}
                                  >
                                    CLOSED
                                  </span>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div
                      style={{
                        padding: "20px",
                        textAlign: "center",
                        background: "#0d1526",
                        border: "1px dashed #1e293b",
                        borderRadius: "10px",
                        color: "#64748b",
                        fontSize: "13px",
                      }}
                    >
                      No user access sessions were recorded during this selected period.
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <>
                <div className="classification-list">
                  <div className="settings-row">
                    <span>Start</span>
                    <code>{reportData.start}</code>
                  </div>

                  <div className="settings-row">
                    <span>End</span>
                    <code>{reportData.end}</code>
                  </div>

                  <div className="settings-row">
                    <span>Total Events</span>
                    <strong>{reportData.summary?.total_events ?? 0}</strong>
                  </div>
                </div>

                {reportData.event_types &&
                  Object.keys(reportData.event_types).length > 0 && (
                    <div style={{ marginTop: "20px" }}>
                      <div className="panel-title">
                        Event Breakdown
                      </div>

                      <div className="classification-list">
                      {Object.entries(reportData.summary?.event_types || {}).map( 
                          ([eventType, count]) => (
                            <div
                              className="settings-row"
                              key={eventType}
                            >
                              <span>{eventType}</span>
                              <strong>{count}</strong>
                            </div>
                          )
                        )}
                      </div>
                    </div>
                  )}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

  // ------------------------------------------------------------
  // SETTINGS
  // ------------------------------------------------------------

  const SettingsPage = () => {
    const [sophosStatus, setSophosStatus] = useState(null);
    const [sophosLoading, setSophosLoading] = useState(false);

    const checkSophos = () => {
      setSophosLoading(true);
      fetch(`${API_URL}/sophos/live-status`)
        .then((r) => r.json())
        .then((data) => setSophosStatus(data))
        .catch((err) => setSophosStatus({ connected: false, error: err.message }))
        .finally(() => setSophosLoading(false));
    };

    useEffect(() => {
      checkSophos();
    }, []);

    return (
      <div className="page">
        <div className="page-header">
          <div>
            <div className="page-title">
              Settings
            </div>

            <div className="page-description">
              NETOPS platform configuration &amp; hardware integrations.
            </div>
          </div>
        </div>

        <div className="settings-grid">
          <div className="panel">
            <div className="panel-header">
              <div>
                <div className="panel-title">
                  Backend API
                </div>

                <div className="panel-subtitle">
                  NETOPS FastAPI service
                </div>
              </div>
            </div>

            <div className="settings-row">
              <span>API URL</span>
              <code>{API_URL}</code>
            </div>

            <div className="settings-row">
              <span>WebSocket</span>
              <code>{WS_URL}</code>
            </div>
          </div>

          <div className="panel">
            <div className="panel-header">
              <div>
                <div className="panel-title">
                  Connection
                </div>

                <div className="panel-subtitle">
                  Current frontend status
                </div>
              </div>
            </div>

            <div className="settings-row">
              <span>API</span>

              <span className="settings-status">
                <span className="status-dot online" />
                Connected
              </span>
            </div>

            <div className="settings-row">
              <span>WebSocket</span>

              <span className="settings-status">
                <span
                  className={
                    wsConnected
                      ? "status-dot online"
                      : "status-dot offline"
                  }
                />

                {wsConnected
                  ? "Connected"
                  : "Disconnected"}
              </span>
            </div>

            <div className="settings-row">
              <span>Refresh interval</span>
              <span>10 seconds</span>
            </div>
          </div>

          <div className="panel" style={{ gridColumn: "span 2" }}>
            <div className="panel-header">
              <div>
                <div className="panel-title">Sophos Firewall Integration</div>
                <div className="panel-subtitle">Physical network isolation &amp; quarantine enforcement</div>
              </div>
              <button
                type="button"
                className="secondary-button small"
                onClick={checkSophos}
                disabled={sophosLoading}
              >
                {sophosLoading ? "Checking..." : "Refresh Status"}
              </button>
            </div>

            <div className="settings-row">
              <span>Firewall Appliance</span>
              <code>192.168.0.10:4444 {sophosStatus?.api_version ? `(SFOS ${sophosStatus.api_version})` : ""}</code>
            </div>

            <div className="settings-row">
              <span>Enforcement Status</span>
              <span className="settings-status">
                <span className={`status-dot ${sophosStatus?.connected ? "online" : "offline"}`} />
                {sophosStatus?.connected ? "Active & Enforcing (Real Firewall)" : "Connecting / Error"}
              </span>
            </div>

            <div className="settings-row">
              <span>Quarantine Firewall Rule</span>
              <span style={{ color: sophosStatus?.quarantine_rule_active ? "#22c55e" : "#ef4444", fontWeight: "600" }}>
                {sophosStatus?.quarantine_rule_active ? "NETOPS_Quarantine_Block (Top Drop Rule Live)" : "Rule Not Found"}
              </span>
            </div>

            <div className="settings-row">
              <span>Active Quarantined Hosts</span>
              <span style={{ fontWeight: "600", color: "#f59e0b" }}>
                {sophosStatus?.quarantined_hosts_count !== undefined ? `${sophosStatus.quarantined_hosts_count} device(s) isolated` : "Querying..."}
              </span>
            </div>

            <div className="settings-row">
              <span>Protected Infrastructure IPs</span>
              <code style={{ fontSize: "11px" }}>192.168.0.1, 192.168.0.10, 192.168.0.13, 192.168.0.101</code>
            </div>
          </div>
        </div>
      </div>
    );
  };
// ------------------------------------------------------------
// DASHBOARD PAGE
// ------------------------------------------------------------

const Dashboard = () => {

  const [dashboardEndpointUpdates, setDashboardEndpointUpdates] =
    useState([]);
  const [dashboardUpdatesLoading, setDashboardUpdatesLoading] =
    useState(true);
  const [dashboardUpdatesError, setDashboardUpdatesError] =
    useState("");
  useEffect(() => {
    const loadDashboardEndpointUpdates = async () => {
      try {
        const response = await fetch(
          `${API_URL}/endpoint-updates/`
        );

        if (!response.ok) {
          throw new Error("Failed to load endpoint updates");
        }

        const data = await response.json();

        setDashboardEndpointUpdates(
          Array.isArray(data) ? data : []
        );
      } catch (error) {
        setDashboardUpdatesError(error.message);
      } finally {
        setDashboardUpdatesLoading(false);
      }
    };

    loadDashboardEndpointUpdates();

    const refreshInterval = setInterval(() => {
      loadDashboardEndpointUpdates();
    }, 60000);

    return () => {
      clearInterval(refreshInterval);
    };
  }, []);  

  const parseEndpointDate = (d) => {
    if (!d) return null;
    return new Date(d.endsWith("Z") || d.includes("+") ? d : d + "Z");
  };

  const dashboardUpdatesNeeded = dashboardEndpointUpdates.filter(
    (endpoint) => endpoint.update_status === "updates_available"
  ).length;

  const dashboardUpToDate = dashboardEndpointUpdates.filter(
    (endpoint) => endpoint.update_status === "up_to_date"
  ).length;

  const dashboardPendingUpdates = dashboardEndpointUpdates.reduce(
    (total, endpoint) => total + (endpoint.pending_updates || 0),
    0
  );
  const totalDevices = devices.length;

  const onlineDevices = devices.filter(
    (device) => device.status === "online"
  ).length;

  const pendingDevices = devices.filter(
    (device) => device.approval_status === "pending"
  ).length;

  const approvedDevices = devices.filter(
    (device) => device.approval_status === "approved"
  ).length;

  const quarantinedDevices = devices.filter(
    (device) =>
      device.enforcement_status === "quarantined" ||
      device.access_decision === "quarantine"
  ).length;

  const computerDevices = devices.filter(
    (device) => device.device_type === "computer"
  ).length;

  const cctvDevices = devices.filter(
    (device) => device.device_type === "cctv"
  ).length;

  const printerDevices = devices.filter(
    (device) => device.device_type === "printer"
  ).length;

  const unknownDevices = devices.filter(
    (device) =>
      !device.device_type ||
      device.device_type === "unknown"
  ).length;

  return (
    <div className="page">

      <div className="page-header">
        <div>
          <div className="page-title">
            Network Operations Dashboard
          </div>

          <div className="page-description">
            Real-time overview of connected devices,
            access control, VLAN assignment and
            network enforcement.
          </div>
        </div>
      </div>

      <div className="access-summary">

        <AccessSummary
          title="Total Devices"
          value={totalDevices}
          text="Devices detected on the LAN"
          onClick={() => {
  setDeviceFilter("all");
  setActivePage("devices");
}}
        />

        <AccessSummary
          title="Online"
          value={onlineDevices}
          text="Currently connected"
          onClick={() => {
  setDeviceFilter("online");
  setActivePage("devices");
}}
        />

        <AccessSummary
          title="Pending"
          value={pendingDevices}
          text="Awaiting administrator approval"
         onClick={() => {
  setDeviceFilter("pending");
  setActivePage("devices");
}}
        />

        <AccessSummary
          title="Quarantined"
          value={quarantinedDevices}
          text="Internet access blocked"
         onClick={() => {
  setDeviceFilter("quarantined");
  setActivePage("devices");
}}
        />

 <AccessSummary
          title="Rejected"
          value={rejectedDevices}
          text="Devices rejected by administrator"
          onClick={() => {
            setDeviceFilter("rejected");
            setActivePage("devices");
          }}
        />

      </div>

      <div className="panel">
        <div className="panel-header">
          <div>
            <div className="panel-title">
              Endpoint Update Status
            </div>
            <div className="panel-subtitle">
              Update status of monitored machines
            </div>
          </div>

          <div style={{ display: "flex", gap: "8px" }}>
            <button
              className="primary-button small"
              onClick={async () => {
                await scanLanUpdates();
              }}
              disabled={lanScanLoading}
              style={{ display: "flex", alignItems: "center", gap: "4px" }}
            >
              {lanScanLoading ? "⏳ Scanning..." : "⚡ Scan LAN Updates"}
            </button>
            <button
              className="secondary-button small"
              onClick={() => setActivePage("endpoint-updates")}
            >
              View Details
            </button>
          </div>
        </div>

        {dashboardUpdatesError && (
          <div className="error-message">
            {dashboardUpdatesError}
          </div>
        )}

        <div className="access-summary">
          <div
            className="summary-card"
            style={{ cursor: "pointer" }}
            onClick={() => {
              setDeviceFilter("all");
              setActivePage("devices");
            }}
            title="Click to view all LAN devices"
          >
            <div className="summary-card-title">
              Monitored Machines
            </div>
            <div className="summary-card-value">
              {dashboardUpdatesLoading
                ? "..."
                : dashboardEndpointUpdates.length}
            </div>
          </div>

          <div
            className="summary-card"
            style={{ cursor: "pointer" }}
            onClick={() => {
              setDeviceFilter("needs_updates");
              setActivePage("devices");
            }}
            title="Click to filter machines with pending updates"
          >
            <div className="summary-card-title" style={{ color: "#f59e0b" }}>
              Needs Updates
            </div>
            <div className="summary-card-value" style={{ color: "#f59e0b" }}>
              {dashboardUpdatesLoading
                ? "..."
                : dashboardUpdatesNeeded}
            </div>
          </div>

          <div
            className="summary-card"
            style={{ cursor: "pointer" }}
            onClick={() => {
              setDeviceFilter("up_to_date");
              setActivePage("devices");
            }}
            title="Click to filter up-to-date machines"
          >
            <div className="summary-card-title" style={{ color: "#10b981" }}>
              Up to Date
            </div>
            <div className="summary-card-value" style={{ color: "#10b981" }}>
              {dashboardUpdatesLoading
                ? "..."
                : dashboardUpToDate}
            </div>
          </div>

          <div
            className="summary-card"
            style={{ cursor: "pointer" }}
            onClick={() => {
              setActivePage("endpoint-updates");
            }}
            title="Click to view detailed endpoint telemetry"
          >
            <div className="summary-card-title">
              Pending Updates
            </div>
            <div className="summary-card-value">
              {dashboardUpdatesLoading
                ? "..."
                : dashboardPendingUpdates.toLocaleString()}
            </div>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <div>
            <div className="panel-title">
              Machine Update Details
            </div>
            <div className="panel-subtitle">
              Latest update report from each monitored endpoint
            </div>
          </div>
          <div style={{ display: "flex", gap: "8px" }}>
            <button
              type="button"
              className="secondary-button"
              onClick={() => { loadPatchJobs(); setShowJobsModal(true); }}
              style={{ display: "flex", alignItems: "center", gap: "6px" }}
            >
              📋 Remediation Jobs ({patchJobs.length})
            </button>
            <button
              type="button"
              className="primary-button"
              onClick={scanLanUpdates}
              disabled={lanScanLoading}
              style={{ display: "flex", alignItems: "center", gap: "6px" }}
            >
              {lanScanLoading ? "⏳ Scanning..." : "⚡ Scan LAN Updates"}
            </button>
          </div>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>MACHINE</th>
                <th>IP ADDRESS</th>
                <th>OPERATING SYSTEM</th>
                <th>UPDATE STATUS</th>
                <th>PENDING</th>
                <th>LAST CHECKED</th>
                <th>REPORT AGE</th>
                <th>ACTION</th>
              </tr>
            </thead>
            <tbody>
              {dashboardUpdatesLoading ? (
                <tr>
                  <td colSpan="8">Loading endpoint reports...</td>
                </tr>
              ) : dashboardEndpointUpdates.length === 0 ? (
                <tr>
                  <td colSpan="8">
                    No endpoint update reports available.
                  </td>
                </tr>
              ) : (
                dashboardEndpointUpdates.map((endpoint) => {
                  const checkedAt = parseEndpointDate(endpoint.last_checked);

                  const ageMinutes = checkedAt
                    ? (Date.now() - checkedAt.getTime()) / 60000
                    : Infinity;

                  const isOnline =
                    endpoint.device_status === "online" ||
                    endpoint.is_online === true ||
                    endpoint.status === "online";

                  const isFresh =
                    isOnline || (ageMinutes >= 0 && ageMinutes <= 15);

                  const activeJob = getActiveJobForDevice(endpoint);

                  return (
                    <tr key={endpoint.id}>
                      <td>{endpoint.hostname}</td>
                      <td>{endpoint.device_ip || endpoint.ip_address || "—"}</td>
                      <td>
                        {endpoint.operating_system}
                        {endpoint.os_version
                          ? ` ${endpoint.os_version}`
                          : ""}
                      </td>
                      <td>
                        <span
                          className={`status-badge ${
                            !isFresh && !isOnline
                              ? "blocked"
                              : endpoint.update_status === "up_to_date"
                              ? "allowed"
                              : endpoint.update_status === "updates_available"
                              ? "warning"
                              : "blocked"
                          }`}
                        >
                          {!isFresh && !isOnline
                            ? "STALE / UNKNOWN"
                            : endpoint.update_status === "up_to_date"
                            ? "UP TO DATE"
                            : endpoint.update_status === "updates_available"
                            ? "NEEDS UPDATES"
                            : endpoint.update_status || "UNKNOWN"}
                        </span>
                      </td>
                      <td>{endpoint.pending_updates ?? "—"}</td>
                      <td>
                        {checkedAt
                          ? checkedAt.toLocaleString()
                          : "Never"}
                      </td>
                      <td>
                        {!checkedAt
                          ? "Unknown"
                          : ageMinutes < 0
                          ? "Invalid timestamp"
                          : ageMinutes <= 15
                          ? "Recent"
                          : `${Math.floor(ageMinutes)} min ago`}
                      </td>
                      <td>
                        {activeJob ? (
                          <div style={{ display: "flex", gap: "6px", alignItems: "center", flexWrap: "wrap" }}>
                            <button
                              type="button"
                              className="secondary-button small"
                              style={{
                                fontSize: "11px",
                                padding: "3px 8px",
                                color: activeJob.status === "SCHEDULED" ? "#a5b4fc" : "#f59e0b",
                                borderColor: activeJob.status === "SCHEDULED" ? "#6366f1" : "#f59e0b",
                                fontWeight: "700",
                              }}
                              onClick={() => {
                                setSelectedJobDetails(activeJob);
                                setShowJobsModal(true);
                              }}
                            >
                              {activeJob.status === "SCHEDULED"
                                ? "📅 Scheduled"
                                : activeJob.status === "IN_PROGRESS"
                                ? `⚡ ${activeJob.progress_percent}%`
                                : "⚡ Queued"}
                            </button>
                            {(activeJob.status === "PENDING" || activeJob.status === "SCHEDULED") && (
                              <button
                                type="button"
                                className="primary-button small"
                                style={{
                                  fontSize: "11px",
                                  padding: "3px 8px",
                                  backgroundColor: "#10b981",
                                  borderColor: "#059669",
                                  fontWeight: "600",
                                }}
                                onClick={async () => {
                                  await runJobNow(activeJob.id);
                                  setShowJobsModal(true);
                                }}
                                title="Continue update deployment immediately"
                              >
                                ▶️ Continue
                              </button>
                            )}
                          </div>
                        ) : (
                          <button
                            type="button"
                            className="primary-button small"
                            style={{
                              fontSize: "11px",
                              padding: "3px 8px",
                              background: "#10b981",
                              borderColor: "#059669",
                              fontWeight: "600",
                            }}
                            onClick={() => openDeployModal(endpoint)}
                            title="Centrally deploy updates to this machine"
                          >
                            ⚡ Deploy Updates
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>


      <div className="panel">

        <div className="panel-header">

          <div>
            <div className="panel-title">
              Device Classification
            </div>

            <div className="panel-subtitle">
              Current device-to-VLAN distribution
            </div>
          </div>

        </div>

        <div className="access-summary">

          <div
            className="summary-card"
            onClick={() => {
              setActivePage("vlans");
              setVlanFilter("20");
            }}
            style={{ cursor: "pointer" }}
          >
            <div className="summary-card-title">
              💻 Computers
            </div>

            <div className="summary-card-value">
              {computerDevices}
            </div>

            <div className="summary-card-text">
              VLAN 20
            </div>
          </div>

          <div
            className="summary-card"
            onClick={() => {
              setActivePage("vlans");
              setVlanFilter("30");
            }}
            style={{ cursor: "pointer" }}
          >
            <div className="summary-card-title">
              📹 CCTV
            </div>

            <div className="summary-card-value">
              {cctvDevices}
            </div>

            <div className="summary-card-text">
              VLAN 30
            </div>
          </div>

          <div
            className="summary-card"
            onClick={() => {
              setActivePage("vlans");
              setVlanFilter("40");
            }}
            style={{ cursor: "pointer" }}
          >
            <div className="summary-card-title">
              🖨️ Printers
            </div>

            <div className="summary-card-value">
              {printerDevices}
            </div>

            <div className="summary-card-text">
              VLAN 40
            </div>
          </div>

          <div
            className="summary-card"
            onClick={() => {
              setActivePage("vlans");
              setVlanFilter("90");
            }}
            style={{ cursor: "pointer" }}
          >
            <div className="summary-card-title">
              ⚠️ Quarantine
            </div>

            <div className="summary-card-value">
              {unknownDevices}
            </div>

            <div className="summary-card-text">
              VLAN 90
            </div>
          </div>

        </div>

      </div>

      <div className="panel">

        <div className="panel-header">

          <div>
            <div className="panel-title">
              Access Control Status
            </div>

            <div className="panel-subtitle">
              Approval and Internet access state
            </div>
          </div>

          <button
            className="secondary-button small"
            onClick={() => setActivePage("access")}
          >
            Manage Access
          </button>

        </div>

        <div className="table-container">

          <table className="data-table">

            <thead>
              <tr>
                <th>DEVICE</th>
                <th>TYPE</th>
                <th>APPROVAL</th>
                <th>ACCESS</th>
                <th>ENFORCEMENT</th>
                <th>VLAN</th>
              </tr>
            </thead>

            <tbody>

              {devices.length === 0 ? (

                <tr>
                  <td colSpan="6">
                    <div className="empty-state">
                      No devices detected.
                    </div>
                  </td>
                </tr>

              ) : (

                devices.slice(0, 10).map((device) => (

                  <tr key={device.id}>

                    <td>
                      <div className="device-primary">
                        {device.hostname ||
                          "Unknown Device"}
                      </div>

                      <div className="device-secondary">
                        {device.ip_address || "-"}
                      </div>
                    </td>

                    <td>
                      <TypeBadge
                        type={device.device_type}
                      />
                    </td>

                    <td>
                      <StatusBadge
                        value={
                          device.approval_status
                        }
                      />
                    </td>

                    <td>
                      <StatusBadge
                        value={
                          device.access_decision ||
                          "unknown"
                        }
                      />
                    </td>

                    <td>
                      <EnforcementBadge
                        value={
                          device.enforcement_status
                        }
                      />
                    </td>

                    <td>
                      <span className="vlan-badge">
                        VLAN{" "}
                        {device.vlan_id || 90}
                      </span>
                    </td>

                  </tr>

                ))

              )}

            </tbody>

          </table>

        </div>

      </div>

    </div>
  );
};

const EndpointUpdatesPage = () => {
  const [endpointUpdates, setEndpointUpdates] = useState([]);
  const [endpointUpdatesLoading, setEndpointUpdatesLoading] =
    useState(false);
  const [endpointUpdatesError, setEndpointUpdatesError] =
    useState("");
  const parseCheckedDate = (d) => {
    if (!d) return null;
    const str = String(d);
    const dateObj = new Date(str.endsWith("Z") || str.includes("+") ? str : `${str}Z`);
    return isNaN(dateObj.getTime()) ? null : dateObj;
  };

  const endpointFreshness = (endpointOrLastChecked, maybeEndpoint) => {
    const endpoint =
      typeof endpointOrLastChecked === "object" && endpointOrLastChecked !== null
        ? endpointOrLastChecked
        : maybeEndpoint || {};
    const lastChecked =
      typeof endpointOrLastChecked === "string"
        ? endpointOrLastChecked
        : endpoint.last_checked;

    const isOnline =
      endpoint.device_status === "online" ||
      endpoint.is_online === true ||
      endpoint.status === "online";

    if (isOnline) {
      return "online";
    }

    if (!lastChecked) {
      return "stale";
    }

    const parsedDate = parseCheckedDate(lastChecked);
    if (!parsedDate) {
      return "stale";
    }

    const ageMinutes = (Date.now() - parsedDate.getTime()) / 60000;
    return ageMinutes >= 0 && ageMinutes <= 15 ? "online" : "stale";
  };

  const freshEndpointUpdates = endpointUpdates.filter(
    (endpoint) => endpointFreshness(endpoint) === "online"
  );

  const endpointsWithUpdates = freshEndpointUpdates.filter(
    (endpoint) =>
      endpoint.update_status === "updates_available"
  ).length;

  const endpointsUpToDate = freshEndpointUpdates.filter(
    (endpoint) =>
      endpoint.update_status === "up_to_date"
  ).length;

  const totalPendingUpdates = freshEndpointUpdates.reduce(
    (total, endpoint) =>
      total + (endpoint.pending_updates || 0),
    0
  );

  const loadEndpointUpdates = async () => {
    setEndpointUpdatesLoading(true);
    setEndpointUpdatesError("");

    try {
      const response = await fetch(
        `${API_URL}/endpoint-updates/`
      );

      if (!response.ok) {
        throw new Error(
          `Failed to load endpoint updates: ${response.status}`
        );
      }

      const data = await response.json();
      setEndpointUpdates(data);
    } catch (error) {
      setEndpointUpdatesError(error.message);
    } finally {
      setEndpointUpdatesLoading(false);
    }
  };

  useEffect(() => {
    loadEndpointUpdates();

    const refreshInterval = setInterval(() => {
      loadEndpointUpdates();
    }, 60000);

    return () => {
      clearInterval(refreshInterval);
    };
  }, []);

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <div className="page-title">
            Endpoint Updates
          </div>

          <div className="page-description">
            Monitor pending software updates on managed
            network endpoints.
          </div>
        </div>

        <div style={{ display: "flex", gap: "8px" }}>
          <button
            className="primary-button"
            onClick={async () => {
              await scanLanUpdates();
              await loadEndpointUpdates();
            }}
            disabled={lanScanLoading || endpointUpdatesLoading}
            style={{ display: "flex", alignItems: "center", gap: "6px" }}
          >
            {lanScanLoading ? "⏳ Scanning LAN..." : "⚡ Scan LAN for Updates (Agentless)"}
          </button>
          <button
            className="secondary-button"
            onClick={loadEndpointUpdates}
            disabled={endpointUpdatesLoading || lanScanLoading}
          >
            {endpointUpdatesLoading ? "Refreshing..." : "Refresh"}
          </button>
        </div>
      </div>

      {endpointUpdatesError && (
        <div className="error-message">
          {endpointUpdatesError}
        </div>
      )}
      <div className="stats-grid">
        <div className="card">
          <div className="card-subtitle">
            KNOWN ENDPOINTS
          </div>

          <div className="stat-value">
            {endpointUpdates.length}
          </div>
        </div>

        <div className="card">
          <div className="card-subtitle">
            REPORTING NOW
          </div>

          <div className="stat-value">
            {freshEndpointUpdates.length}
          </div>
        </div>

        <div className="card">
          <div className="card-subtitle">
            UPDATES NEEDED
          </div>

          <div className="stat-value">
            {endpointsWithUpdates}
          </div>
        </div>

        <div className="card">
          <div className="card-subtitle">
            PENDING UPDATES
          </div>

          <div className="stat-value">
            {totalPendingUpdates.toLocaleString()}
          </div>
        </div>

        <div className="card">
          <div className="card-subtitle">
            UP TO DATE
          </div>

          <div className="stat-value">
            {endpointsUpToDate}
          </div>
        </div>
      </div>


      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">
              Endpoint Update Status
            </div>

            <div className="card-subtitle">
              {endpointUpdates.length} endpoint
              {endpointUpdates.length === 1 ? "" : "s"} reported
            </div>
          </div>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>DEVICE</th>
                <th>IP ADDRESS</th>
                <th>MAC ADDRESS</th>
                <th>OS</th>
                <th>VERSION</th>
                <th>ARCHITECTURE</th>
                <th>STATUS</th>
                <th>PENDING</th>
                <th>SECURITY</th>
                <th>LAST CHECKED</th>
                <th>CONNECTION</th>
                <th>ACCESS</th>
              </tr>
            </thead>

<tbody>
  {endpointUpdates.length === 0 ? (
    <tr>
      <td colSpan="11">
        No endpoint update information available.
      </td>
    </tr>
  ) : (
    endpointUpdates.map((endpoint) => (
      <tr key={endpoint.id}>
        <td>
          {endpoint.hostname}
        </td>

        <td>
          {endpoint.device_ip || "—"}
        </td>

        <td>
          {endpoint.mac_address || "—"}
        </td>

        <td>
          {endpoint.operating_system}
        </td>

        <td>
          {endpoint.os_version}
        </td>

        <td>
          {endpoint.architecture}
        </td>


        <td>
          <span
            className={`status-badge ${
              endpointFreshness(endpoint) !== "online"
                ? "blocked"
                : endpoint.update_status === "up_to_date"
                ? "allowed"
                : endpoint.update_status === "updates_available"
                ? "warning"
                : "blocked"
            }`}
          >
            {endpointFreshness(endpoint) !== "online"
              ? "STALE / UNKNOWN"
              : endpoint.update_status === "updates_available"
              ? "Updates Available"
              : endpoint.update_status === "up_to_date"
              ? "Up to Date"
              : endpoint.update_status || "Unknown"}
          </span>
        </td>


                    <td>
                      <strong>
                        {endpoint.pending_updates}
                      </strong>
                    </td>

                    <td>
                      {endpoint.security_updates ?? "—"}
                    </td>

                    <td>
                      {parseCheckedDate(endpoint.last_checked)
                        ? parseCheckedDate(endpoint.last_checked).toLocaleString()
                        : endpoint.last_checked || "Never"}
                    </td>

                    <td>
                      <span
                        className={`status-badge ${
                          endpointFreshness(endpoint) === "online"
                            ? "allowed"
                            : "blocked"
                        }`}
                      >
                        {endpointFreshness(endpoint) === "online"
                          ? "ONLINE"
                          : "STALE"}
                      </span>
                    </td>

<td>
  {!endpoint.device_id ? (
    <span className="status-badge blocked">
      UNRECOGNIZED
    </span>
  ) : endpoint.approval_status === "pending" ? (
    <span className="status-badge blocked">
      PENDING
    </span>
  ) : endpoint.approval_status === "rejected" ? (
    <span className="status-badge blocked">
      REJECTED
    </span>
  ) : endpoint.enforcement_status === "allowed" &&
    endpoint.internet_access_authorized ? (
    <span className="status-badge allowed">
      INTERNET ALLOWED
    </span>
  ) : (
    <span className="status-badge blocked">
      QUARANTINED
    </span>
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
  );
};

  // ------------------------------------------------------------
  // PAGE ROUTER
  // ------------------------------------------------------------

  const renderPage = () => {
  console.log("NETOPS activePage:", activePage);
    switch (activePage) {
      case "lan-scanner":
        return <LanScannerPage />;
      case "devices":
        return <DevicesPage />;
      case "events":
        return <EventsPage />;

      case "access":
        return <AccessPage />;
      
      case "endpoint-updates":
        return <EndpointUpdatesPage />;

      case "vlans":
        return <VLANPage />;

      case "reports":
        return <ReportsPage />;

      case "users":
        return <UsersPage API_URL={API_URL} currentUser={currentUser} getAuthHeaders={getAuthHeaders} />;

      case "settings":
        return <SettingsPage />;

      default:
        return <Dashboard />;
    }
  };

  // ------------------------------------------------------------
  // PATCH REMEDIATION MODALS
  // ------------------------------------------------------------

  const renderPatchModals = () => {
    return (
      <>
        {deployModalDevice && (
          <div
            className="modal-overlay"
            onClick={() => {
              if (deployingStatus !== "dispatching") {
                setDeployModalDevice(null);
                setDeployingStatus(null);
              }
            }}
          >
            <div
              className="automation-modal"
              onClick={(e) => e.stopPropagation()}
              style={{ maxWidth: "580px" }}
            >
              <div className="automation-modal-header">
                <div>
                  <div className="automation-label">CENTRAL PATCH REMEDIATION</div>
                  <div className="automation-title">Deploy Updates</div>
                </div>
                <button
                  type="button"
                  style={{
                    background: "transparent",
                    border: "none",
                    color: "#94a3b8",
                    fontSize: "20px",
                    cursor: "pointer",
                  }}
                  onClick={() => {
                    setDeployModalDevice(null);
                    setDeployingStatus(null);
                  }}
                >
                  ✕
                </button>
              </div>

              <div style={{ marginTop: "16px" }}>
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "1fr 1fr",
                    gap: "12px",
                    background: "#090d16",
                    border: "1px solid #1e293b",
                    borderRadius: "8px",
                    padding: "16px",
                  }}
                >
                  <div>
                    <span style={{ fontSize: "11px", color: "#64748b", textTransform: "uppercase" }}>Target Machine</span>
                    <div style={{ fontWeight: "700", color: "#f8fafc", fontSize: "15px", marginTop: "2px" }}>
                      {deployModalDevice.hostname || "Unknown Host"}
                    </div>
                  </div>
                  <div>
                    <span style={{ fontSize: "11px", color: "#64748b", textTransform: "uppercase" }}>IP Address</span>
                    <div style={{ fontWeight: "600", color: "#f8fafc", fontSize: "15px", marginTop: "2px" }}>
                      {deployModalDevice.ip_address || deployModalDevice.device_ip || "LAN Interface"}
                    </div>
                  </div>
                  <div>
                    <span style={{ fontSize: "11px", color: "#64748b", textTransform: "uppercase" }}>Operating System</span>
                    <div style={{ color: "#cbd5e1", fontSize: "13px", marginTop: "2px" }}>
                      {deployModalDevice.operating_system || "Linux / Windows"} {deployModalDevice.os_version || ""}
                    </div>
                  </div>
                  <div>
                    <span style={{ fontSize: "11px", color: "#64748b", textTransform: "uppercase" }}>Pending Patches</span>
                    <div style={{ color: "#f59e0b", fontWeight: "700", fontSize: "13px", marginTop: "2px" }}>
                      ⚠️ {deployModalDevice.pending_updates ?? "Available"} Updates Pending
                    </div>
                  </div>
                </div>

                <div style={{ marginTop: "16px", marginBottom: "16px" }}>
                  <label style={{ fontSize: "11px", fontWeight: "700", color: "#94a3b8", display: "block", marginBottom: "8px", textTransform: "uppercase" }}>
                    Deployment Timing
                  </label>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
                    <div
                      onClick={() => setScheduleMode("now")}
                      style={{
                        padding: "10px 12px",
                        borderRadius: "6px",
                        cursor: "pointer",
                        background: scheduleMode === "now" ? "rgba(16, 185, 129, 0.12)" : "#090d16",
                        border: scheduleMode === "now" ? "1px solid #10b981" : "1px solid #1e293b",
                        display: "flex",
                        alignItems: "center",
                        gap: "8px",
                      }}
                    >
                      <input
                        type="radio"
                        name="scheduleMode"
                        checked={scheduleMode === "now"}
                        onChange={() => setScheduleMode("now")}
                        style={{ cursor: "pointer" }}
                      />
                      <div>
                        <div style={{ fontSize: "13px", fontWeight: "600", color: scheduleMode === "now" ? "#34d399" : "#f1f5f9" }}>
                          ⚡ Deploy Now
                        </div>
                        <div style={{ fontSize: "11px", color: "#94a3b8" }}>
                          Execute updates immediately
                        </div>
                      </div>
                    </div>

                    <div
                      onClick={() => {
                        setScheduleMode("scheduled");
                        if (!scheduledDateTime) {
                          const d = new Date(Date.now() + 3600 * 1000);
                          setScheduledDateTime(new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16));
                        }
                      }}
                      style={{
                        padding: "10px 12px",
                        borderRadius: "6px",
                        cursor: "pointer",
                        background: scheduleMode === "scheduled" ? "rgba(99, 102, 241, 0.12)" : "#090d16",
                        border: scheduleMode === "scheduled" ? "1px solid #6366f1" : "1px solid #1e293b",
                        display: "flex",
                        alignItems: "center",
                        gap: "8px",
                      }}
                    >
                      <input
                        type="radio"
                        name="scheduleMode"
                        checked={scheduleMode === "scheduled"}
                        onChange={() => {
                          setScheduleMode("scheduled");
                          if (!scheduledDateTime) {
                            const d = new Date(Date.now() + 3600 * 1000);
                            setScheduledDateTime(new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16));
                          }
                        }}
                        style={{ cursor: "pointer" }}
                      />
                      <div>
                        <div style={{ fontSize: "13px", fontWeight: "600", color: scheduleMode === "scheduled" ? "#a5b4fc" : "#f1f5f9" }}>
                          📅 Schedule for Date & Time
                        </div>
                        <div style={{ fontSize: "11px", color: "#94a3b8" }}>
                          Specify future maintenance window
                        </div>
                      </div>
                    </div>
                  </div>

                  {scheduleMode === "scheduled" && (
                    <div style={{ marginTop: "12px", background: "#0b1120", border: "1px solid #1e293b", borderRadius: "6px", padding: "12px" }}>
                      <div style={{ fontSize: "11px", color: "#94a3b8", marginBottom: "6px", fontWeight: "600", textTransform: "uppercase" }}>
                        Select Scheduled Execution Time
                      </div>
                      <input
                        type="datetime-local"
                        value={scheduledDateTime}
                        min={new Date(Date.now() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16)}
                        onChange={(e) => setScheduledDateTime(e.target.value)}
                        style={{
                          width: "100%",
                          padding: "8px 10px",
                          background: "#030712",
                          border: "1px solid #334155",
                          borderRadius: "4px",
                          color: "#f8fafc",
                          fontSize: "13px",
                          outline: "none",
                          boxSizing: "border-box",
                        }}
                      />

                      <div style={{ marginTop: "10px" }}>
                        <span style={{ fontSize: "11px", color: "#64748b", marginRight: "8px" }}>Quick Presets:</span>
                        <div style={{ display: "inline-flex", gap: "6px", flexWrap: "wrap", marginTop: "4px" }}>
                          <button
                            type="button"
                            className="secondary-button small"
                            style={{ fontSize: "11px", padding: "2px 8px" }}
                            onClick={() => {
                              const d = new Date();
                              d.setHours(23, 0, 0, 0);
                              if (d <= new Date()) d.setDate(d.getDate() + 1);
                              setScheduledDateTime(new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16));
                            }}
                          >
                            Tonight 11:00 PM
                          </button>
                          <button
                            type="button"
                            className="secondary-button small"
                            style={{ fontSize: "11px", padding: "2px 8px" }}
                            onClick={() => {
                              const d = new Date();
                              d.setDate(d.getDate() + 1);
                              d.setHours(2, 0, 0, 0);
                              setScheduledDateTime(new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16));
                            }}
                          >
                            Tomorrow 2:00 AM
                          </button>
                          <button
                            type="button"
                            className="secondary-button small"
                            style={{ fontSize: "11px", padding: "2px 8px" }}
                            onClick={() => {
                              const d = new Date();
                              const day = d.getDay();
                              const daysUntilSat = (6 - day + 7) % 7 || 7;
                              d.setDate(d.getDate() + daysUntilSat);
                              d.setHours(3, 0, 0, 0);
                              setScheduledDateTime(new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16));
                            }}
                          >
                            Weekend (Sat 3:00 AM)
                          </button>
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                <div
                  style={{
                    margin: "16px 0",
                    padding: "12px 14px",
                    background: scheduleMode === "scheduled" ? "rgba(99, 102, 241, 0.08)" : "rgba(59, 130, 246, 0.08)",
                    border: scheduleMode === "scheduled" ? "1px solid rgba(99, 102, 241, 0.25)" : "1px solid rgba(59, 130, 246, 0.25)",
                    borderRadius: "6px",
                    fontSize: "13px",
                    color: scheduleMode === "scheduled" ? "#c7d2fe" : "#93c5fd",
                    lineHeight: "1.5",
                  }}
                >
                  {(deployModalDevice.hostname === "kali" ||
                    deployModalDevice.ip_address === "127.0.0.1" ||
                    deployModalDevice.ip_address === "192.168.0.101") ? (
                    <div>
                      🖥️ <strong>Local Machine Remediation:</strong> {scheduleMode === "scheduled" ? "Updates will be queued and automatically triggered using the native package manager (apt-get upgrade -y) when the scheduled date & time arrives." : "Updates will be applied immediately using the native package manager (apt-get upgrade -y)."}
                    </div>
                  ) : (
                    <div>
                      📡 <strong>LAN Remote Remediation (Approach 1):</strong> {scheduleMode === "scheduled" ? "An update job will be queued in SCHEDULED state. Once the scheduled time arrives, it will activate for the endpoint's agent to install updates on its next check-in." : "An update installation job will be dispatched. When this machine's agent reports its check-in, it will automatically download and install updates natively and sync completion back to NETOPS."}
                    </div>
                  )}
                </div>

                <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px", marginTop: "20px" }}>
                  <button
                    type="button"
                    className="secondary-button"
                    onClick={() => {
                      setDeployModalDevice(null);
                      setDeployingStatus(null);
                    }}
                    disabled={deployingStatus === "dispatching"}
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    className="primary-button"
                    style={{
                      background: scheduleMode === "scheduled" ? "#6366f1" : "#10b981",
                      borderColor: scheduleMode === "scheduled" ? "#4f46e5" : "#059669",
                    }}
                    disabled={
                      deployingStatus === "dispatching" ||
                      (scheduleMode === "scheduled" && (!scheduledDateTime || new Date(scheduledDateTime) <= new Date()))
                    }
                    onClick={async () => {
                      const target = deployModalDevice;
                      const targetTime = scheduleMode === "scheduled" ? scheduledDateTime : null;
                      const job = await deployUpdates(target, targetTime);
                      if (job) {
                        setDeployModalDevice(null);
                        setDeployingStatus(null);
                        setSelectedJobDetails(job);
                        setShowJobsModal(true);
                      }
                    }}
                  >
                    {deployingStatus === "dispatching"
                      ? (scheduleMode === "scheduled" ? "⏳ Scheduling Job..." : "⏳ Queueing Update Job...")
                      : (scheduleMode === "scheduled" ? "📅 Confirm & Schedule Updates" : "⚡ Confirm & Deploy Updates")}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {showJobsModal && (
          <div
            className="modal-overlay"
            onClick={() => setShowJobsModal(false)}
          >
            <div
              className="automation-modal"
              onClick={(e) => e.stopPropagation()}
              style={{ width: "min(850px, 95%)" }}
            >
              <div className="automation-modal-header">
                <div>
                  <div className="automation-label">NETOPS REMEDIATION</div>
                  <div className="automation-title">Central Update Jobs & Logs</div>
                </div>
                <button
                  type="button"
                  style={{
                    background: "transparent",
                    border: "none",
                    color: "#94a3b8",
                    fontSize: "20px",
                    cursor: "pointer",
                  }}
                  onClick={() => setShowJobsModal(false)}
                >
                  ✕
                </button>
              </div>

              <div style={{ marginTop: "16px" }}>
                {patchJobs.length === 0 ? (
                  <div style={{ textAlign: "center", padding: "30px", color: "#64748b" }}>
                    No update deployment jobs have been triggered yet.
                  </div>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: "10px", maxHeight: "260px", overflowY: "auto", marginBottom: "16px" }}>
                    {patchJobs.map((job) => (
                      <div
                        key={job.id}
                        onClick={() => setSelectedJobDetails(job)}
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                          padding: "10px 14px",
                          borderRadius: "6px",
                          cursor: "pointer",
                          background: selectedJobDetails?.id === job.id ? "#1e293b" : "#0f172a",
                          border: selectedJobDetails?.id === job.id ? "1px solid #3b82f6" : "1px solid #1e293b",
                        }}
                      >
                        <div>
                          <div style={{ fontWeight: "700", color: "#f8fafc", fontSize: "14px" }}>
                            Job #{job.id} — {job.hostname} ({job.ip_address || "LAN"})
                          </div>
                          <div style={{ fontSize: "12px", color: "#94a3b8", marginTop: "2px" }}>
                            {job.is_local ? "🖥️ Local Host Execution" : "📡 Remote Agent Queue"} • {job.created_at ? new Date(job.created_at.endsWith("Z") ? job.created_at : job.created_at + "Z").toLocaleTimeString() : ""}
                            {job.scheduled_at && (
                              <span style={{ color: "#a5b4fc", marginLeft: "6px" }}>
                                • 📅 Scheduled: {new Date(job.scheduled_at.endsWith("Z") ? job.scheduled_at : job.scheduled_at + "Z").toLocaleString()}
                              </span>
                            )}
                          </div>
                        </div>

                        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                          <span
                            className={`status-badge ${
                              job.status === "COMPLETED"
                                ? "allowed"
                                : job.status === "IN_PROGRESS"
                                ? "warning"
                                : job.status === "FAILED"
                                ? "blocked"
                                : "offline"
                            }`}
                            style={
                              job.status === "SCHEDULED"
                                ? { background: "rgba(99, 102, 241, 0.2)", color: "#a5b4fc", border: "1px solid rgba(99, 102, 241, 0.5)" }
                                : {}
                            }
                          >
                            {job.status === "IN_PROGRESS"
                              ? `UPDATING ${job.progress_percent}%`
                              : job.status === "SCHEDULED"
                              ? "📅 SCHEDULED"
                              : job.status}
                          </span>

                          {(job.status === "PENDING" || job.status === "SCHEDULED") && (
                            <>
                              <button
                                type="button"
                                className="primary-button small"
                                style={{ fontSize: "11px", padding: "2px 8px", background: "#10b981", borderColor: "#059669", fontWeight: "600" }}
                                onClick={async (e) => {
                                  e.stopPropagation();
                                  await runJobNow(job.id);
                                }}
                                title="Continue and execute update immediately"
                              >
                                ▶️ Continue Update
                              </button>
                              <button
                                type="button"
                                className="secondary-button small"
                                style={{ fontSize: "11px", padding: "2px 8px", color: "#f87171", borderColor: "#7f1d1d" }}
                                onClick={async (e) => {
                                  e.stopPropagation();
                                  const label = job.status === "SCHEDULED" ? "scheduled update" : "pending update";
                                  if (window.confirm(`Cancel ${label} job #${job.id} for ${job.hostname}?`)) {
                                    try {
                                      await fetch(`${API_URL}/endpoint-updates/jobs/${job.id}/cancel`, { method: "POST" });
                                      await loadPatchJobs();
                                    } catch (err) {
                                      alert("Failed to cancel job: " + err.message);
                                    }
                                  }
                                }}
                                title={job.status === "SCHEDULED" ? "Cancel scheduled maintenance job" : "Cancel this pending job from queue"}
                              >
                                Cancel
                              </button>
                            </>
                          )}
                          {(job.status === "CANCELLED" || job.status === "FAILED") && (
                            <button
                              type="button"
                              className="secondary-button small"
                              style={{ fontSize: "11px", padding: "2px 8px", color: "#60a5fa", borderColor: "#2563eb", fontWeight: "600" }}
                              onClick={async (e) => {
                                e.stopPropagation();
                                await runJobNow(job.id);
                              }}
                              title="Restart or retry this update job"
                            >
                              🔄 Retry Update
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {selectedJobDetails && (
                  <div style={{ background: "#06090e", border: "1px solid #1e293b", borderRadius: "8px", padding: "14px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "8px" }}>
                      <span style={{ fontSize: "12px", fontWeight: "700", color: "#94a3b8" }}>
                        LIVE EXECUTION LOGS (JOB #{selectedJobDetails.id} - {selectedJobDetails.hostname})
                      </span>
                      <span style={{ fontSize: "12px", color: "#64748b" }}>
                        Progress: {selectedJobDetails.progress_percent}%
                      </span>
                    </div>

                    {selectedJobDetails.status === "SCHEDULED" && (
                      <div style={{ background: "rgba(99, 102, 241, 0.1)", border: "1px solid #4f46e5", borderRadius: "6px", padding: "10px 12px", marginBottom: "12px", fontSize: "12px", color: "#c7d2fe", display: "flex", justifyContent: "space-between", alignItems: "center", gap: "10px" }}>
                        <div>
                          <strong>📅 Scheduled Maintenance Window:</strong> Updates for <strong>{selectedJobDetails.hostname}</strong> are scheduled to run at <strong>{selectedJobDetails.scheduled_at ? new Date(selectedJobDetails.scheduled_at.endsWith("Z") ? selectedJobDetails.scheduled_at : selectedJobDetails.scheduled_at + "Z").toLocaleString() : "the scheduled time"}</strong>.
                        </div>
                        <div style={{ display: "flex", gap: "8px", flexShrink: 0 }}>
                          <button
                            type="button"
                            className="primary-button small"
                            style={{ fontSize: "11px", padding: "2px 8px", background: "#10b981", borderColor: "#059669", fontWeight: "600", whiteSpace: "nowrap" }}
                            onClick={async () => {
                              await runJobNow(selectedJobDetails.id);
                            }}
                            title="Execute updates immediately without waiting for scheduled time"
                          >
                            ▶️ Run Now
                          </button>
                          <button
                            type="button"
                            className="secondary-button small"
                            style={{ fontSize: "11px", padding: "2px 8px", color: "#f87171", borderColor: "#7f1d1d", whiteSpace: "nowrap" }}
                            onClick={async () => {
                              if (window.confirm(`Cancel scheduled update job #${selectedJobDetails.id}?`)) {
                                try {
                                  await fetch(`${API_URL}/endpoint-updates/jobs/${selectedJobDetails.id}/cancel`, { method: "POST" });
                                  await loadPatchJobs();
                                  setSelectedJobDetails((prev) => prev ? { ...prev, status: "CANCELLED" } : null);
                                } catch (err) {
                                  alert("Failed to cancel job: " + err.message);
                                }
                              }
                            }}
                          >
                            Cancel Schedule
                          </button>
                        </div>
                      </div>
                    )}

                    {selectedJobDetails.status === "PENDING" && (
                      <div style={{ background: "rgba(59, 130, 246, 0.1)", border: "1px solid #1d4ed8", borderRadius: "6px", padding: "10px 12px", marginBottom: "12px", fontSize: "12px", color: "#93c5fd", display: "flex", justifyContent: "space-between", alignItems: "center", gap: "10px" }}>
                        <div>
                          <strong>⏳ Queued for Updates:</strong> This command is waiting in queue for <strong>{selectedJobDetails.hostname}</strong> ({selectedJobDetails.ip_address || "LAN"}).
                        </div>
                        <div style={{ display: "flex", gap: "8px", flexShrink: 0 }}>
                          <button
                            type="button"
                            className="primary-button small"
                            style={{ fontSize: "11px", padding: "3px 10px", background: "#10b981", borderColor: "#059669", fontWeight: "600", whiteSpace: "nowrap" }}
                            onClick={async () => {
                              await runJobNow(selectedJobDetails.id);
                            }}
                            title="Continue update deployment immediately"
                          >
                            ▶️ Continue to Update Now
                          </button>
                          <button
                            type="button"
                            className="secondary-button small"
                            style={{ fontSize: "11px", padding: "2px 8px", color: "#f87171", borderColor: "#7f1d1d", whiteSpace: "nowrap" }}
                            onClick={async () => {
                              if (window.confirm(`Cancel pending update job #${selectedJobDetails.id}?`)) {
                                try {
                                  await fetch(`${API_URL}/endpoint-updates/jobs/${selectedJobDetails.id}/cancel`, { method: "POST" });
                                  await loadPatchJobs();
                                  setSelectedJobDetails((prev) => prev ? { ...prev, status: "CANCELLED" } : null);
                                } catch (err) {
                                  alert("Failed to cancel job: " + err.message);
                                }
                              }
                            }}
                          >
                            Cancel Job
                          </button>
                        </div>
                      </div>
                    )}

                    {(selectedJobDetails.status === "CANCELLED" || selectedJobDetails.status === "FAILED") && (
                      <div style={{ background: "rgba(239, 68, 68, 0.1)", border: "1px solid #b91c1c", borderRadius: "6px", padding: "10px 12px", marginBottom: "12px", fontSize: "12px", color: "#fca5a5", display: "flex", justifyContent: "space-between", alignItems: "center", gap: "10px" }}>
                        <div>
                          <strong>{selectedJobDetails.status === "CANCELLED" ? "✕ Update Job Cancelled:" : "⚠️ Update Job Failed:"}</strong> You can restart and continue update deployment anytime.
                        </div>
                        <button
                          type="button"
                          className="primary-button small"
                          style={{ fontSize: "11px", padding: "3px 10px", background: "#3b82f6", borderColor: "#2563eb", fontWeight: "600", whiteSpace: "nowrap" }}
                          onClick={async () => {
                            await runJobNow(selectedJobDetails.id);
                          }}
                        >
                          🔄 Restart / Retry Update
                        </button>
                      </div>
                    )}

                    <div style={{ background: "#111827", height: "6px", borderRadius: "3px", overflow: "hidden", marginBottom: "12px" }}>
                      <div
                        style={{
                          height: "100%",
                          width: `${selectedJobDetails.progress_percent}%`,
                          background: selectedJobDetails.status === "FAILED" ? "#ef4444" : "#10b981",
                          transition: "width 0.3s ease",
                        }}
                      />
                    </div>

                    <pre
                      style={{
                        background: "#030712",
                        color: "#4ade80",
                        padding: "12px",
                        borderRadius: "6px",
                        fontSize: "12px",
                        fontFamily: "monospace",
                        maxHeight: "180px",
                        overflowY: "auto",
                        whiteSpace: "pre-wrap",
                        margin: 0,
                      }}
                    >
                      {selectedJobDetails.log_output || "Awaiting execution..."}
                      {selectedJobDetails.error_message ? `\nError: ${selectedJobDetails.error_message}` : ""}
                    </pre>
                  </div>
                )}

                <div style={{ display: "flex", justifyContent: "flex-end", marginTop: "16px" }}>
                  <button
                    type="button"
                    className="primary-button small"
                    onClick={() => setShowJobsModal(false)}
                  >
                    Close
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </>
    );
  };

  // ------------------------------------------------------------
  // AUTOMATION MODAL
  // ------------------------------------------------------------

  const renderAutomationResult = () => {
    if (!automationResult) {
      return null;
    }

    const success =
      automationResult.configuration_status ===
        "simulated" &&
      automationResult.verification_status ===
        "verified_simulation";

    return (
      <div
        className="modal-overlay"
        onClick={() =>
          setAutomationResult(null)
        }
      >
        <div
          className="automation-modal"
          onClick={(event) =>
            event.stopPropagation()
          }
        >
          <div className="automation-modal-header">
            <div>
              <div className="automation-label">
                NETOPS AUTOMATION
              </div>

              <div className="automation-title">
                VLAN Automation
              </div>
            </div>

            <div
              className={
                success
                  ? "automation-result success"
                  : "automation-result warning"
              }
            >
              {success
                ? "SUCCESS"
                : "WARNING"}
            </div>
          </div>

          <div className="automation-device">
            <div>
              <span>IP ADDRESS</span>
              <strong>
                {automationResult.ip_address ||
                  "-"}
              </strong>
            </div>

            <div>
              <span>MAC ADDRESS</span>
              <strong>
                {automationResult.mac_address ||
                  "-"}
              </strong>
            </div>
          </div>

          <div className="automation-grid">
            <AutomationField
              label="Device Type"
              value={
                automationResult.device_type
              }
            />

            <AutomationField
              label="Target VLAN"
              value={`VLAN ${
                automationResult.vlan_id ??
                "-"
              }`}
            />

            <AutomationField
              label="Switch"
              value={
                automationResult.switch_name ||
                "Not identified"
              }
            />

            <AutomationField
              label="Port"
              value={
                automationResult.switch_port ||
                "Not identified"
              }
            />

            <AutomationField
              label="Switch Status"
              value={
                automationResult.switch_status ||
                "-"
              }
            />

            <AutomationField
              label="Port Status"
              value={
                automationResult.port_status ||
                "-"
              }
            />
          </div>

          <div className="automation-pipeline">
            <div className="pipeline-title">
              AUTOMATION PIPELINE
            </div>

            <PipelineStep
              number="01"
              title="Classify Device"
              status="Complete"
            />

            <PipelineStep
              number="02"
              title="Apply VLAN Policy"
              status={`VLAN ${
                automationResult.vlan_id ??
                "-"
              }`}
            />

            <PipelineStep
              number="03"
              title="Identify Switch Port"
              status={
                automationResult.switch_port
                  ? "Complete"
                  : "Waiting"
              }
            />

            <PipelineStep
              number="04"
              title="Configure Switch"
              status={
                automationResult.configuration_status ||
                "-"
              }
            />

            <PipelineStep
              number="05"
              title="Verify Configuration"
              status={
                automationResult.verification_status ||
                "-"
              }
            />
          </div>

          <div className="automation-mode">
            <span>MODE</span>

            <strong>
              {automationResult.mode ||
                "simulation"}
            </strong>
          </div>

          <button
            className="primary-button full"
            onClick={() =>
              setAutomationResult(null)
            }
          >
            Done
          </button>
        </div>
      </div>
    );
  };

  // ------------------------------------------------------------
  // MAIN UI
  // ------------------------------------------------------------

  if (!currentUser) {
    return (
      <LoginPage
        API_URL={API_URL}
        onLoginSuccess={handleLoginSuccess}
        initialActivationToken={activationToken}
      />
    );
  }

  return (
    <>
      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }

        * {
          box-sizing: border-box;
        }

        html,
        body,
        #root {
          margin: 0;
          padding: 0;
          width: 100%;
          min-height: 100%;
        }

        body {
          min-height: 100vh;
          background: #0b1120;
          color: #e5e7eb;
          font-family:
            Inter,
            -apple-system,
            BlinkMacSystemFont,
            "Segoe UI",
            sans-serif;
        }

        button,
        input,
        select,
        textarea {
          font-family: inherit;
        }

        button {
          transition:
            background 0.15s ease,
            border-color 0.15s ease,
            color 0.15s ease,
            transform 0.15s ease;
        }

        .app {
          min-height: 100vh;
          display: flex;
          background: #0b1120;
        }

        .sidebar {
          width: 230px;
          min-height: 100vh;
          background: #0d1526;
          border-right: 1px solid #1e293b;
          display: flex;
          flex-direction: column;
          position: fixed;
          left: 0;
          top: 0;
          bottom: 0;
          z-index: 20;
        }

        .brand {
          height: 76px;
          padding: 0 20px;
          display: flex;
          align-items: center;
          border-bottom: 1px solid #1e293b;
        }

        .brand-mark {
          width: 38px;
          height: 38px;
          border-radius: 8px;
          background: #2563eb;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 14px;
          font-weight: 800;
          color: white;
          margin-right: 11px;
        }

        .brand-name {
          font-size: 15px;
          font-weight: 800;
          color: #f8fafc;
        }

        .brand-subtitle {
          font-size: 9px;
          color: #64748b;
          margin-top: 3px;
          letter-spacing: 0.8px;
          text-transform: uppercase;
        }

        .nav {
          padding: 18px 12px;
          flex: 1;
        }

        .nav-section-title {
          color: #475569;
          font-size: 9px;
          font-weight: 800;
          letter-spacing: 1.2px;
          padding: 0 10px 8px;
        }

        .nav-item {
          width: 100%;
          border: 0;
          background: transparent;
          color: #94a3b8;
          padding: 10px 11px;
          margin-bottom: 3px;
          border-radius: 6px;
          display: flex;
          align-items: center;
          text-align: left;
          cursor: pointer;
          font-size: 12px;
        }

        .nav-item:hover {
          background: #111c30;
          color: #e2e8f0;
        }

        .nav-item.active {
          background: #172554;
          color: #60a5fa;
        }

        .nav-icon {
          width: 25px;
          color: inherit;
          font-size: 11px;
          font-weight: 800;
        }

        .sidebar-footer {
          border-top: 1px solid #1e293b;
          padding: 14px 18px;
        }

        .system-status {
          display: flex;
          align-items: center;
          gap: 8px;
          color: #64748b;
          font-size: 10px;
        }

        .status-dot {
          width: 7px;
          height: 7px;
          border-radius: 50%;
          display: inline-block;
        }

        .status-dot.online {
          background: #22c55e;
          box-shadow: 0 0 7px rgba(34, 197, 94, 0.45);
        }

        .status-dot.offline {
          background: #ef4444;
        }

        .main {
          margin-left: 230px;
          width: calc(100% - 230px);
          min-height: 100vh;
        }

        .topbar {
          height: 76px;
          border-bottom: 1px solid #1e293b;
          background: #0c1424;
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 0 28px;
          position: sticky;
          top: 0;
          z-index: 10;
        }

        .topbar-title {
          color: #f8fafc;
          font-size: 14px;
          font-weight: 700;
        }

        .topbar-right {
          display: flex;
          align-items: center;
          gap: 16px;
        }

        .live-indicator {
          display: flex;
          align-items: center;
          gap: 7px;
          font-size: 10px;
          color: #64748b;
        }

        .live-dot {
          width: 7px;
          height: 7px;
          border-radius: 50%;
          background: #22c55e;
        }

        .page {
          padding: 28px;
          max-width: 1700px;
          margin: 0 auto;
        }

        .page-header {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          gap: 20px;
          margin-bottom: 24px;
        }

        .page-title {
          color: #f8fafc;
          font-size: 23px;
          font-weight: 800;
        }

        .page-description {
          margin-top: 5px;
          color: #64748b;
          font-size: 11px;
        }

        .connection-indicator {
          display: flex;
          align-items: center;
          gap: 7px;
          font-size: 10px;
          color: #64748b;
          padding: 7px 10px;
          background: #0f172a;
          border: 1px solid #1e293b;
          border-radius: 6px;
        }

        .connection-dot {
          width: 7px;
          height: 7px;
          border-radius: 50%;
        }

        .connection-dot.online {
          background: #22c55e;
        }

        .connection-dot.offline {
          background: #ef4444;
        }

        .stats-grid {
          display: grid;
          grid-template-columns: repeat(5, 1fr);
          gap: 12px;
          margin-bottom: 18px;
        }

        .stat-card {
          background: #0f172a;
          border: 1px solid #1e293b;
          border-radius: 8px;
          padding: 17px;
          min-height: 126px;
        }

        .stat-card-clickable {
          cursor: pointer;
        }

        .stat-card-clickable:hover {
          border-color: #2563eb;
          background: #172033;
          transform: translateY(-2px);
        }

        .stat-title {
          color: #64748b;
          font-size: 9px;
          font-weight: 800;
          letter-spacing: 0.8px;
        }

        .stat-value {
          color: #f8fafc;
          font-size: 29px;
          line-height: 1;
          font-weight: 800;
          margin-top: 12px;
        }

        .stat-subtitle {
          color: #475569;
          font-size: 10px;
          margin-top: 8px;
        }

        .stat-card-action {
          margin-top: 12px;
          color: #60a5fa;
          font-size: 10px;
          font-weight: 700;
        }

        .dashboard-grid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 18px;
          margin-bottom: 18px;
        }

        .panel {
          background: #0f172a;
          border: 1px solid #1e293b;
          border-radius: 8px;
          overflow: hidden;
          margin-bottom: 18px;
        }

        .panel-header {
          min-height: 65px;
          padding: 15px 17px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 15px;
          border-bottom: 1px solid #1e293b;
        }

        .panel-title {
          color: #e2e8f0;
          font-size: 12px;
          font-weight: 800;
        }

        .panel-subtitle {
          color: #475569;
          font-size: 9px;
          margin-top: 4px;
        }

        .classification-list {
          padding: 4px 17px;
        }

        .classification-row {
          min-height: 53px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          border-bottom: 1px solid #172033;
        }

        .classification-row:last-child {
          border-bottom: 0;
        }

        .classification-name {
          display: flex;
          align-items: center;
          gap: 9px;
          color: #94a3b8;
          font-size: 11px;
        }

        .classification-value {
          color: #f8fafc;
          font-weight: 800;
          font-size: 14px;
        }

        .device-icon {
          width: 32px;
          height: 25px;
          border-radius: 5px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 8px;
          font-weight: 800;
        }

        .device-icon.computer {
          background: #172554;
          color: #60a5fa;
        }

        .device-icon.camera {
          background: #2e1065;
          color: #c4b5fd;
        }

        .device-icon.printer {
          background: #083344;
          color: #67e8f9;
        }

        .device-icon.unknown {
          background: #451a03;
          color: #fbbf24;
        }

        .vlan-mini-grid {
          padding: 15px;
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 10px;
        }

        .vlan-mini {
          background: #0b1120;
          border: 1px solid #1e293b;
          border-radius: 6px;
          padding: 13px;
        }

        .vlan-mini.quarantine {
          border-color: #422006;
        }

        .vlan-mini-id {
          color: #60a5fa;
          font-size: 10px;
          font-weight: 800;
        }

        .vlan-mini-name {
          color: #cbd5e1;
          font-size: 11px;
          font-weight: 700;
          margin-top: 7px;
        }

        .vlan-mini-count {
          color: #475569;
          font-size: 9px;
          margin-top: 4px;
        }

        .event-list {
          padding: 0 17px;
        }

        .event-list.large {
          padding: 0;
        }

        .event-row {
          display: flex;
          align-items: flex-start;
          gap: 12px;
          padding: 14px 0;
          border-bottom: 1px solid #172033;
        }

        .event-list.large .event-row {
          padding: 15px 18px;
        }

        .event-row:last-child {
          border-bottom: 0;
        }

        .event-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: #3b82f6;
          margin-top: 4px;
          flex-shrink: 0;
        }

        .event-dot.warning {
          background: #f59e0b;
        }

        .event-dot.success {
          background: #22c55e;
        }

        .event-content {
          min-width: 0;
          flex: 1;
        }

        .event-message {
          color: #cbd5e1;
          font-size: 11px;
          line-height: 1.45;
        }

        .event-meta {
          display: flex;
          gap: 10px;
          margin-top: 4px;
          color: #475569;
          font-size: 9px;
        }

        .primary-button,
        .secondary-button,
        .approve-button,
        .reject-button {
          border-radius: 5px;
          padding: 8px 11px;
          font-size: 10px;
          font-weight: 700;
          cursor: pointer;
        }

        .primary-button {
          border: 1px solid #2563eb;
          background: #2563eb;
          color: white;
        }

        .primary-button:hover {
          background: #1d4ed8;
        }

        .secondary-button {
          border: 1px solid #334155;
          background: #1e293b;
          color: #cbd5e1;
        }

        .secondary-button:hover {
          background: #334155;
        }

        .approve-button {
          border: 1px solid #166534;
          background: #14532d;
          color: #86efac;
        }

        .reject-button {
          border: 1px solid #7f1d1d;
          background: #450a0a;
          color: #fca5a5;
        }

        button:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }

        .small {
          padding: 6px 8px;
          font-size: 9px;
        }

        .full {
          width: 100%;
        }

        .table-container {
          width: 100%;
          overflow-x: auto;
        }

        .data-table {
          width: 100%;
          border-collapse: collapse;
          min-width: 1150px;
        }

        .data-table th {
          background: #0b1120;
          color: #475569;
          text-align: left;
          padding: 11px 13px;
          font-size: 8px;
          font-weight: 800;
          letter-spacing: 0.7px;
          border-bottom: 1px solid #1e293b;
          white-space: nowrap;
        }

        .data-table td {
          padding: 12px 13px;
          border-bottom: 1px solid #172033;
          color: #94a3b8;
          font-size: 10px;
          vertical-align: middle;
        }

        .data-table tbody tr:hover {
          background: #111c30;
        }

        .data-table tbody tr.highlighted {
          background: #172554;
        }

        .device-primary {
          color: #e2e8f0;
          font-size: 11px;
          font-weight: 700;
        }

        .device-secondary {
          color: #475569;
          font-size: 9px;
          margin-top: 3px;
        }

        .action-group {
          display: flex;
          flex-wrap: wrap;
          gap: 5px;
        }

        .type-badge,
        .status-badge,
        .vlan-badge,
        .enforcement-badge {
          display: inline-flex;
          align-items: center;
          border-radius: 4px;
          padding: 4px 6px;
          font-size: 8px;
          font-weight: 800;
          text-transform: uppercase;
          white-space: nowrap;
        }

        .type-badge.computer {
          color: #60a5fa;
          background: #172554;
        }

        .type-badge.cctv {
          color: #c4b5fd;
          background: #2e1065;
        }

        .type-badge.printer {
          color: #67e8f9;
          background: #083344;
        }

        .type-badge.unknown {
          color: #fbbf24;
          background: #451a03;
        }

        .status-badge.online,
        .status-badge.allowed,
        .status-badge.approved {
          color: #86efac;
          background: #052e16;
        }

        .status-badge.offline,
        .status-badge.rejected,
        .status-badge.quarantine {
          color: #fca5a5;
          background: #450a0a;
        }

        .status-badge.pending {
          color: #fcd34d;
          background: #451a03;
        }

        .enforcement-badge.allowed {
          color: #86efac;
          background: #052e16;
        }

        .enforcement-badge.quarantined {
          color: #fca5a5;
          background: #450a0a;
        }

        .enforcement-badge.unknown {
          color: #fcd34d;
          background: #451a03;
        }

        .vlan-badge {
          color: #60a5fa;
          background: #172554;
        }

        .device-filter-bar {
          margin-bottom: 14px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 12px;
          padding: 10px 12px;
          background: #0f172a;
          border: 1px solid #1f2937;
          border-radius: 7px;
          color: #64748b;
          font-size: 11px;
        }

        .device-filter-bar strong {
          color: #60a5fa;
        }

        .clear-filter-button {
          border: 1px solid #334155;
          background: #1e293b;
          color: #cbd5e1;
          border-radius: 5px;
          padding: 6px 9px;
          font-size: 10px;
          cursor: pointer;
        }

        .access-summary {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 12px;
          margin-bottom: 18px;
        }

        .access-summary-card {
          background: #0f172a;
          border: 1px solid #1e293b;
          border-radius: 7px;
          padding: 16px;
          cursor: pointer;
        }

        .access-summary-card:hover {
          border-color: #2563eb;
          background: #172033;
        }

        .access-summary-card span {
          display: block;
          color: #64748b;
          font-size: 9px;
          text-transform: uppercase;
          font-weight: 800;
        }

        .access-summary-card strong {
          display: block;
          color: #f8fafc;
          font-size: 25px;
          margin-top: 8px;
        }

        .access-summary-card small {
          display: block;
          color: #60a5fa;
          font-size: 9px;
          margin-top: 8px;
        }

        .vlan-card-grid {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 12px;
          margin-bottom: 18px;
        }

        .vlan-card {
          background: #0f172a;
          border: 1px solid #1e293b;
          border-radius: 8px;
          padding: 17px;
          cursor: pointer;
        }

        .vlan-card:hover,
        .vlan-card-selected {
          border-color: #2563eb;
          background: #172033;
        }

        .vlan-card.quarantine {
          border-color: #422006;
        }

        .vlan-card-top {
          display: flex;
          justify-content: space-between;
        }

        .vlan-number {
          color: #60a5fa;
          font-size: 10px;
          font-weight: 800;
        }

        .vlan-name {
          color: #cbd5e1;
          font-size: 13px;
          font-weight: 800;
          margin-top: 10px;
        }

        .vlan-description {
          color: #475569;
          font-size: 9px;
          margin-top: 5px;
        }

        .vlan-count {
          color: #f8fafc;
          font-size: 13px;
          font-weight: 800;
          margin-top: 12px;
        }

        .vlan-device-list {
          margin-top: 12px;
        }

        .vlan-device {
          display: flex;
          justify-content: space-between;
          gap: 8px;
          padding: 5px 0;
          color: #64748b;
          font-size: 8px;
          border-top: 1px solid #172033;
        }

        .vlan-card-action {
          margin-top: 14px;
          padding-top: 10px;
          border-top: 1px solid #1e293b;
          color: #60a5fa;
          font-size: 9px;
          font-weight: 700;
        }

        .vlan-policy-row {
          min-height: 68px;
          padding: 10px 17px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          border-bottom: 1px solid #172033;
        }

        .vlan-policy-row:last-child {
          border-bottom: 0;
        }

        .vlan-policy-left {
          display: flex;
          align-items: center;
          gap: 12px;
        }

        .vlan-policy-number {
          width: 38px;
          height: 30px;
          display: flex;
          align-items: center;
          justify-content: center;
          border-radius: 5px;
          background: #172554;
          color: #60a5fa;
          font-size: 9px;
          font-weight: 800;
        }

        .vlan-policy-name {
          color: #cbd5e1;
          font-size: 11px;
          font-weight: 800;
        }

        .vlan-policy-description {
          color: #475569;
          font-size: 9px;
          margin-top: 4px;
        }

        .vlan-policy-count {
          color: #f8fafc;
          font-size: 15px;
          font-weight: 800;
        }

        .report-grid {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 12px;
        }

        .report-card {
          background: #0f172a;
          border: 1px solid #1e293b;
          border-radius: 8px;
          padding: 17px;
        }

        .report-card-title {
          color: #cbd5e1;
          font-size: 11px;
          font-weight: 800;
        }

        .report-card-value {
          color: #f8fafc;
          font-size: 25px;
          font-weight: 800;
          margin-top: 12px;
        }

        .report-card-description {
          color: #475569;
          font-size: 9px;
          line-height: 1.5;
          margin-top: 6px;
        }

        .settings-grid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 18px;
        }

        .settings-row {
          min-height: 52px;
          padding: 12px 17px;
          border-bottom: 1px solid #172033;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 15px;
          color: #64748b;
          font-size: 10px;
        }
        .report-date-row {
        min-height: 52px;
        padding: 12px 17px;
        border-bottom: 1px solid #172033;
        display: flex;
        align-items: center;
        gap: 15px;
        color: #64748b;
        font-size: 10px;
        }

        .report-date-row > label {
        min-width: 70px;
        }

        .report-date-fields {
        display: flex;
        align-items: center;
        gap: 10px;
        flex: 1;
        }

        .report-date-fields input {
        flex: 1;
        min-width: 0;
        }

        .settings-row code {
          color: #60a5fa;
          font-size: 9px;
          word-break: break-all;
          text-align: right;
        }

        .settings-status {
          display: flex;
          align-items: center;
          gap: 7px;
          color: #94a3b8;
        }

        .new-device-alert {
          position: fixed;
          top: 90px;
          right: 25px;
          width: 340px;
          background: #0f172a;
          border: 1px solid #2563eb;
          border-radius: 8px;
          box-shadow: 0 15px 45px rgba(0,0,0,.4);
          z-index: 100;
        }

        .alert-top {
          height: 3px;
          background: #2563eb;
        }

        .alert-body {
          padding: 15px;
        }

        .alert-label {
          color: #60a5fa;
          font-size: 9px;
          font-weight: 800;
        }

        .alert-title {
          color: #f8fafc;
          font-size: 13px;
          font-weight: 800;
          margin-top: 5px;
        }

        .alert-message {
          color: #64748b;
          font-size: 10px;
          line-height: 1.5;
          margin-top: 7px;
        }

        .modal-overlay {
          position: fixed;
          inset: 0;
          background: rgba(2,6,23,.78);
          backdrop-filter: blur(4px);
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 20px;
          z-index: 200;
        }

        .automation-modal {
          width: min(700px,100%);
          max-height: 90vh;
          overflow-y: auto;
          background: #0d1526;
          border: 1px solid #334155;
          border-radius: 10px;
          padding: 22px;
        }

        .automation-modal-header {
          display: flex;
          justify-content: space-between;
          gap: 20px;
          align-items: flex-start;
          padding-bottom: 18px;
          border-bottom: 1px solid #1e293b;
        }

        .automation-label {
          color: #3b82f6;
          font-size: 9px;
          font-weight: 800;
        }

        .automation-title {
          color: #f8fafc;
          font-size: 20px;
          font-weight: 800;
          margin-top: 4px;
        }

        .automation-result {
          padding: 6px 9px;
          border-radius: 4px;
          font-size: 8px;
          font-weight: 800;
        }

        .automation-result.success {
          color: #86efac;
          background: #052e16;
          border: 1px solid #166534;
        }

        .automation-result.warning {
          color: #fcd34d;
          background: #451a03;
          border: 1px solid #92400e;
        }

        .automation-device {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 12px;
          padding: 17px 0;
          border-bottom: 1px solid #1e293b;
        }

        .automation-device span,
        .automation-grid span {
          display: block;
          color: #475569;
          font-size: 8px;
          font-weight: 800;
        }

        .automation-device strong {
          display: block;
          color: #cbd5e1;
          font-size: 11px;
          margin-top: 5px;
        }

        .automation-grid {
          display: grid;
          grid-template-columns: repeat(3,1fr);
          gap: 10px;
          padding: 17px 0;
        }

        .automation-field {
          background: #0b1120;
          border: 1px solid #1e293b;
          border-radius: 5px;
          padding: 10px;
        }

        .automation-field strong {
          display: block;
          color: #cbd5e1;
          font-size: 10px;
          margin-top: 5px;
        }

        .automation-pipeline {
          border: 1px solid #1e293b;
          border-radius: 6px;
          background: #0b1120;
          padding: 13px;
          margin-bottom: 14px;
        }

        .pipeline-title {
          color: #475569;
          font-size: 8px;
          font-weight: 800;
          margin-bottom: 5px;
        }

        .pipeline-step {
          display: flex;
          align-items: center;
          gap: 10px;
          min-height: 38px;
          border-bottom: 1px solid #172033;
        }

        .pipeline-number {
          color: #3b82f6;
          font-size: 8px;
          font-weight: 800;
          width: 22px;
        }

        .pipeline-title-text {
          flex: 1;
          color: #94a3b8;
          font-size: 9px;
        }

        .pipeline-status {
          color: #86efac;
          font-size: 8px;
          font-weight: 800;
          text-transform: uppercase;
        }

        .automation-mode {
          display: flex;
          justify-content: space-between;
          padding: 11px 12px;
          background: #111c30;
          border-radius: 5px;
          margin-bottom: 14px;
        }

        .automation-mode strong {
          color: #fbbf24;
          font-size: 9px;
          text-transform: uppercase;
        }

        .loading-state,
        .empty-state {
          padding: 35px 20px;
          text-align: center;
          color: #475569;
          font-size: 11px;
        }

        @media (max-width: 1200px) {
          .stats-grid {
            grid-template-columns: repeat(3,1fr);
          }

          .vlan-card-grid,
          .report-grid {
            grid-template-columns: repeat(2,1fr);
          }
        }

        @media (max-width: 850px) {
          .sidebar {
            width: 68px;
          }

          .brand {
            justify-content: center;
            padding: 0;
          }

          .brand-mark {
            margin: 0;
          }

          .brand-text,
          .nav-section-title,
          .nav-label,
          .sidebar-footer {
            display: none;
          }

          .nav-item {
            justify-content: center;
          }

          .main {
            margin-left: 68px;
            width: calc(100% - 68px);
          }

          .dashboard-grid,
          .settings-grid {
            grid-template-columns: 1fr;
          }

          .stats-grid {
            grid-template-columns: repeat(2,1fr);
          }
        }

        @media (max-width: 600px) {
          .page {
            padding: 16px;
          }

          .topbar {
            padding: 0 16px;
          }

          .stats-grid,
          .vlan-card-grid,
          .report-grid,
          .access-summary {
            grid-template-columns: 1fr;
          }

          .page-header {
            flex-direction: column;
          }

          .automation-grid {
            grid-template-columns: 1fr 1fr;
          }

          .automation-device {
            grid-template-columns: 1fr;
          }

          .new-device-alert {
            left: 15px;
            right: 15px;
            width: auto;
          }
        }
      `}</style>

      <div className="app">
        <aside className="sidebar">
          <div className="brand">
            <div className="brand-mark">
              N
            </div>

            <div className="brand-text">
              <div className="brand-name">
                NETOPS
              </div>

              <div className="brand-subtitle">
                Network Operations
              </div>
            </div>
          </div>

          <nav className="nav">
            <div className="nav-section-title">
              OPERATIONS
            </div>

            <NavItem
              icon="D"
              label="Dashboard"
              active={
                activePage === "dashboard"
              }
              onClick={() =>
                setActivePage("dashboard")
              }
            />

            <NavItem
              icon="📡"
              label="LAN Scanner"
              active={
                activePage === "lan-scanner"
              }
              onClick={() =>
                setActivePage("lan-scanner")
              }
            />

            <NavItem
              icon="▣"
              label="Devices"
              active={
                activePage === "devices"
              }
              onClick={() => {
                setDeviceFilter("all");
                setActivePage("devices");
              }}
            />

            <NavItem
              icon="!"
              label="Events"
              active={
                activePage === "events"
              }
              onClick={() =>
                setActivePage("events")
              }
            />

            <NavItem
              icon="A"
              label="Access Control"
              active={
                activePage === "access"
              }
              onClick={() => {
                setDeviceFilter("all");
                setActivePage("access");
              }}
            />
           <NavItem
  icon="U"
  label="Endpoint Updates"
  active={
    activePage === "endpoint-updates"
  }
  onClick={() =>
    setActivePage("endpoint-updates")
  }
/>

            <div className="nav-section-title">
              AUTOMATION
            </div>

            <NavItem
              icon="V"
              label="VLAN Automation"
              active={
                activePage === "vlans"
              }
              onClick={() => {
                setVlanFilter("all");
                setActivePage("vlans");
              }}
            />

            <NavItem
              icon="R"
              label="Reports"
              active={
                activePage === "reports"
              }
              onClick={() =>
                setActivePage("reports")
              }
            />

            {isAdmin && (
              <>
                <div className="nav-section-title">
                  MANAGEMENT
                </div>

                <NavItem
                  icon="👥"
                  label="Users"
                  active={
                    activePage === "users"
                  }
                  onClick={() =>
                    setActivePage("users")
                  }
                />
              </>
            )}

            <div className="nav-section-title">
              SYSTEM
            </div>

            <NavItem
              icon="S"
              label="Settings"
              active={
                activePage === "settings"
              }
              onClick={() =>
                setActivePage("settings")
              }
            />
          </nav>

          <div className="sidebar-footer">
            <div className="system-status">
              <span className="status-dot online" />
              NETOPS online
            </div>
          </div>
        </aside>

        <main className="main">
          <header className="topbar">
            <div className="topbar-title">
              {getPageTitle(activePage)}
            </div>

            <div className="topbar-right" style={{ display: "flex", alignItems: "center", gap: "16px" }}>
              <div className="live-indicator">
                <span className="live-dot" />
                Live monitoring
              </div>

              {currentUser && (
                <div style={{ display: "flex", alignItems: "center", gap: "10px", background: "#111c33", border: "1px solid #1e293b", padding: "4px 12px 4px 6px", borderRadius: "24px" }}>
                  <div style={{ width: "26px", height: "26px", borderRadius: "50%", background: isSuperAdmin ? "linear-gradient(135deg, #d97706, #b45309)" : isAdmin ? "linear-gradient(135deg, #2563eb, #1d4ed8)" : "linear-gradient(135deg, #475569, #334155)", color: "#fff", display: "flex", alignItems: "center", justifyContent: "center", fontSize: "11px", fontWeight: "800", textTransform: "uppercase" }}>
                    {(currentUser.username || "U").slice(0, 2).toUpperCase()}
                  </div>
                  <div style={{ display: "flex", flexDirection: "column" }}>
                    <div style={{ fontSize: "12px", fontWeight: "700", color: "#f8fafc", lineHeight: 1.2 }}>
                      {currentUser.username}
                    </div>
                    <div style={{ fontSize: "10px", fontWeight: "600", color: isSuperAdmin ? "#fbbf24" : isAdmin ? "#60a5fa" : "#94a3b8" }}>
                      {isSuperAdmin ? "👑 Developer (Super Admin)" : isAdmin ? "🛡️ Administrator" : "👤 Standard User"}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={handleLogout}
                    style={{ background: "transparent", border: "none", color: "#94a3b8", fontSize: "12px", cursor: "pointer", padding: "4px 6px", borderRadius: "4px", marginLeft: "6px" }}
                    onMouseEnter={(e) => { e.currentTarget.style.color = "#f87171"; }}
                    onMouseLeave={(e) => { e.currentTarget.style.color = "#94a3b8"; }}
                    title="Sign Out of NETOPS"
                  >
                    🚪 Sign Out
                  </button>
                </div>
              )}
            </div>
          </header>

          <PageErrorBoundary>
  {renderPage()}
</PageErrorBoundary>
        </main>

        {newDeviceAlert && (
          <div className="new-device-alert">
            <div className="alert-top" />

            <div className="alert-body">
              <div className="alert-label">
                NEW DEVICE DETECTED
              </div>

              <div className="alert-title">
                Network device requires review
              </div>

              <div className="alert-message">
                {newDeviceAlert.message ||
                  "A new device was discovered on the LAN."}
              </div>

              <button
                className="primary-button small"
                style={{
                  marginTop: "11px",
                }}
                onClick={() => {
                  setDeviceFilter("pending");
                  setActivePage("devices");
                  setNewDeviceAlert(null);
                }}
              >
                Review Device
              </button>
            </div>
          </div>
        )}

        {renderAutomationResult()}
        {renderPatchModals()}
      </div>
    </>
  );
}

// ============================================================
// COMPONENTS
// ============================================================

class PageErrorBoundary extends React.Component {
  constructor(props) {
    super(props);

    this.state = {
      hasError: false,
      error: null,
    };
  }

  static getDerivedStateFromError(error) {
    return {
      hasError: true,
      error,
    };
  }

  componentDidCatch(error, errorInfo) {
    console.error(
      "NETOPS PAGE RENDER ERROR:",
      error,
      errorInfo
    );
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="page">
          <div className="panel">
            <div className="panel-title">
              NETOPS Page Error
            </div>

            <div className="panel-subtitle">
              The selected module encountered a rendering error.
            </div>

            <pre
              style={{
                marginTop: "20px",
                whiteSpace: "pre-wrap",
                color: "#ff6b6b",
                background: "#111827",
                padding: "16px",
                borderRadius: "8px",
              }}
            >
              {this.state.error?.message ||
                "Unknown React rendering error"}
            </pre>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
function NavItem({
  icon,
  label,
  active,
  onClick,
}) {
  return (
    <button
      className={
        active
          ? "nav-item active"
          : "nav-item"
      }
      onClick={onClick}
    >
      <span className="nav-icon">
        {icon}
      </span>

      <span className="nav-label">
        {label}
      </span>
    </button>
  );
}

function getPageTitle(page) {
  const titles = {
    dashboard:
      "Network Operations Dashboard",
    "lan-scanner": "LAN Device Scanner & Discovery",
    devices: "Device Management",
    events: "Network Events",
    access: "Access Control",
    "endpoint-updates": "Endpoint Updates",
    vlans: "VLAN Automation",
    reports: "Network Reports",
    users: "User Management & RBAC Access",
    settings: "System Settings",
  };

  return titles[page] || "NETOPS";
}

function TypeBadge({ type }) {
  const normalized =
    type || "unknown";

  return (
    <span
      className={`type-badge ${normalized}`}
    >
      {normalized}
    </span>
  );
}

function StatusBadge({ value }) {
  const normalized =
    value || "unknown";

  return (
    <span
      className={`status-badge ${normalized}`}
    >
      {normalized}
    </span>
  );
}

function EnforcementBadge({ value }) {
  const normalized =
    value || "unknown";

  return (
    <span
      className={`enforcement-badge ${normalized}`}
    >
      {normalized}
    </span>
  );
}

function ClassificationRow({
  label,
  icon,
  type,
  value,
}) {
  return (
    <div className="classification-row">
      <div className="classification-name">
        <span
          className={`device-icon ${type}`}
        >
          {icon}
        </span>

        {label}
      </div>

      <div className="classification-value">
        {value}
      </div>
    </div>
  );
}

function VLANMini({
  vlan,
  name,
  count,
  quarantine = false,
}) {
  return (
    <div
      className={
        quarantine
          ? "vlan-mini quarantine"
          : "vlan-mini"
      }
    >
      <div className="vlan-mini-id">
        VLAN {vlan}
      </div>

      <div className="vlan-mini-name">
        {name}
      </div>

      <div className="vlan-mini-count">
        {count} device
        {count === 1 ? "" : "s"}
      </div>
    </div>
  );
}

function FilterBar({
  label,
  count,
  active,
  clear,
}) {
  return (
    <div className="device-filter-bar">
      <span>
        Showing:{" "}
        <strong>{label}</strong>{" "}
        <span>
          ({count})
        </span>
      </span>

      {active && (
        <button
          className="clear-filter-button"
          onClick={clear}
        >
          Show All
        </button>
      )}
    </div>
  );
}

function AccessSummary({
  title,
  value,
  text,
  onClick,
}) {
  return (
    <div
      className="access-summary-card"
      role="button"
      tabIndex={0}
      onClick={onClick}
      onKeyDown={(event) => {
        if (
          event.key === "Enter" ||
          event.key === " "
        ) {
          event.preventDefault();
          onClick();
        }
      }}
    >
      <span>{title}</span>

      <strong>{value}</strong>

      <small>
        {text} →
      </small>
    </div>
  );
}

function DeviceRow({
  device,
  actionLoading,
  highlighted,
  onAction,
}) {
  return (
    <tr
      className={
        highlighted ? "highlighted" : ""
      }
    >
      <td>
        <div className="device-primary">
          {device.hostname ||
            "Unknown Device"}
        </div>

        <div className="device-secondary">
          {device.mac_address}
        </div>
      </td>

      <td>
        {device.ip_address || "-"}
      </td>

      <td>
        <TypeBadge
          type={device.device_type}
        />
      </td>

      <td>
        <StatusBadge
          value={device.status}
        />
      </td>

      <td>
        <StatusBadge
          value={device.approval_status}
        />
      </td>

      <td>
        <StatusBadge
          value={
            device.access_decision ||
            "unknown"
          }
        />
      </td>

      <td>
        <EnforcementBadge
          value={
            device.enforcement_status
          }
        />
      </td>

      <td>
        <span className="vlan-badge">
          VLAN {device.vlan_id || "-"}
        </span>
      </td>

      <td>
        <div className="action-group">
          {device.approval_status ===
            "pending" && (
            <>
              <button
                className="approve-button"
                disabled={
                  actionLoading ===
                  `approve-${device.id}`
                }
                onClick={() =>
                  onAction(
                    device.id,
                    "approve"
                  )
                }
              >
                {actionLoading ===
                `approve-${device.id}`
                  ? "Approving..."
                  : "Approve"}
              </button>

              <button
                className="reject-button"
                disabled={
                  actionLoading ===
                  `reject-${device.id}`
                }
                onClick={() =>
                  onAction(
                    device.id,
                    "reject"
                  )
                }
              >
                {actionLoading ===
                `reject-${device.id}`
                  ? "Rejecting..."
                  : "Reject"}
              </button>
            </>
          )}

          <button
            className="secondary-button small"
            disabled={
              actionLoading ===
              `enforce-${device.id}`
            }
            onClick={() =>
              onAction(
                device.id,
                "enforce"
              )
            }
          >
            {actionLoading ===
            `enforce-${device.id}`
              ? "Enforcing..."
              : "Enforce"}
          </button>

          <button
            className="primary-button small"
            disabled={
              actionLoading ===
              `automate-vlan-${device.id}`
            }
            onClick={() =>
              onAction(
                device.id,
                "automate-vlan"
              )
            }
          >
            {actionLoading ===
            `automate-vlan-${device.id}`
              ? "Running..."
              : "Auto VLAN"}
          </button>
        </div>
      </td>
    </tr>
  );
}

function VLANCard({
  vlan,
  name,
  description,
  devices,
  selected,
  quarantine,
  onClick,
}) {
  return (
    <div
      className={[
        "vlan-card",
        selected
          ? "vlan-card-selected"
          : "",
        quarantine
          ? "quarantine"
          : "",
      ].join(" ")}
      onClick={onClick}
      role="button"
      tabIndex={0}
      onKeyDown={(event) => {
        if (
          event.key === "Enter" ||
          event.key === " "
        ) {
          event.preventDefault();
          onClick();
        }
      }}
    >
      <div className="vlan-card-top">
        <div className="vlan-number">
          VLAN {vlan}
        </div>

        <div>VIEW →</div>
      </div>

      <div className="vlan-name">
        {name}
      </div>

      <div className="vlan-description">
        {description}
      </div>

      <div className="vlan-count">
        {devices.length} device
        {devices.length === 1 ? "" : "s"}
      </div>

      {devices
        .slice(0, 4)
        .map((device) => (
          <div
            className="vlan-device"
            key={device.id}
          >
            <span>
              {device.hostname ||
                "Unknown"}
            </span>

            <span>
              {device.ip_address || "-"}
            </span>
          </div>
        ))}

      <div className="vlan-card-action">
        Show VLAN {vlan} devices →
      </div>
    </div>
  );
}

function PolicyRow({
  vlan,
  name,
  description,
  count,
  quarantine,
}) {
  return (
    <div
      className="vlan-policy-row"
      style={
        quarantine
          ? {
              borderBottomColor:
                "#422006",
            }
          : undefined
      }
    >
      <div className="vlan-policy-left">
        <div className="vlan-policy-number">
          {vlan}
        </div>

        <div>
          <div className="vlan-policy-name">
            {name}
          </div>

          <div className="vlan-policy-description">
            {description}
          </div>
        </div>
      </div>

      <div className="vlan-policy-count">
        {count}
      </div>
    </div>
  );
}

function ReportCard({
  title,
  value,
  description,
onClick,
}) {
  return (

   <div
  className="report-card"
  onClick={onClick}
  style={{
    cursor: onClick ? "pointer" : "default",
  }}
>  
 <div className="report-card-title">
        {title}
      </div>

      <div className="report-card-value">
        {value}
      </div>

      <div className="report-card-description">
        {description}
      </div>
    </div>
  );
}

function EventRow({ event }) {
  const type =
    event.event_type || "event";

  let dotClass = "event-dot";


if (
  type.includes("reject") ||
  type.includes("quarantine") ||
  type.includes("unrecognized")
) {
  dotClass += " warning";
}

  if (
    type.includes("approve") ||
    type.includes("allow")
  ) {
    dotClass += " success";
  }

  return (
    <div className="event-row">
      <span className={dotClass} />

      <div className="event-content">
        <div className="event-message">
          {event.message ||
            type}
        </div>

        <div className="event-meta">
          <span>{type}</span>

          {event.device_id && (
            <span>
              Device #{event.device_id}
            </span>
          )}

          {event.created_at && (
            <span>
              {event.created_at}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

function AutomationField({
  label,
  value,
}) {
  return (
    <div className="automation-field">
      <span>{label}</span>

      <strong>
        {value || "-"}
      </strong>
    </div>
  );
}

function PipelineStep({
  number,
  title,
  status,
}) {
  return (
    <div className="pipeline-step">
      <div className="pipeline-number">
        {number}
      </div>

      <div className="pipeline-title-text">
        {title}
      </div>

      <div className="pipeline-status">
        {status}
      </div>
    </div>
  );
}

export default App;
