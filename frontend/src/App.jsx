import React, { useEffect, useState } from "react";

const API_URL =
  import.meta.env.VITE_API_URL || "/api";
const WS_URL =
  import.meta.env.VITE_WS_URL ||
  `${window.location.protocol === "https:" ? "wss:" : "ws:"}//${window.location.host}/ws/events`;

function App() {
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
    start_time: "08:00",
    end_time: "17:00",
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

  const scanLanUpdates = async () => {
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

      setScheduleForm({
        schedule_id: null,
        device_id: null,
        start_time: "08:00",
        end_time: "17:00",
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
    loadDevices();
    loadEvents();
    loadAccessSchedules();
  }, []);

  useEffect(() => {
    loadEvents();
  }, [eventTypeFilter, eventLimit, eventOffset]);

  // ------------------------------------------------------------
  // WEBSOCKET
  // ------------------------------------------------------------

  useEffect(() => {
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
            onClick={loadDevices}
            disabled={lanScanLoading}
          >
            Refresh Devices
          </button>
        </div>
      </div>

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
            Online ({devices.filter(d => d.status === "online").length})
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
                gap: "12px",
                flexWrap: "wrap",
                alignItems: "end",
              }}
            >
              <div>
                <label>Start Time</label>
                <input
                  type="time"
                  value={scheduleForm.start_time}
                  onChange={(e) =>
                    setScheduleForm({
                      ...scheduleForm,
                      start_time: e.target.value,
                    })
                  }
                />
              </div>

              <div>
                <label>End Time</label>
                <input
                  type="time"
                  value={scheduleForm.end_time}
                  onChange={(e) =>
                    setScheduleForm({
                      ...scheduleForm,
                      end_time: e.target.value,
                    })
                  }
                />
              </div>

              <div>
                <label>Days</label>
                <select
                  value={scheduleForm.days}
                  onChange={(e) =>
                    setScheduleForm({
                      ...scheduleForm,
                      days: e.target.value,
                    })
                  }
                >
                  <option value="daily">Daily</option>
                  <option value="monday">Monday</option>
                  <option value="tuesday">Tuesday</option>
                  <option value="wednesday">Wednesday</option>
                  <option value="thursday">Thursday</option>
                  <option value="friday">Friday</option>
                  <option value="saturday">Saturday</option>
                  <option value="sunday">Sunday</option>
                </select>
              </div>

              <label
                style={{
                  display: "flex",
                  gap: "6px",
                  alignItems: "center",
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

              <button
                type="button"
                className="primary-button small"
                onClick={createAccessSchedule}
                disabled={
                  scheduleLoading === scheduleForm.device_id
                }
              >
                {scheduleLoading === scheduleForm.device_id
                  ? "Saving..."
                  : "Save Schedule"}
              </button>

              <button
                type="button"
                className="secondary-button small"
                onClick={() =>
                  setScheduleForm({
                    device_id: null,
                    start_time: "08:00",
                    end_time: "17:00",
                    days: "daily",
                    enabled: true,
                  })
                }
              >
                Cancel
              </button>
            </div>
          </div>
        )}
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>DEVICE</th>
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
                  <td colSpan="9">
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

    if (deviceFilter === "needs_updates") {
      return device.update_status === "updates_available";
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
                          ⚠️ Unknown
                        </option>

                        <option value="computer">
                          💻 Computer
                        </option>

                        <option value="cctv">
                          📹 CCTV
                        </option>

                        <option value="printer">
                          🖨️ Printer
                        </option>
                      </select>
                    </td>

                    <td>
                      <span className="vlan-badge">
                        VLAN {device.vlan_id || 90}
                      </span>
                    </td>

                    <td>
                      {device.update_status === "up_to_date" ? (
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
                      ) : device.update_status === "updates_available" ? (
                        <div>
                          <span className="status-badge warning" title={`${device.pending_updates} updates pending`}>
                            ⚠️ {device.pending_updates ?? "—"} UPDATES
                          </span>
                          {device.operating_system && (
                            <div className="device-secondary" style={{ fontSize: "11px", marginTop: "3px" }}>
                              {device.operating_system} {device.os_version || ""}
                            </div>
                          )}
                        </div>
                      ) : (
                        <div>
                          <span className="status-badge offline" style={{ opacity: 0.6 }} title="No telemetry agent reporting for this LAN machine">
                            ⚪ NO AGENT
                          </span>
                        </div>
                      )}
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
                                <span className="status-badge allowed">
                                  {schedule.start_time.slice(0, 5)}
                                  {" - "}
                                  {schedule.end_time.slice(0, 5)}
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
      existingSchedule?.start_time?.slice(0, 5) ||
      "08:00",
    end_time:
      existingSchedule?.end_time?.slice(0, 5) ||
      "17:00",
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

                      <span className="vlan-badge">
                        VLAN{" "}
                        {device.vlan_id || 90}
                      </span>

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
                          <span className="vlan-badge">
                            VLAN{" "}
                            {device.vlan_id ||
                              "-"}
                          </span>
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
          </div>
        )}
      </div>
    </div>
  );
};

  // ------------------------------------------------------------
  // SETTINGS
  // ------------------------------------------------------------

  const SettingsPage = () => (
    <div className="page">
      <div className="page-header">
        <div>
          <div className="page-title">
            Settings
          </div>

          <div className="page-description">
            NETOPS platform configuration.
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
      </div>
    </div>
  );
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
              </tr>
            </thead>
            <tbody>
              {dashboardUpdatesLoading ? (
                <tr>
                  <td colSpan="7">Loading endpoint reports...</td>
                </tr>
              ) : dashboardEndpointUpdates.length === 0 ? (
                <tr>
                  <td colSpan="7">
                    No endpoint update reports available.
                  </td>
                </tr>
              ) : (
                dashboardEndpointUpdates.map((endpoint) => {
                  const checkedAt = endpoint.last_checked
                    ? new Date(`${endpoint.last_checked}Z`)
                    : null;

                  const ageMinutes = checkedAt
                    ? (Date.now() - checkedAt.getTime()) / 60000
                    : Infinity;

                  const isFresh =
                    ageMinutes >= 0 && ageMinutes <= 15;

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
                            !isFresh
                              ? "blocked"
                              : endpoint.update_status === "up_to_date"
                              ? "allowed"
                              : endpoint.update_status === "updates_available"
                              ? "warning"
                              : "blocked"
                          }`}
                        >
                          {!isFresh
                            ? "STALE / UNKNOWN"
                            : endpoint.update_status === "up_to_date"
                            ? "UP TO DATE"
                            : endpoint.update_status === "updates_available"
                            ? "NEEDS UPDATES"
                            : endpoint.update_status}
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
const endpointFreshness = (lastChecked) => {
  if (!lastChecked) {
    return "stale";
  }
const lastCheckedTime = new Date(`${lastChecked}Z`);
  const now = new Date();
console.log("FRESHNESS DEBUG:", lastChecked, new Date(lastChecked), now);
  const ageMinutes =
    (now.getTime() - lastCheckedTime.getTime()) / 60000;

  return ageMinutes <= 15
    ? "online"
    : "stale";
};  
  const freshEndpointUpdates = endpointUpdates.filter(
    (endpoint) => {
      if (!endpoint.last_checked) return false;

      const checkedAt = new Date(`${endpoint.last_checked}Z`);
      const ageMinutes = (Date.now() - checkedAt.getTime()) / 60000;

      return ageMinutes >= 0 && ageMinutes <= 15;
    }
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
              endpointFreshness(endpoint.last_checked) !== "online"
                ? "blocked"
                : endpoint.update_status === "up_to_date"
                ? "allowed"
                : endpoint.update_status === "updates_available"
                ? "warning"
                : "blocked"
            }`}
          >
            {endpointFreshness(endpoint.last_checked) !== "online"
              ? "STALE / UNKNOWN"
              : endpoint.update_status === "updates_available"
              ? "Updates Available"
              : endpoint.update_status === "up_to_date"
              ? "Up to Date"
              : endpoint.update_status}
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
                      {new Date(
                        `${endpoint.last_checked}Z`
                      ).toLocaleString()}
                    </td>

                    <td>
                      <span
                        className={`status-badge ${
                          endpointFreshness(
                            endpoint.last_checked
                          ) === "online"
                            ? "allowed"
                            : "blocked"
                        }`}
                      >
                        {endpointFreshness(
                          endpoint.last_checked
                        ) === "online"
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

      case "settings":
        return <SettingsPage />;

      default:
        return <Dashboard />;
    }
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

  return (
    <>
      <style>{`
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

            <div className="topbar-right">
              <div className="live-indicator">
                <span className="live-dot" />
                Live monitoring
              </div>
            </div>
            <div style={{position:"fixed",bottom:10,right:10,zIndex:99999,background:"#000",color:"#0f0",padding:"8px",fontSize:"12px"}}>PAGE: {activePage}</div>
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
    devices: "Device Management",
    events: "Network Events",
    access: "Access Control",
    vlans: "VLAN Automation",
    reports: "Network Reports",
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
