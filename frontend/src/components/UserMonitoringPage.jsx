import React, { useEffect, useState, useRef } from "react";

export default function UserMonitoringPage({ API_URL, currentUser, getAuthHeaders, setActivePage }) {
  const [activeTab, setActiveTab] = useState("live"); // "live", "users", "history"
  const [summary, setSummary] = useState(null);
  const [liveSessions, setLiveSessions] = useState([]);
  const [usersOverview, setUsersOverview] = useState([]);
  const [sessionsHistory, setSessionsHistory] = useState({ items: [], total: 0 });
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [errorNotice, setErrorNotice] = useState("");
  const [actionSuccessNotice, setActionSuccessNotice] = useState("");
  
  // History tab filtering
  const [historySearch, setHistorySearch] = useState("");
  const [historyFilter, setHistoryFilter] = useState("all");
  const [historyPage, setHistoryPage] = useState(0);
  const PAGE_SIZE = 25;

  // Auto-refresh control (default 10 seconds)
  const [autoRefreshInterval, setAutoRefreshInterval] = useState(10);
  const [secondsUntilRefresh, setSecondsUntilRefresh] = useState(10);
  const timerRef = useRef(null);
  const [copiedIp, setCopiedIp] = useState(null);

  const fetchSummary = async () => {
    try {
      const res = await fetch(`${API_URL}/user-monitoring/summary`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        setSummary(data);
      }
    } catch (err) {
      console.error("Failed to fetch monitoring summary:", err);
    }
  };

  const fetchLiveSessions = async () => {
    try {
      const res = await fetch(`${API_URL}/user-monitoring/live-sessions`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        setLiveSessions(data);
      }
    } catch (err) {
      console.error("Failed to fetch live sessions:", err);
    }
  };

  const fetchUsersOverview = async () => {
    try {
      const res = await fetch(`${API_URL}/user-monitoring/users-overview`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        setUsersOverview(data);
      }
    } catch (err) {
      console.error("Failed to fetch users overview:", err);
    }
  };

  const fetchHistory = async () => {
    try {
      const offset = historyPage * PAGE_SIZE;
      const q = new URLSearchParams({
        limit: PAGE_SIZE.toString(),
        offset: offset.toString(),
        status_filter: historyFilter,
      });
      if (historySearch.trim()) {
        q.append("search", historySearch.trim());
      }
      const res = await fetch(`${API_URL}/user-monitoring/sessions-history?${q.toString()}`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        setSessionsHistory(data);
      }
    } catch (err) {
      console.error("Failed to fetch sessions history:", err);
    }
  };

  const loadAllData = async (isBackground = false) => {
    if (!isBackground) setRefreshing(true);
    setErrorNotice("");
    try {
      await Promise.all([
        fetchSummary(),
        fetchLiveSessions(),
        fetchUsersOverview(),
        fetchHistory(),
      ]);
    } catch (e) {
      setErrorNotice("Could not synchronize user monitoring data.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  // Initial load
  useEffect(() => {
    loadAllData(false);
  }, []);

  // When filters or page in history changes
  useEffect(() => {
    fetchHistory();
  }, [historyPage, historyFilter, historySearch]);

  // Auto-refresh timer
  useEffect(() => {
    if (autoRefreshInterval <= 0) return;

    setSecondsUntilRefresh(autoRefreshInterval);
    const intervalId = setInterval(() => {
      setSecondsUntilRefresh((prev) => {
        if (prev <= 1) {
          loadAllData(true);
          return autoRefreshInterval;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(intervalId);
  }, [autoRefreshInterval, historyFilter, historySearch, historyPage]);

  // Terminate session action
  const handleTerminateSession = async (sessionId, username) => {
    if (!window.confirm(`Are you sure you want to forcibly terminate the active session for user '${username}'?`)) {
      return;
    }
    try {
      const res = await fetch(`${API_URL}/user-monitoring/terminate-session/${sessionId}`, {
        method: "POST",
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        setActionSuccessNotice(`Session for ${username} was terminated.`);
        setTimeout(() => setActionSuccessNotice(""), 4000);
        loadAllData(true);
      } else {
        const err = await res.json().catch(() => ({}));
        setErrorNotice(err.detail || "Failed to terminate session.");
      }
    } catch (e) {
      setErrorNotice("Network error terminating session.");
    }
  };

  const copyToClipboard = (text, id) => {
    navigator.clipboard?.writeText(text);
    setCopiedIp(id);
    setTimeout(() => setCopiedIp(null), 2000);
  };

  // Format seconds to readable duration
  const formatDuration = (seconds) => {
    if (!seconds || seconds <= 0) return "0s";
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    if (hrs > 0) return `${hrs}h ${mins}m ${secs}s`;
    if (mins > 0) return `${mins}m ${secs}s`;
    return `${secs}s`;
  };

  // Format date nicely
  const formatDate = (isoString) => {
    if (!isoString) return "Never";
    try {
      const dt = new Date(isoString);
      return dt.toLocaleString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
    } catch {
      return isoString;
    }
  };

  // Format relative time (e.g. "Just now", "2m ago")
  const formatRelativeTime = (isoString) => {
    if (!isoString) return "Never";
    try {
      const then = new Date(isoString).getTime();
      const diffSecs = Math.max(0, Math.floor((Date.now() - then) / 1000));
      if (diffSecs < 10) return "Just now";
      if (diffSecs < 60) return `${diffSecs}s ago`;
      const diffMins = Math.floor(diffSecs / 60);
      if (diffMins < 60) return `${diffMins}m ago`;
      const diffHrs = Math.floor(diffMins / 60);
      if (diffHrs < 24) return `${diffHrs}h ago`;
      const diffDays = Math.floor(diffHrs / 24);
      return `${diffDays}d ago`;
    } catch {
      return isoString;
    }
  };

  const getPageBadge = (page) => {
    const map = {
      dashboard: { label: "Dashboard", color: "#3b82f6", bg: "#eff6ff" },
      devices: { label: "Devices Inventory", color: "#059669", bg: "#ecfdf5" },
      "lan-scanner": { label: "LAN Patch Scanner", color: "#d97706", bg: "#fffbeb" },
      "endpoint-updates": { label: "Update Manager", color: "#7c3aed", bg: "#f5f3ff" },
      vlans: { label: "Switch & VLANs", color: "#2563eb", bg: "#eff6ff" },
      topology: { label: "Topology Map", color: "#0891b2", bg: "#ecfeff" },
      reports: { label: "Audit Reports", color: "#4f46e5", bg: "#eef2ff" },
      users: { label: "User Management", color: "#ea580c", bg: "#fff7ed" },
      monitoring: { label: "Developer Monitor", color: "#0284c7", bg: "#f0f9ff" },
      settings: { label: "System Settings", color: "#475569", bg: "#f1f5f9" },
      access: { label: "Access Control", color: "#b91c1c", bg: "#fef2f2" },
      events: { label: "Security Events", color: "#dc2626", bg: "#fef2f2" },
    };
    const item = map[page] || { label: page || "Browsing", color: "#64748b", bg: "#f8fafc" };
    return (
      <span
        style={{
          display: "inline-block",
          padding: "3px 8px",
          borderRadius: "12px",
          fontSize: "11px",
          fontWeight: 600,
          background: item.bg,
          color: item.color,
          border: `1px solid ${item.color}30`,
        }}
      >
        📄 {item.label}
      </span>
    );
  };

  return (
    <div className="page-container" style={{ padding: "20px 24px", color: "#1e293b" }}>
      {/* HEADER BAR */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "16px",
          marginBottom: "20px",
          paddingBottom: "16px",
          borderBottom: "1px solid #e2e8f0",
        }}
      >
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <h1 style={{ fontSize: "22px", fontWeight: "800", margin: 0, color: "#0f172a" }}>
              📡 Developer User Monitor &amp; Live Activity
            </h1>
            <span
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "5px",
                padding: "2px 8px",
                borderRadius: "12px",
                fontSize: "11px",
                fontWeight: "700",
                background: summary?.online_users_count > 0 ? "#ecfdf5" : "#f1f5f9",
                color: summary?.online_users_count > 0 ? "#047857" : "#64748b",
                border: summary?.online_users_count > 0 ? "1px solid #a7f3d0" : "1px solid #cbd5e1",
              }}
            >
              <span
                style={{
                  width: "7px",
                  height: "7px",
                  borderRadius: "50%",
                  background: summary?.online_users_count > 0 ? "#10b981" : "#94a3b8",
                  boxShadow: summary?.online_users_count > 0 ? "0 0 6px #10b981" : "none",
                }}
              />
              {summary?.online_users_count || 0} Online
            </span>
          </div>
          <p style={{ margin: "4px 0 0 0", fontSize: "13px", color: "#64748b" }}>
            Real-time tracking of active user sessions, login/logout events, client IPs, devices, and first/last seen lifecycles.
          </p>
        </div>

        {/* CONTROLS */}
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          {/* Auto Refresh selector */}
          <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "12px", color: "#475569" }}>
            <span>Auto-Refresh:</span>
            <select
              value={autoRefreshInterval}
              onChange={(e) => setAutoRefreshInterval(Number(e.target.value))}
              style={{
                padding: "4px 8px",
                borderRadius: "6px",
                border: "1px solid #cbd5e1",
                background: "#fff",
                fontSize: "12px",
                fontWeight: "600",
                color: "#1e293b",
                cursor: "pointer",
              }}
            >
              <option value="5">Every 5s</option>
              <option value="10">Every 10s</option>
              <option value="30">Every 30s</option>
              <option value="0">Paused</option>
            </select>
            {autoRefreshInterval > 0 && (
              <span style={{ fontSize: "11px", color: "#94a3b8", minWidth: "32px" }}>
                ({secondsUntilRefresh}s)
              </span>
            )}
          </div>

          <button
            type="button"
            onClick={() => loadAllData(false)}
            disabled={refreshing}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "6px",
              padding: "6px 14px",
              borderRadius: "8px",
              border: "1px solid #cbd5e1",
              background: refreshing ? "#f1f5f9" : "#fff",
              color: "#1e293b",
              fontSize: "12px",
              fontWeight: "700",
              cursor: refreshing ? "not-allowed" : "pointer",
              boxShadow: "0 1px 2px rgba(0,0,0,0.05)",
            }}
          >
            <span style={{ transform: refreshing ? "rotate(180deg)" : "none", transition: "transform 0.5s" }}>🔄</span>
            {refreshing ? "Updating..." : "Sync Now"}
          </button>
        </div>
      </div>

      {/* NOTICES */}
      {actionSuccessNotice && (
        <div
          style={{
            marginBottom: "16px",
            padding: "10px 14px",
            borderRadius: "8px",
            background: "#ecfdf5",
            border: "1px solid #a7f3d0",
            color: "#065f46",
            fontSize: "13px",
            fontWeight: "600",
          }}
        >
          ✓ {actionSuccessNotice}
        </div>
      )}
      {errorNotice && (
        <div
          style={{
            marginBottom: "16px",
            padding: "10px 14px",
            borderRadius: "8px",
            background: "#fef2f2",
            border: "1px solid #fecaca",
            color: "#991b1b",
            fontSize: "13px",
            fontWeight: "600",
          }}
        >
          ⚠️ {errorNotice}
        </div>
      )}

      {/* TOP STAT CARDS */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
          gap: "16px",
          marginBottom: "24px",
        }}
      >
        {/* Card 1: Online Now */}
        <div
          style={{
            background: "#ffffff",
            borderRadius: "12px",
            padding: "18px 20px",
            border: "1px solid #e2e8f0",
            boxShadow: "0 2px 4px rgba(0,0,0,0.02)",
            position: "relative",
            overflow: "hidden",
          }}
        >
          <div style={{ position: "absolute", top: 0, left: 0, width: "4px", height: "100%", background: "#10b981" }} />
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "12px", fontWeight: "700", textTransform: "uppercase", color: "#64748b" }}>
              Online Right Now
            </span>
            <span style={{ fontSize: "18px" }}>🟢</span>
          </div>
          <div style={{ fontSize: "28px", fontWeight: "800", color: "#0f172a", marginTop: "8px" }}>
            {summary?.online_users_count ?? 0}
          </div>
          <div style={{ fontSize: "12px", color: "#10b981", fontWeight: "600", marginTop: "4px" }}>
            Active within past 3 minutes
          </div>
        </div>

        {/* Card 2: Registered Users */}
        <div
          style={{
            background: "#ffffff",
            borderRadius: "12px",
            padding: "18px 20px",
            border: "1px solid #e2e8f0",
            boxShadow: "0 2px 4px rgba(0,0,0,0.02)",
            position: "relative",
            overflow: "hidden",
          }}
        >
          <div style={{ position: "absolute", top: 0, left: 0, width: "4px", height: "100%", background: "#3b82f6" }} />
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "12px", fontWeight: "700", textTransform: "uppercase", color: "#64748b" }}>
              Total Users
            </span>
            <span style={{ fontSize: "18px" }}>👥</span>
          </div>
          <div style={{ fontSize: "28px", fontWeight: "800", color: "#0f172a", marginTop: "8px" }}>
            {summary?.total_registered_users ?? 0}
          </div>
          <div style={{ fontSize: "12px", color: "#64748b", marginTop: "4px" }}>
            Registered platform accounts
          </div>
        </div>

        {/* Card 3: Active Today */}
        <div
          style={{
            background: "#ffffff",
            borderRadius: "12px",
            padding: "18px 20px",
            border: "1px solid #e2e8f0",
            boxShadow: "0 2px 4px rgba(0,0,0,0.02)",
            position: "relative",
            overflow: "hidden",
          }}
        >
          <div style={{ position: "absolute", top: 0, left: 0, width: "4px", height: "100%", background: "#f59e0b" }} />
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "12px", fontWeight: "700", textTransform: "uppercase", color: "#64748b" }}>
              Active Today
            </span>
            <span style={{ fontSize: "18px" }}>📅</span>
          </div>
          <div style={{ fontSize: "28px", fontWeight: "800", color: "#0f172a", marginTop: "8px" }}>
            {summary?.unique_users_today ?? 0}
          </div>
          <div style={{ fontSize: "12px", color: "#64748b", marginTop: "4px" }}>
            {summary?.sessions_today_count ?? 0} session{summary?.sessions_today_count === 1 ? "" : "s"} initiated today
          </div>
        </div>

        {/* Card 4: Total Sessions */}
        <div
          style={{
            background: "#ffffff",
            borderRadius: "12px",
            padding: "18px 20px",
            border: "1px solid #e2e8f0",
            boxShadow: "0 2px 4px rgba(0,0,0,0.02)",
            position: "relative",
            overflow: "hidden",
          }}
        >
          <div style={{ position: "absolute", top: 0, left: 0, width: "4px", height: "100%", background: "#8b5cf6" }} />
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "12px", fontWeight: "700", textTransform: "uppercase", color: "#64748b" }}>
              Total Logins / Sessions
            </span>
            <span style={{ fontSize: "18px" }}>📜</span>
          </div>
          <div style={{ fontSize: "28px", fontWeight: "800", color: "#0f172a", marginTop: "8px" }}>
            {summary?.total_sessions_all_time ?? 0}
          </div>
          <div style={{ fontSize: "12px", color: "#64748b", marginTop: "4px" }}>
            All-time access history records
          </div>
        </div>
      </div>

      {/* NAVIGATION TABS */}
      <div
        style={{
          display: "flex",
          borderBottom: "1px solid #e2e8f0",
          marginBottom: "20px",
          gap: "8px",
        }}
      >
        <button
          type="button"
          onClick={() => setActiveTab("live")}
          style={{
            padding: "10px 18px",
            background: "none",
            border: "none",
            borderBottom: activeTab === "live" ? "3px solid #2563eb" : "3px solid transparent",
            color: activeTab === "live" ? "#2563eb" : "#64748b",
            fontSize: "14px",
            fontWeight: "700",
            cursor: "pointer",
            display: "inline-flex",
            alignItems: "center",
            gap: "8px",
          }}
        >
          <span>🟢 Live Online Sessions</span>
          <span
            style={{
              background: activeTab === "live" ? "#dbeafe" : "#f1f5f9",
              color: activeTab === "live" ? "#1e40af" : "#64748b",
              fontSize: "11px",
              padding: "2px 6px",
              borderRadius: "10px",
            }}
          >
            {liveSessions.length}
          </span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab("users")}
          style={{
            padding: "10px 18px",
            background: "none",
            border: "none",
            borderBottom: activeTab === "users" ? "3px solid #2563eb" : "3px solid transparent",
            color: activeTab === "users" ? "#2563eb" : "#64748b",
            fontSize: "14px",
            fontWeight: "700",
            cursor: "pointer",
            display: "inline-flex",
            alignItems: "center",
            gap: "8px",
          }}
        >
          <span>👥 User Directory &amp; Lifecycle</span>
          <span
            style={{
              background: activeTab === "users" ? "#dbeafe" : "#f1f5f9",
              color: activeTab === "users" ? "#1e40af" : "#64748b",
              fontSize: "11px",
              padding: "2px 6px",
              borderRadius: "10px",
            }}
          >
            {usersOverview.length}
          </span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab("history")}
          style={{
            padding: "10px 18px",
            background: "none",
            border: "none",
            borderBottom: activeTab === "history" ? "3px solid #2563eb" : "3px solid transparent",
            color: activeTab === "history" ? "#2563eb" : "#64748b",
            fontSize: "14px",
            fontWeight: "700",
            cursor: "pointer",
            display: "inline-flex",
            alignItems: "center",
            gap: "8px",
          }}
        >
          <span>📜 Login &amp; Logout History Log</span>
          <span
            style={{
              background: activeTab === "history" ? "#dbeafe" : "#f1f5f9",
              color: activeTab === "history" ? "#1e40af" : "#64748b",
              fontSize: "11px",
              padding: "2px 6px",
              borderRadius: "10px",
            }}
          >
            {sessionsHistory.total}
          </span>
        </button>
      </div>

      {/* TAB 1: LIVE ONLINE SESSIONS */}
      {activeTab === "live" && (
        <div style={{ background: "#fff", borderRadius: "12px", border: "1px solid #e2e8f0", overflow: "hidden" }}>
          <div
            style={{
              padding: "16px 20px",
              background: "#f8fafc",
              borderBottom: "1px solid #e2e8f0",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <div>
              <h3 style={{ margin: 0, fontSize: "15px", fontWeight: "700", color: "#0f172a" }}>
                Active Users Currently Online
              </h3>
              <p style={{ margin: "2px 0 0 0", fontSize: "12px", color: "#64748b" }}>
                Users actively interacting with your hosted NETOPS deployment right now.
              </p>
            </div>
            <span style={{ fontSize: "12px", color: "#64748b" }}>
              Auto-updating every {autoRefreshInterval}s
            </span>
          </div>

          {liveSessions.length === 0 ? (
            <div style={{ padding: "48px 24px", textAlign: "center", color: "#64748b" }}>
              <div style={{ fontSize: "36px", marginBottom: "8px" }}>💤</div>
              <div style={{ fontSize: "15px", fontWeight: "600", color: "#334155" }}>
                No external users are actively browsing right now.
              </div>
              <div style={{ fontSize: "13px", color: "#94a3b8", marginTop: "4px" }}>
                When users or admins log into your hosted URL, they will appear here live with their location and active page.
              </div>
            </div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px" }}>
                <thead>
                  <tr style={{ background: "#f8fafc", borderBottom: "1px solid #e2e8f0", textAlign: "left" }}>
                    <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>User</th>
                    <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>Role</th>
                    <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>Current Screen</th>
                    <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>Client IP</th>
                    <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>Device &amp; Browser</th>
                    <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>Logged In</th>
                    <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>Time Online</th>
                    <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>Last Seen</th>
                    <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700", textAlign: "right" }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {liveSessions.map((s) => (
                    <tr
                      key={s.session_id}
                      style={{
                        borderBottom: "1px solid #f1f5f9",
                        transition: "background 0.15s",
                      }}
                      onMouseEnter={(e) => { e.currentTarget.style.background = "#f8fafc"; }}
                      onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                    >
                      {/* User */}
                      <td style={{ padding: "14px 16px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                          <div
                            style={{
                              width: "32px",
                              height: "32px",
                              borderRadius: "50%",
                              background: s.role === "super_admin" ? "#d97706" : s.role === "admin" ? "#2563eb" : "#475569",
                              color: "#fff",
                              display: "flex",
                              alignItems: "center",
                              justifyContent: "center",
                              fontWeight: "700",
                              fontSize: "12px",
                            }}
                          >
                            {(s.username || "U").slice(0, 2).toUpperCase()}
                          </div>
                          <div>
                            <div style={{ fontWeight: "700", color: "#0f172a" }}>{s.username}</div>
                            {s.email && <div style={{ fontSize: "11px", color: "#64748b" }}>{s.email}</div>}
                          </div>
                        </div>
                      </td>

                      {/* Role */}
                      <td style={{ padding: "14px 16px" }}>
                        <span
                          style={{
                            padding: "3px 8px",
                            borderRadius: "12px",
                            fontSize: "11px",
                            fontWeight: "700",
                            textTransform: "uppercase",
                            background: s.role === "super_admin" ? "#fef3c7" : s.role === "admin" ? "#eff6ff" : "#f1f5f9",
                            color: s.role === "super_admin" ? "#b45309" : s.role === "admin" ? "#1e40af" : "#475569",
                          }}
                        >
                          {s.role}
                        </span>
                      </td>

                      {/* Current Page */}
                      <td style={{ padding: "14px 16px" }}>
                        {getPageBadge(s.current_page)}
                      </td>

                      {/* IP */}
                      <td style={{ padding: "14px 16px" }}>
                        <div style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}>
                          <code style={{ fontSize: "12px", background: "#f1f5f9", padding: "2px 6px", borderRadius: "4px" }}>
                            {s.ip_address}
                          </code>
                          <button
                            type="button"
                            onClick={() => copyToClipboard(s.ip_address, s.session_id)}
                            style={{
                              background: "none",
                              border: "none",
                              cursor: "pointer",
                              fontSize: "11px",
                              color: copiedIp === s.session_id ? "#10b981" : "#94a3b8",
                            }}
                            title="Copy IP"
                          >
                            {copiedIp === s.session_id ? "✓" : "📋"}
                          </button>
                        </div>
                      </td>

                      {/* Device & Browser */}
                      <td style={{ padding: "14px 16px" }}>
                        <div style={{ fontWeight: "600", color: "#334155" }}>
                          {s.device?.summary || "Standard Browser"}
                        </div>
                        <div style={{ fontSize: "11px", color: "#94a3b8" }}>
                          {s.device?.device || "Desktop"} Client
                        </div>
                      </td>

                      {/* Login Time */}
                      <td style={{ padding: "14px 16px", color: "#475569" }}>
                        <div>{formatDate(s.login_at)}</div>
                        <div style={{ fontSize: "11px", color: "#94a3b8" }}>{formatRelativeTime(s.login_at)}</div>
                      </td>

                      {/* Duration */}
                      <td style={{ padding: "14px 16px" }}>
                        <span style={{ fontWeight: "700", color: "#0f172a" }}>
                          ⏱️ {formatDuration(s.duration_seconds)}
                        </span>
                      </td>

                      {/* Last Seen */}
                      <td style={{ padding: "14px 16px" }}>
                        <span
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: "5px",
                            fontWeight: "600",
                            color: s.is_online ? "#059669" : "#d97706",
                          }}
                        >
                          <span
                            style={{
                              width: "6px",
                              height: "6px",
                              borderRadius: "50%",
                              background: s.is_online ? "#10b981" : "#f59e0b",
                            }}
                          />
                          {formatRelativeTime(s.last_activity_at)}
                        </span>
                      </td>

                      {/* Action */}
                      <td style={{ padding: "14px 16px", textAlign: "right" }}>
                        <button
                          type="button"
                          onClick={() => handleTerminateSession(s.session_id, s.username)}
                          style={{
                            background: "#fee2e2",
                            border: "1px solid #fecaca",
                            color: "#b91c1c",
                            padding: "4px 10px",
                            borderRadius: "6px",
                            fontSize: "12px",
                            fontWeight: "700",
                            cursor: "pointer",
                          }}
                          title="Force terminate user session"
                        >
                          🚪 Disconnect
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* TAB 2: USER DIRECTORY & LIFECYCLE (FIRST SEEN / LAST SEEN) */}
      {activeTab === "users" && (
        <div style={{ background: "#fff", borderRadius: "12px", border: "1px solid #e2e8f0", overflow: "hidden" }}>
          <div
            style={{
              padding: "16px 20px",
              background: "#f8fafc",
              borderBottom: "1px solid #e2e8f0",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <div>
              <h3 style={{ margin: 0, fontSize: "15px", fontWeight: "700", color: "#0f172a" }}>
                User Activity Directory (First Seen &amp; Last Seen)
              </h3>
              <p style={{ margin: "2px 0 0 0", fontSize: "12px", color: "#64748b" }}>
                Historical summary for each user: account creation, first logged in, last seen, total visits, and total time spent.
              </p>
            </div>
          </div>

          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px" }}>
              <thead>
                <tr style={{ background: "#f8fafc", borderBottom: "1px solid #e2e8f0", textAlign: "left" }}>
                  <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>User</th>
                  <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>Role</th>
                  <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>Status</th>
                  <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>First Seen</th>
                  <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>Last Seen</th>
                  <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>Last Known IP</th>
                  <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>Last Device</th>
                  <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>Total Logins</th>
                  <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>Total Time Spent</th>
                </tr>
              </thead>
              <tbody>
                {usersOverview.map((u) => (
                  <tr
                    key={u.user_id}
                    style={{
                      borderBottom: "1px solid #f1f5f9",
                      transition: "background 0.15s",
                    }}
                    onMouseEnter={(e) => { e.currentTarget.style.background = "#f8fafc"; }}
                    onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                  >
                    {/* User */}
                    <td style={{ padding: "14px 16px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                        <div
                          style={{
                            width: "32px",
                            height: "32px",
                            borderRadius: "50%",
                            background: u.role === "super_admin" ? "#d97706" : u.role === "admin" ? "#2563eb" : "#475569",
                            color: "#fff",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            fontWeight: "700",
                            fontSize: "12px",
                          }}
                        >
                          {(u.username || "U").slice(0, 2).toUpperCase()}
                        </div>
                        <div>
                          <div style={{ fontWeight: "700", color: "#0f172a" }}>{u.username}</div>
                          <div style={{ fontSize: "11px", color: "#64748b" }}>{u.email}</div>
                        </div>
                      </div>
                    </td>

                    {/* Role */}
                    <td style={{ padding: "14px 16px" }}>
                      <span
                        style={{
                          padding: "3px 8px",
                          borderRadius: "12px",
                          fontSize: "11px",
                          fontWeight: "700",
                          textTransform: "uppercase",
                          background: u.role === "super_admin" ? "#fef3c7" : u.role === "admin" ? "#eff6ff" : "#f1f5f9",
                          color: u.role === "super_admin" ? "#b45309" : u.role === "admin" ? "#1e40af" : "#475569",
                        }}
                      >
                        {u.role}
                      </span>
                    </td>

                    {/* Status */}
                    <td style={{ padding: "14px 16px" }}>
                      {u.is_online ? (
                        <span
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: "5px",
                            padding: "3px 8px",
                            borderRadius: "12px",
                            fontSize: "11px",
                            fontWeight: "700",
                            background: "#ecfdf5",
                            color: "#059669",
                          }}
                        >
                          <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: "#10b981" }} />
                          Online
                        </span>
                      ) : (
                        <span
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: "5px",
                            padding: "3px 8px",
                            borderRadius: "12px",
                            fontSize: "11px",
                            fontWeight: "600",
                            background: "#f1f5f9",
                            color: "#64748b",
                          }}
                        >
                          <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: "#cbd5e1" }} />
                          Offline
                        </span>
                      )}
                    </td>

                    {/* First Seen */}
                    <td style={{ padding: "14px 16px", color: "#475569" }}>
                      <div>{formatDate(u.first_seen)}</div>
                      <div style={{ fontSize: "11px", color: "#94a3b8" }}>{formatRelativeTime(u.first_seen)}</div>
                    </td>

                    {/* Last Seen */}
                    <td style={{ padding: "14px 16px", color: "#475569" }}>
                      <div style={{ fontWeight: u.is_online ? "700" : "normal", color: u.is_online ? "#059669" : "#475569" }}>
                        {formatDate(u.last_seen)}
                      </div>
                      <div style={{ fontSize: "11px", color: "#94a3b8" }}>{formatRelativeTime(u.last_seen)}</div>
                    </td>

                    {/* Last Known IP */}
                    <td style={{ padding: "14px 16px" }}>
                      <code style={{ fontSize: "12px", background: "#f1f5f9", padding: "2px 6px", borderRadius: "4px" }}>
                        {u.last_ip}
                      </code>
                    </td>

                    {/* Last Device */}
                    <td style={{ padding: "14px 16px", color: "#475569", fontSize: "12px" }}>
                      {u.last_device?.summary || "—"}
                    </td>

                    {/* Total Logins */}
                    <td style={{ padding: "14px 16px" }}>
                      <span
                        style={{
                          background: "#eff6ff",
                          color: "#1d4ed8",
                          fontWeight: "700",
                          padding: "2px 8px",
                          borderRadius: "10px",
                          fontSize: "12px",
                        }}
                      >
                        {u.total_sessions} login{u.total_sessions === 1 ? "" : "s"}
                      </span>
                    </td>

                    {/* Total Duration */}
                    <td style={{ padding: "14px 16px", fontWeight: "600", color: "#0f172a" }}>
                      ⏱️ {formatDuration(u.total_duration_seconds)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 3: LOGIN & LOGOUT HISTORY LOG */}
      {activeTab === "history" && (
        <div style={{ background: "#fff", borderRadius: "12px", border: "1px solid #e2e8f0", overflow: "hidden" }}>
          {/* SEARCH & FILTER CONTROLS */}
          <div
            style={{
              padding: "16px 20px",
              background: "#f8fafc",
              borderBottom: "1px solid #e2e8f0",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: "12px",
            }}
          >
            <div>
              <h3 style={{ margin: 0, fontSize: "15px", fontWeight: "700", color: "#0f172a" }}>
                Access Sessions Audit Trail
              </h3>
              <p style={{ margin: "2px 0 0 0", fontSize: "12px", color: "#64748b" }}>
                Every single login, logout timestamp, session length, and IP recorded by the system.
              </p>
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
              {/* Search */}
              <input
                type="text"
                placeholder="Search username, IP, email..."
                value={historySearch}
                onChange={(e) => {
                  setHistorySearch(e.target.value);
                  setHistoryPage(0);
                }}
                style={{
                  padding: "6px 12px",
                  borderRadius: "6px",
                  border: "1px solid #cbd5e1",
                  fontSize: "12px",
                  minWidth: "220px",
                }}
              />

              {/* Status filter */}
              <select
                value={historyFilter}
                onChange={(e) => {
                  setHistoryFilter(e.target.value);
                  setHistoryPage(0);
                }}
                style={{
                  padding: "6px 10px",
                  borderRadius: "6px",
                  border: "1px solid #cbd5e1",
                  background: "#fff",
                  fontSize: "12px",
                  fontWeight: "600",
                }}
              >
                <option value="all">All Sessions</option>
                <option value="online">Online Right Now</option>
                <option value="active">Active Sessions</option>
                <option value="ended">Logged Out / Ended</option>
              </select>
            </div>
          </div>

          {sessionsHistory.items.length === 0 ? (
            <div style={{ padding: "48px 24px", textAlign: "center", color: "#64748b" }}>
              No session records found matching your filters.
            </div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px" }}>
                <thead>
                  <tr style={{ background: "#f8fafc", borderBottom: "1px solid #e2e8f0", textAlign: "left" }}>
                    <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>ID</th>
                    <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>User</th>
                    <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>Role</th>
                    <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>Status</th>
                    <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>Logged In</th>
                    <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>Logged Out</th>
                    <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>Duration</th>
                    <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>Client IP</th>
                    <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700" }}>Device &amp; Browser</th>
                    <th style={{ padding: "12px 16px", color: "#64748b", fontWeight: "700", textAlign: "right" }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {sessionsHistory.items.map((s) => (
                    <tr
                      key={s.session_id}
                      style={{
                        borderBottom: "1px solid #f1f5f9",
                        transition: "background 0.15s",
                      }}
                      onMouseEnter={(e) => { e.currentTarget.style.background = "#f8fafc"; }}
                      onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                    >
                      <td style={{ padding: "12px 16px", color: "#94a3b8", fontSize: "12px" }}>
                        #{s.session_id}
                      </td>

                      {/* User */}
                      <td style={{ padding: "12px 16px", fontWeight: "700", color: "#0f172a" }}>
                        <div>{s.username}</div>
                        {s.email && <div style={{ fontSize: "11px", color: "#64748b", fontWeight: "normal" }}>{s.email}</div>}
                      </td>

                      {/* Role */}
                      <td style={{ padding: "12px 16px" }}>
                        <span
                          style={{
                            padding: "2px 6px",
                            borderRadius: "10px",
                            fontSize: "10px",
                            fontWeight: "700",
                            textTransform: "uppercase",
                            background: s.role === "super_admin" ? "#fef3c7" : s.role === "admin" ? "#eff6ff" : "#f1f5f9",
                            color: s.role === "super_admin" ? "#b45309" : s.role === "admin" ? "#1e40af" : "#475569",
                          }}
                        >
                          {s.role}
                        </span>
                      </td>

                      {/* Status */}
                      <td style={{ padding: "12px 16px" }}>
                        {s.is_online ? (
                          <span style={{ color: "#059669", fontWeight: "700", fontSize: "12px" }}>🟢 Online</span>
                        ) : s.is_active ? (
                          <span style={{ color: "#d97706", fontWeight: "600", fontSize: "12px" }}>🟡 Active (Idle)</span>
                        ) : (
                          <span style={{ color: "#64748b", fontSize: "12px" }}>⚪ Ended</span>
                        )}
                      </td>

                      {/* Logged in */}
                      <td style={{ padding: "12px 16px", color: "#475569" }}>
                        <div>{formatDate(s.login_at)}</div>
                        <div style={{ fontSize: "11px", color: "#94a3b8" }}>{formatRelativeTime(s.login_at)}</div>
                      </td>

                      {/* Logged out */}
                      <td style={{ padding: "12px 16px", color: "#475569" }}>
                        {s.logout_at ? (
                          <>
                            <div>{formatDate(s.logout_at)}</div>
                            <div style={{ fontSize: "11px", color: "#94a3b8" }}>{formatRelativeTime(s.logout_at)}</div>
                          </>
                        ) : (
                          <span style={{ color: "#10b981", fontWeight: "600", fontSize: "12px" }}>
                            — Still Active
                          </span>
                        )}
                      </td>

                      {/* Duration */}
                      <td style={{ padding: "12px 16px", fontWeight: "700", color: "#0f172a" }}>
                        {formatDuration(s.duration_seconds)}
                      </td>

                      {/* IP */}
                      <td style={{ padding: "12px 16px" }}>
                        <code style={{ fontSize: "12px", background: "#f1f5f9", padding: "2px 6px", borderRadius: "4px" }}>
                          {s.ip_address}
                        </code>
                      </td>

                      {/* Device & Browser */}
                      <td style={{ padding: "12px 16px", color: "#475569", fontSize: "12px" }}>
                        {s.device?.summary || "Standard Client"}
                      </td>

                      {/* Action */}
                      <td style={{ padding: "12px 16px", textAlign: "right" }}>
                        {s.is_active ? (
                          <button
                            type="button"
                            onClick={() => handleTerminateSession(s.session_id, s.username)}
                            style={{
                              background: "#fee2e2",
                              border: "1px solid #fecaca",
                              color: "#b91c1c",
                              padding: "3px 8px",
                              borderRadius: "6px",
                              fontSize: "11px",
                              fontWeight: "700",
                              cursor: "pointer",
                            }}
                          >
                            Terminate
                          </button>
                        ) : (
                          <span style={{ color: "#cbd5e1", fontSize: "12px" }}>Closed</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {/* PAGINATION */}
              <div
                style={{
                  padding: "12px 20px",
                  background: "#f8fafc",
                  borderTop: "1px solid #e2e8f0",
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  fontSize: "12px",
                  color: "#64748b",
                }}
              >
                <span>
                  Showing {sessionsHistory.items.length} of {sessionsHistory.total} total recorded sessions
                </span>
                <div style={{ display: "flex", gap: "8px" }}>
                  <button
                    type="button"
                    disabled={historyPage === 0}
                    onClick={() => setHistoryPage((p) => Math.max(0, p - 1))}
                    style={{
                      padding: "4px 10px",
                      borderRadius: "6px",
                      border: "1px solid #cbd5e1",
                      background: historyPage === 0 ? "#f1f5f9" : "#fff",
                      color: historyPage === 0 ? "#94a3b8" : "#1e293b",
                      cursor: historyPage === 0 ? "not-allowed" : "pointer",
                    }}
                  >
                    Previous
                  </button>
                  <span style={{ display: "flex", alignItems: "center", padding: "0 8px", fontWeight: "600" }}>
                    Page {historyPage + 1} of {Math.ceil(sessionsHistory.total / PAGE_SIZE) || 1}
                  </span>
                  <button
                    type="button"
                    disabled={(historyPage + 1) * PAGE_SIZE >= sessionsHistory.total}
                    onClick={() => setHistoryPage((p) => p + 1)}
                    style={{
                      padding: "4px 10px",
                      borderRadius: "6px",
                      border: "1px solid #cbd5e1",
                      background: (historyPage + 1) * PAGE_SIZE >= sessionsHistory.total ? "#f1f5f9" : "#fff",
                      color: (historyPage + 1) * PAGE_SIZE >= sessionsHistory.total ? "#94a3b8" : "#1e293b",
                      cursor: (historyPage + 1) * PAGE_SIZE >= sessionsHistory.total ? "not-allowed" : "pointer",
                    }}
                  >
                    Next
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
