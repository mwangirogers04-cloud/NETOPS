import React, { useEffect, useState, useRef } from "react";

export default function WebActivityPage({
  API_URL,
  currentUser,
  getAuthHeaders,
  setActivePage,
}) {
  const [logs, setLogs] = useState([]);
  const [activeSessions, setActiveSessions] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [policy, setPolicy] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [violationsOnly, setViolationsOnly] = useState(false);
  const [timeRange, setTimeRange] = useState("live"); // 'live' (<5m), '15m', '1h', '24h', 'all'
  const [searchQuery, setSearchQuery] = useState("");
  const [showPolicyModal, setShowPolicyModal] = useState(false);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [policyNotice, setPolicyNotice] = useState("");
  const [autoRefreshSecs, setAutoRefreshSecs] = useState(5);
  const [lastRefreshedAt, setLastRefreshedAt] = useState(new Date());
  const [clearingHistory, setClearingHistory] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [viewMode, setViewMode] = useState("grouped"); // 'grouped' (one card per machine) or 'flat'

  // Scan all connected endpoints for browsing and DNS activity
  const handleScanWebActivity = async () => {
    setScanning(true);
    try {
      await fetch(`${API_URL}/web-activity/trigger-scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...getAuthHeaders() },
      });
      await Promise.all([fetchActiveSessions(), fetchLogs(), fetchAnalytics()]);
      setLastRefreshedAt(new Date());
    } catch (err) {
      console.error("Error triggering web activity scan:", err);
    } finally {
      setScanning(false);
    }
  };

  // Fetch active sessions (devices communicating in the last 5 minutes)
  const fetchActiveSessions = async () => {
    try {
      const res = await fetch(`${API_URL}/web-activity/active-sessions?minutes=5`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        setActiveSessions(data);
      }
    } catch (err) {
      console.error("Error fetching active web sessions:", err);
    }
  };

  // Fetch activity logs with time filter
  const fetchLogs = async () => {
    try {
      let url = `${API_URL}/web-activity/logs?limit=150`;
      if (timeRange === "live") {
        url += `&minutes=5`;
      } else if (timeRange === "15m") {
        url += `&minutes=15`;
      } else if (timeRange === "1h") {
        url += `&minutes=60`;
      } else if (timeRange === "24h") {
        url += `&minutes=1440`;
      }

      if (categoryFilter !== "all") {
        url += `&category=${categoryFilter}`;
      }
      if (violationsOnly) {
        url += `&violations_only=true`;
      }
      const res = await fetch(url, { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setLogs(data);
      }
    } catch (err) {
      console.error("Error fetching web activity logs:", err);
    }
  };

  // Fetch summary analytics
  const fetchAnalytics = async () => {
    try {
      const res = await fetch(`${API_URL}/web-activity/analytics?hours=24`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        setAnalytics(data);
      }
    } catch (err) {
      console.error("Error fetching web analytics:", err);
    }
  };

  // Fetch policy
  const fetchPolicy = async () => {
    try {
      const res = await fetch(`${API_URL}/web-activity/policy`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        setPolicy(data);
      }
    } catch (err) {
      console.error("Error fetching web policy:", err);
    }
  };

  const loadAll = async () => {
    setRefreshing(true);
    await Promise.all([fetchActiveSessions(), fetchLogs(), fetchAnalytics(), fetchPolicy()]);
    setLastRefreshedAt(new Date());
    setLoading(false);
    setRefreshing(false);
  };

  useEffect(() => {
    loadAll();
  }, [categoryFilter, violationsOnly, timeRange]);

  // Auto-refresh timer
  useEffect(() => {
    if (autoRefreshSecs <= 0) return;
    const interval = setInterval(() => {
      fetchActiveSessions();
      fetchLogs();
      fetchAnalytics();
      setLastRefreshedAt(new Date());
    }, autoRefreshSecs * 1000);
    return () => clearInterval(interval);
  }, [autoRefreshSecs, categoryFilter, violationsOnly, timeRange]);

  // Save Policy
  const handleSavePolicy = async () => {
    if (!policy) return;
    setSavingPolicy(true);
    setPolicyNotice("");
    try {
      const res = await fetch(`${API_URL}/web-activity/policy`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", ...getAuthHeaders() },
        body: JSON.stringify({
          block_streaming_work_hours: policy.block_streaming_work_hours,
          block_gaming_work_hours: policy.block_gaming_work_hours,
          block_social_media_work_hours: policy.block_social_media_work_hours,
          block_adult_always: policy.block_adult_always,
          sniffer_enabled: policy.sniffer_enabled,
        }),
      });
      if (res.ok) {
        const updated = await res.json();
        setPolicy(updated);
        setPolicyNotice("✅ Institution Web Filtering Policy updated successfully!");
        setTimeout(() => setPolicyNotice(""), 3000);
      } else {
        setPolicyNotice("✕ Failed to save policy.");
      }
    } catch (err) {
      setPolicyNotice(`✕ Error: ${err.message}`);
    } finally {
      setSavingPolicy(false);
    }
  };

  // Clear history for testing
  const handleClearHistory = async () => {
    if (!window.confirm("Clear all historical web activity logs? Live active connections will continue being monitored in real time.")) {
      return;
    }
    setClearingHistory(true);
    try {
      const res = await fetch(`${API_URL}/web-activity/logs`, {
        method: "DELETE",
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        await loadAll();
      } else {
        alert("Failed to clear logs. Ensure you have administrator permissions.");
      }
    } catch (err) {
      alert(`Error clearing history: ${err.message}`);
    } finally {
      setClearingHistory(false);
    }
  };

  // Calculate live connection status from timestamp
  const getSessionStatus = (timestamp) => {
    const dt = new Date(timestamp.endsWith("Z") ? timestamp : timestamp + "Z");
    const diffSec = Math.max(0, Math.floor((Date.now() - dt.getTime()) / 1000));
    if (diffSec < 120) {
      return {
        status: "active",
        label: `Active (${diffSec}s ago)`,
        dotColor: "#10b981",
        color: "#34d399",
        bg: "rgba(16, 185, 129, 0.15)",
        border: "rgba(16, 185, 129, 0.4)",
        isOnline: true,
      };
    } else if (diffSec < 300) {
      const mins = Math.floor(diffSec / 60);
      return {
        status: "idle",
        label: `Idle (${mins}m ago)`,
        dotColor: "#f59e0b",
        color: "#fbbf24",
        bg: "rgba(245, 158, 11, 0.15)",
        border: "rgba(245, 158, 11, 0.4)",
        isOnline: true,
      };
    } else {
      const mins = Math.floor(diffSec / 60);
      const hours = Math.floor(mins / 60);
      const timeStr = hours > 0 ? `${hours}h ${mins % 60}m ago` : `${mins}m ago`;
      return {
        status: "left",
        label: `Left Site (${timeStr})`,
        dotColor: "#64748b",
        color: "#94a3b8",
        bg: "rgba(148, 163, 184, 0.1)",
        border: "rgba(148, 163, 184, 0.25)",
        isOnline: false,
      };
    }
  };

  // Filter logs by search query
  const filteredLogs = logs.filter((log) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase().trim();
    return (
      (log.domain || "").toLowerCase().includes(q) ||
      (log.hostname || "").toLowerCase().includes(q) ||
      (log.ip_address || "").toLowerCase().includes(q) ||
      (log.category || "").toLowerCase().includes(q)
    );
  });

  const getCategoryBadge = (cat) => {
    switch (cat) {
      case "streaming":
        return { label: "🎬 Streaming", bg: "rgba(239, 68, 68, 0.15)", color: "#f87171", border: "rgba(239, 68, 68, 0.4)" };
      case "gaming":
        return { label: "🎮 Gaming", bg: "rgba(168, 85, 247, 0.15)", color: "#c084fc", border: "rgba(168, 85, 247, 0.4)" };
      case "social_media":
        return { label: "📱 Social Media", bg: "rgba(59, 130, 246, 0.15)", color: "#60a5fa", border: "rgba(59, 130, 246, 0.4)" };
      case "gambling_adult":
        return { label: "🔞 High Risk / Adult", bg: "rgba(220, 38, 38, 0.25)", color: "#ef4444", border: "#dc2626" };
      case "productivity":
        return { label: "💼 Productivity", bg: "rgba(16, 185, 129, 0.15)", color: "#34d399", border: "rgba(16, 185, 129, 0.4)" };
      default:
        return { label: "🌐 General Web", bg: "rgba(148, 163, 184, 0.12)", color: "#94a3b8", border: "rgba(148, 163, 184, 0.3)" };
    }
  };

  return (
    <div style={{ padding: "20px 24px", color: "#f8fafc", maxWidth: "1400px", margin: "0 auto" }}>
      <style>{`
        @keyframes spinSlow {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        @keyframes pulseDot {
          0% { transform: scale(0.95); opacity: 0.8; }
          50% { transform: scale(1.2); opacity: 1; }
          100% { transform: scale(0.95); opacity: 0.8; }
        }
        .spin-active {
          animation: spinSlow 0.8s linear infinite;
        }
        .live-dot {
          animation: pulseDot 2s infinite ease-in-out;
        }
      `}</style>

      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px", flexWrap: "wrap", gap: "12px" }}>
        <div>
          <h1 style={{ fontSize: "22px", fontWeight: "800", color: "#f1f5f9", margin: "0 0 4px 0", display: "flex", alignItems: "center", gap: "8px" }}>
            <span>🌐</span> Web & Application Activity Monitor
          </h1>
          <p style={{ margin: 0, fontSize: "13px", color: "#94a3b8" }}>
            Real-time passive visibility into active websites, radio streaming, online games, and social media accessed by connected computers.
          </p>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
          {/* Last refreshed status badge */}
          <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "12px", color: "#94a3b8", background: "#0f172a", border: "1px solid #334155", padding: "6px 12px", borderRadius: "6px" }}>
            <span style={{ display: "inline-block", width: "8px", height: "8px", borderRadius: "50%", background: "#10b981" }} className="live-dot" />
            <span>Last checked: <strong>{lastRefreshedAt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</strong></span>
          </div>

          <button
            type="button"
            className="secondary-button"
            onClick={() => setShowPolicyModal(true)}
            style={{ display: "inline-flex", alignItems: "center", gap: "6px", fontSize: "12px", padding: "7px 14px" }}
          >
            ⚙️ Institution Policy
          </button>

          <button
            type="button"
            className="secondary-button"
            onClick={handleClearHistory}
            disabled={clearingHistory}
            style={{ display: "inline-flex", alignItems: "center", gap: "6px", fontSize: "12px", padding: "7px 12px", borderColor: "#475569", color: "#cbd5e1" }}
            title="Clear old logs to start with a clean real-time test"
          >
            🗑️ Clear History
          </button>

          {/* Scan Endpoints Browsing Activity Button */}
          <button
            type="button"
            className="primary-button"
            onClick={handleScanWebActivity}
            disabled={scanning}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "8px",
              fontSize: "12px",
              fontWeight: "700",
              padding: "7px 16px",
              background: scanning ? "#0369a1" : "linear-gradient(135deg, #0284c7, #0369a1)",
              borderColor: "#0284c7",
              cursor: scanning ? "not-allowed" : "pointer",
              boxShadow: "0 2px 4px rgba(2, 132, 199, 0.3)",
            }}
            title="Scan connected LAN machines for active and cached browsing activity"
          >
            <span style={{ display: "inline-block", fontSize: "14px" }} className={scanning ? "spin-active" : ""}>
              {scanning ? "⏳" : "📡"}
            </span>
            {scanning ? "Scanning Machines..." : "Scan Browsing Activity"}
          </button>

          {/* Enhanced Refresh Button */}
          <button
            type="button"
            className="primary-button"
            onClick={loadAll}
            disabled={refreshing}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "8px",
              fontSize: "12px",
              fontWeight: "700",
              padding: "7px 16px",
              background: refreshing ? "#2563eb" : "#3b82f6",
              borderColor: "#1d4ed8",
              cursor: "pointer",
            }}
            title="Reload devices active right now"
          >
            <span style={{ display: "inline-block", fontSize: "14px" }} className={refreshing ? "spin-active" : ""}>
              🔄
            </span>
            {refreshing ? "Reloading..." : "Reload Devices Now"}
          </button>
        </div>
      </div>

      {/* Live Active Connections Card */}
      {(() => {
        // Group active sessions by unique device IP / hostname
        const groupedDevices = activeSessions.reduce((acc, s) => {
          const key = s.ip_address || s.hostname || "unknown";
          if (!acc[key]) {
            acc[key] = {
              ip_address: s.ip_address,
              hostname: s.hostname || s.ip_address,
              mac_address: s.mac_address,
              device_id: s.device_id,
              status: s.status,
              minSecondsAgo: s.seconds_ago,
              hasViolation: s.is_violation,
              sites: [],
            };
          }
          if (s.seconds_ago < acc[key].minSecondsAgo) {
            acc[key].minSecondsAgo = s.seconds_ago;
            acc[key].status = s.status;
          }
          if (s.is_violation) {
            acc[key].hasViolation = true;
          }
          acc[key].sites.push(s);
          return acc;
        }, {});

        const deviceList = Object.values(groupedDevices).sort((a, b) => a.minSecondsAgo - b.minSecondsAgo);

        return (
          <div style={{ background: "#1e293b", border: "1px solid #334155", borderRadius: "8px", padding: "16px", marginBottom: "20px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px", flexWrap: "wrap", gap: "10px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
                <span style={{ display: "inline-block", width: "10px", height: "10px", borderRadius: "50%", background: "#10b981" }} className="live-dot" />
                <span style={{ fontSize: "14px", fontWeight: "700", color: "#f8fafc" }}>
                  🟢 Active Devices & Browsing Activity (Live Now)
                </span>
                <span style={{ background: "rgba(16, 185, 129, 0.2)", color: "#34d399", border: "1px solid rgba(16, 185, 129, 0.4)", borderRadius: "12px", padding: "2px 8px", fontSize: "11px", fontWeight: "700" }}>
                  {deviceList.length} device{deviceList.length === 1 ? "" : "s"} • {activeSessions.length} active site{activeSessions.length === 1 ? "" : "s"}
                </span>
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                {/* View toggle */}
                <div style={{ display: "flex", background: "#0f172a", padding: "2px", borderRadius: "6px", border: "1px solid #334155" }}>
                  <button
                    type="button"
                    onClick={() => setViewMode("grouped")}
                    style={{
                      background: viewMode === "grouped" ? "#2563eb" : "transparent",
                      color: viewMode === "grouped" ? "#ffffff" : "#94a3b8",
                      border: "none",
                      borderRadius: "4px",
                      padding: "4px 10px",
                      fontSize: "11px",
                      cursor: "pointer",
                      fontWeight: viewMode === "grouped" ? "700" : "500",
                    }}
                    title="Show one consolidated card per machine with all its browsed websites"
                  >
                    💻 One Card per Machine
                  </button>
                  <button
                    type="button"
                    onClick={() => setViewMode("flat")}
                    style={{
                      background: viewMode === "flat" ? "#2563eb" : "transparent",
                      color: viewMode === "flat" ? "#ffffff" : "#94a3b8",
                      border: "none",
                      borderRadius: "4px",
                      padding: "4px 10px",
                      fontSize: "11px",
                      cursor: "pointer",
                      fontWeight: viewMode === "flat" ? "700" : "500",
                    }}
                    title="Show repeating individual site tiles"
                  >
                    🌐 Individual Sites
                  </button>
                </div>

                <div style={{ fontSize: "11px", color: "#94a3b8" }}>
                  Auto-refreshes every {autoRefreshSecs}s
                </div>
              </div>
            </div>

            {deviceList.length === 0 ? (
              <div style={{ padding: "20px", textAlign: "center", background: "#0f172a", borderRadius: "6px", color: "#64748b", fontSize: "12px" }}>
                <span>⚪ No devices actively streaming or browsing in the last 5 minutes.</span>
                <div style={{ marginTop: "4px", fontSize: "11px", color: "#475569" }}>
                  When a laptop streams radio, opens YouTube, or visits a website, it will show up here instantly with its live status.
                </div>
              </div>
            ) : viewMode === "grouped" ? (
              /* GROUPED VIEW: Exactly 1 card per machine showing all its sites */
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(360px, 1fr))", gap: "14px" }}>
                {deviceList.map((dev, dIdx) => (
                  <div
                    key={`device-card-${dIdx}`}
                    style={{
                      background: "#0f172a",
                      border: dev.hasViolation ? "1px solid rgba(239, 68, 68, 0.6)" : "1px solid #334155",
                      borderRadius: "8px",
                      padding: "14px",
                      display: "flex",
                      flexDirection: "column",
                      gap: "10px",
                      boxShadow: dev.hasViolation ? "0 0 10px rgba(239, 68, 68, 0.15)" : "none",
                    }}
                  >
                    {/* Machine Header */}
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", borderBottom: "1px solid #1e293b", paddingBottom: "10px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                        <span style={{ fontSize: "22px" }}>💻</span>
                        <div>
                          <div style={{ fontWeight: "700", color: "#f8fafc", fontSize: "14px" }}>
                            {dev.hostname}
                          </div>
                          <div style={{ fontSize: "11px", color: "#94a3b8", fontFamily: "monospace" }}>
                            {dev.ip_address} {dev.mac_address ? `• ${dev.mac_address}` : ""}
                          </div>
                        </div>
                      </div>

                      <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "4px" }}>
                        <span
                          style={{
                            fontSize: "10px",
                            fontWeight: "700",
                            padding: "2px 8px",
                            borderRadius: "4px",
                            background: dev.status === "active" ? "rgba(16, 185, 129, 0.2)" : "rgba(245, 158, 11, 0.2)",
                            color: dev.status === "active" ? "#34d399" : "#fbbf24",
                            border: dev.status === "active" ? "1px solid #10b981" : "1px solid #f59e0b",
                            display: "flex",
                            alignItems: "center",
                            gap: "4px",
                          }}
                        >
                          <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: dev.status === "active" ? "#10b981" : "#f59e0b" }} className={dev.status === "active" ? "live-dot" : ""} />
                          {dev.minSecondsAgo < 60 ? `${dev.minSecondsAgo}s ago` : `${Math.floor(dev.minSecondsAgo / 60)}m ago`}
                        </span>

                        <span style={{ fontSize: "10px", color: "#94a3b8", background: "#1e293b", padding: "1px 6px", borderRadius: "4px" }}>
                          {dev.sites.length} site{dev.sites.length === 1 ? "" : "s"} browsed
                        </span>
                      </div>
                    </div>

                    {/* Websites Browsed by this Machine */}
                    <div style={{ display: "flex", flexDirection: "column", gap: "6px", maxHeight: "240px", overflowY: "auto", paddingRight: "4px" }}>
                      {dev.sites.map((site, sIdx) => {
                        const badge = getCategoryBadge(site.category);
                        return (
                          <div
                            key={`site-${sIdx}`}
                            style={{
                              background: site.is_violation ? "rgba(239, 68, 68, 0.08)" : "#1e293b",
                              border: site.is_violation ? "1px solid rgba(239, 68, 68, 0.3)" : "1px solid rgba(51, 65, 85, 0.5)",
                              borderRadius: "6px",
                              padding: "6px 10px",
                              display: "flex",
                              justifyContent: "space-between",
                              alignItems: "center",
                              gap: "8px",
                            }}
                          >
                            <div style={{ display: "flex", alignItems: "center", gap: "6px", overflow: "hidden" }}>
                              <span style={{ fontWeight: "600", color: "#60a5fa", fontFamily: "monospace", fontSize: "12px", textOverflow: "ellipsis", overflow: "hidden", whiteSpace: "nowrap" }}>
                                {site.domain}
                              </span>
                              {site.is_violation && (
                                <span style={{ fontSize: "10px", color: "#f87171", fontWeight: "700" }}>⚠️</span>
                              )}
                            </div>

                            <div style={{ display: "flex", alignItems: "center", gap: "6px", flexShrink: 0 }}>
                              <span
                                style={{
                                  fontSize: "9px",
                                  fontWeight: "700",
                                  padding: "1px 6px",
                                  borderRadius: "4px",
                                  background: badge.bg,
                                  color: badge.color,
                                  border: `1px solid ${badge.border}`,
                                }}
                              >
                                {badge.label}
                              </span>
                              <span style={{ fontSize: "10px", color: "#64748b" }}>
                                {site.seconds_ago < 60 ? `${site.seconds_ago}s ago` : `${Math.floor(site.seconds_ago / 60)}m ago`}
                              </span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              /* FLAT VIEW: Repeating individual site tiles */
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: "12px" }}>
                {activeSessions.map((s, idx) => {
                  const badge = getCategoryBadge(s.category);
                  return (
                    <div
                      key={`active-session-${idx}`}
                      style={{
                        background: "#0f172a",
                        border: s.is_violation ? "1px solid rgba(239, 68, 68, 0.5)" : "1px solid #334155",
                        borderRadius: "6px",
                        padding: "12px",
                        display: "flex",
                        flexDirection: "column",
                        gap: "8px",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <div style={{ fontWeight: "700", color: "#f8fafc", fontSize: "13px" }}>
                          {s.hostname || s.ip_address}
                        </div>
                        <span
                          style={{
                            fontSize: "10px",
                            fontWeight: "700",
                            padding: "2px 6px",
                            borderRadius: "4px",
                            background: s.status === "active" ? "rgba(16, 185, 129, 0.2)" : "rgba(245, 158, 11, 0.2)",
                            color: s.status === "active" ? "#34d399" : "#fbbf24",
                            border: s.status === "active" ? "1px solid #10b981" : "1px solid #f59e0b",
                            display: "flex",
                            alignItems: "center",
                            gap: "4px",
                          }}
                        >
                          <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: s.status === "active" ? "#10b981" : "#f59e0b" }} className={s.status === "active" ? "live-dot" : ""} />
                          {s.seconds_ago < 60 ? `${s.seconds_ago}s ago` : `${Math.floor(s.seconds_ago / 60)}m ago`}
                        </span>
                      </div>

                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "12px" }}>
                        <span style={{ fontFamily: "monospace", color: "#94a3b8" }}>{s.ip_address}</span>
                        <span
                          style={{
                            fontSize: "10px",
                            fontWeight: "700",
                            padding: "1px 6px",
                            borderRadius: "4px",
                            background: badge.bg,
                            color: badge.color,
                            border: `1px solid ${badge.border}`,
                          }}
                        >
                          {badge.label}
                        </span>
                      </div>

                      <div style={{ fontSize: "13px", fontWeight: "700", color: "#60a5fa", fontFamily: "monospace", wordBreak: "break-all" }}>
                        {s.domain}
                      </div>

                      {s.is_violation && (
                        <div style={{ fontSize: "11px", color: "#f87171", background: "rgba(239, 68, 68, 0.1)", padding: "4px 8px", borderRadius: "4px", border: "1px solid rgba(239, 68, 68, 0.3)" }}>
                          ⚠️ Prohibited activity during working hours
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })()}

      {/* Metrics Summary Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: "14px", marginBottom: "22px" }}>
        <div style={{ background: "#1e293b", border: "1px solid #334155", borderRadius: "8px", padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "#94a3b8", textTransform: "uppercase", fontWeight: "700" }}>Total Queries (24h)</div>
          <div style={{ fontSize: "26px", fontWeight: "800", color: "#f8fafc", marginTop: "4px" }}>
            {analytics?.total_queries?.toLocaleString() ?? 0}
          </div>
          <div style={{ fontSize: "11px", color: "#64748b", marginTop: "4px" }}>Active DNS queries</div>
        </div>

        <div style={{ background: "#1e293b", border: "1px solid rgba(239, 68, 68, 0.4)", borderRadius: "8px", padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "#f87171", textTransform: "uppercase", fontWeight: "700" }}>🎬 Audio & Video Streaming</div>
          <div style={{ fontSize: "26px", fontWeight: "800", color: "#f87171", marginTop: "4px" }}>
            {analytics?.category_counts?.streaming ?? 0}
          </div>
          <div style={{ fontSize: "11px", color: "#94a3b8", marginTop: "4px" }}>Radio streams, YouTube, Netflix</div>
        </div>

        <div style={{ background: "#1e293b", border: "1px solid rgba(168, 85, 247, 0.4)", borderRadius: "8px", padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "#c084fc", textTransform: "uppercase", fontWeight: "700" }}>🎮 Online Gaming</div>
          <div style={{ fontSize: "26px", fontWeight: "800", color: "#c084fc", marginTop: "4px" }}>
            {analytics?.category_counts?.gaming ?? 0}
          </div>
          <div style={{ fontSize: "11px", color: "#94a3b8", marginTop: "4px" }}>Steam, Roblox, Epic, Discord</div>
        </div>

        <div style={{ background: "#1e293b", border: "1px solid rgba(59, 130, 246, 0.4)", borderRadius: "8px", padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "#60a5fa", textTransform: "uppercase", fontWeight: "700" }}>📱 Social Media</div>
          <div style={{ fontSize: "26px", fontWeight: "800", color: "#60a5fa", marginTop: "4px" }}>
            {analytics?.category_counts?.social_media ?? 0}
          </div>
          <div style={{ fontSize: "11px", color: "#94a3b8", marginTop: "4px" }}>Facebook, TikTok, Instagram</div>
        </div>

        <div style={{ background: "#1e293b", border: "1px solid rgba(245, 158, 11, 0.4)", borderRadius: "8px", padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "#fbbf24", textTransform: "uppercase", fontWeight: "700" }}>⚠️ Work-Hours Violations</div>
          <div style={{ fontSize: "26px", fontWeight: "800", color: "#fbbf24", marginTop: "4px" }}>
            {analytics?.violations_count ?? 0}
          </div>
          <div style={{ fontSize: "11px", color: "#94a3b8", marginTop: "4px" }}>Prohibited activities during work hours</div>
        </div>
      </div>

      {/* Top Consumers Leaderboards (Streaming & Gaming) */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "22px" }}>
        {/* Top Streaming PCs */}
        <div style={{ background: "#1e293b", border: "1px solid #334155", borderRadius: "8px", padding: "16px" }}>
          <div style={{ fontSize: "13px", fontWeight: "700", color: "#f87171", display: "flex", alignItems: "center", gap: "6px", marginBottom: "12px" }}>
            <span>🎬</span> Top Audio & Video Streaming Computers
          </div>
          {analytics?.top_streaming_devices?.length > 0 ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              {analytics.top_streaming_devices.map((d, i) => (
                <div
                  key={`stream-dev-${i}`}
                  style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "12px", padding: "6px 10px", background: "#0f172a", borderRadius: "4px" }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <span style={{ fontWeight: "700", color: "#94a3b8" }}>#{i + 1}</span>
                    <span style={{ fontWeight: "600", color: "#f8fafc" }}>{d.device}</span>
                  </div>
                  <span style={{ background: "rgba(239, 68, 68, 0.15)", color: "#f87171", padding: "2px 8px", borderRadius: "4px", fontSize: "11px", fontWeight: "700" }}>
                    {d.hits} streaming requests
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ fontSize: "12px", color: "#64748b", fontStyle: "italic", padding: "10px 0" }}>
              No streaming activity detected in this time window.
            </div>
          )}
        </div>

        {/* Top Gaming PCs */}
        <div style={{ background: "#1e293b", border: "1px solid #334155", borderRadius: "8px", padding: "16px" }}>
          <div style={{ fontSize: "13px", fontWeight: "700", color: "#c084fc", display: "flex", alignItems: "center", gap: "6px", marginBottom: "12px" }}>
            <span>🎮</span> Top Online Gaming Computers
          </div>
          {analytics?.top_gaming_devices?.length > 0 ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              {analytics.top_gaming_devices.map((d, i) => (
                <div
                  key={`gaming-dev-${i}`}
                  style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "12px", padding: "6px 10px", background: "#0f172a", borderRadius: "4px" }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <span style={{ fontWeight: "700", color: "#94a3b8" }}>#{i + 1}</span>
                    <span style={{ fontWeight: "600", color: "#f8fafc" }}>{d.device}</span>
                  </div>
                  <span style={{ background: "rgba(168, 85, 247, 0.15)", color: "#c084fc", padding: "2px 8px", borderRadius: "4px", fontSize: "11px", fontWeight: "700" }}>
                    {d.hits} gaming requests
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ fontSize: "12px", color: "#64748b", fontStyle: "italic", padding: "10px 0" }}>
              No gaming activity detected in this time window.
            </div>
          )}
        </div>
      </div>

      {/* Filters Toolbar */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", background: "#1e293b", border: "1px solid #334155", borderRadius: "8px", padding: "12px 16px", marginBottom: "16px", flexWrap: "wrap", gap: "10px" }}>
        {/* Time Window Buttons */}
        <div style={{ display: "flex", gap: "6px", alignItems: "center", flexWrap: "wrap" }}>
          <span style={{ fontSize: "11px", color: "#94a3b8", fontWeight: "700", marginRight: "4px" }}>WINDOW:</span>
          <button
            type="button"
            className={timeRange === "live" ? "primary-button small" : "secondary-button small"}
            onClick={() => setTimeRange("live")}
            style={{ fontSize: "11px", padding: "4px 8px", background: timeRange === "live" ? "#10b981" : undefined, borderColor: timeRange === "live" ? "#059669" : undefined }}
          >
            🟢 Live Now (&lt;5m)
          </button>
          <button
            type="button"
            className={timeRange === "15m" ? "primary-button small" : "secondary-button small"}
            onClick={() => setTimeRange("15m")}
            style={{ fontSize: "11px", padding: "4px 8px" }}
          >
            ⏱️ Last 15m
          </button>
          <button
            type="button"
            className={timeRange === "1h" ? "primary-button small" : "secondary-button small"}
            onClick={() => setTimeRange("1h")}
            style={{ fontSize: "11px", padding: "4px 8px" }}
          >
            ⏳ 1 Hour
          </button>
          <button
            type="button"
            className={timeRange === "24h" ? "primary-button small" : "secondary-button small"}
            onClick={() => setTimeRange("24h")}
            style={{ fontSize: "11px", padding: "4px 8px" }}
          >
            📅 Today (24h)
          </button>
          <button
            type="button"
            className={timeRange === "all" ? "primary-button small" : "secondary-button small"}
            onClick={() => setTimeRange("all")}
            style={{ fontSize: "11px", padding: "4px 8px" }}
          >
            📜 All Time
          </button>
        </div>

        {/* Category Filters */}
        <div style={{ display: "flex", gap: "6px", alignItems: "center", flexWrap: "wrap" }}>
          <button
            type="button"
            className={categoryFilter === "all" && !violationsOnly ? "primary-button small" : "secondary-button small"}
            onClick={() => { setCategoryFilter("all"); setViolationsOnly(false); }}
            style={{ fontSize: "11px", padding: "4px 8px" }}
          >
            All Categories
          </button>
          <button
            type="button"
            className={violationsOnly ? "primary-button small" : "secondary-button small"}
            onClick={() => { setViolationsOnly(true); setCategoryFilter("all"); }}
            style={{ fontSize: "11px", padding: "4px 8px", background: violationsOnly ? "#dc2626" : undefined, borderColor: violationsOnly ? "#b91c1c" : undefined }}
          >
            ⚠️ Violations Only
          </button>
          <button
            type="button"
            className={categoryFilter === "streaming" ? "primary-button small" : "secondary-button small"}
            onClick={() => { setCategoryFilter("streaming"); setViolationsOnly(false); }}
            style={{ fontSize: "11px", padding: "4px 8px", background: categoryFilter === "streaming" ? "#ef4444" : undefined }}
          >
            🎬 Streaming
          </button>
          <button
            type="button"
            className={categoryFilter === "gaming" ? "primary-button small" : "secondary-button small"}
            onClick={() => { setCategoryFilter("gaming"); setViolationsOnly(false); }}
            style={{ fontSize: "11px", padding: "4px 8px", background: categoryFilter === "gaming" ? "#a855f7" : undefined }}
          >
            🎮 Gaming
          </button>
          <button
            type="button"
            className={categoryFilter === "social_media" ? "primary-button small" : "secondary-button small"}
            onClick={() => { setCategoryFilter("social_media"); setViolationsOnly(false); }}
            style={{ fontSize: "11px", padding: "4px 8px", background: categoryFilter === "social_media" ? "#3b82f6" : undefined }}
          >
            📱 Social Media
          </button>
        </div>

        {/* Search & Auto-Refresh Dropdown */}
        <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
          <input
            type="text"
            className="form-control"
            placeholder="Search domain, IP, host..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{ fontSize: "12px", padding: "5px 10px", width: "190px", background: "#0f172a", border: "1px solid #334155", color: "#f8fafc", borderRadius: "4px" }}
          />

          <select
            className="form-control"
            value={autoRefreshSecs}
            onChange={(e) => setAutoRefreshSecs(parseInt(e.target.value, 10))}
            style={{ fontSize: "11px", padding: "5px 8px", background: "#0f172a", border: "1px solid #334155", color: "#94a3b8", borderRadius: "4px" }}
          >
            <option value="5">Auto (5s)</option>
            <option value="15">Auto (15s)</option>
            <option value="0">Manual</option>
          </select>
        </div>
      </div>

      {/* Activity Table */}
      <div style={{ background: "#1e293b", border: "1px solid #334155", borderRadius: "8px", overflow: "hidden" }}>
        <table className="netops-table" style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
          <thead>
            <tr style={{ background: "#0f172a", borderBottom: "1px solid #334155", textAlign: "left", color: "#94a3b8" }}>
              <th style={{ padding: "10px 14px" }}>TIME</th>
              <th style={{ padding: "10px 14px" }}>COMPUTER / USER</th>
              <th style={{ padding: "10px 14px" }}>IP & MAC ADDRESS</th>
              <th style={{ padding: "10px 14px" }}>DOMAIN / WEBSITE</th>
              <th style={{ padding: "10px 14px" }}>CATEGORY</th>
              <th style={{ padding: "10px 14px" }}>CONNECTION STATE</th>
              <th style={{ padding: "10px 14px" }}>COMPLIANCE</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan="7" style={{ textAlign: "center", padding: "30px", color: "#64748b" }}>
                  {loading ? (
                    "⏳ Loading web activity logs..."
                  ) : timeRange === "live" ? (
                    <div>
                      <div>⚪ No active web activity detected in the last 5 minutes.</div>
                      <div style={{ fontSize: "11px", color: "#475569", marginTop: "4px" }}>
                        Users who closed their sites have left the session. Switch window to "Last 1 Hour" or "All Time" to view previous history.
                      </div>
                    </div>
                  ) : (
                    "No web activity logs match the selected filter."
                  )}
                </td>
              </tr>
            ) : (
              filteredLogs.map((log) => {
                const badge = getCategoryBadge(log.category);
                const sessionStatus = getSessionStatus(log.timestamp);
                const dt = new Date(log.timestamp.endsWith("Z") ? log.timestamp : log.timestamp + "Z");
                return (
                  <tr
                    key={`log-${log.id}`}
                    style={{
                      borderBottom: "1px solid #334155",
                      background: log.is_violation ? "rgba(239, 68, 68, 0.05)" : undefined,
                    }}
                  >
                    <td style={{ padding: "10px 14px", color: "#94a3b8", whiteSpace: "nowrap" }}>
                      {dt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                    </td>

                    <td style={{ padding: "10px 14px" }}>
                      <div style={{ fontWeight: "700", color: "#f8fafc" }}>
                        {log.hostname || "Network Host"}
                      </div>
                    </td>

                    <td style={{ padding: "10px 14px", fontFamily: "monospace", color: "#94a3b8" }}>
                      <div>{log.ip_address}</div>
                      {log.mac_address && <div style={{ fontSize: "11px", color: "#64748b" }}>{log.mac_address}</div>}
                    </td>

                    <td style={{ padding: "10px 14px" }}>
                      <div style={{ fontWeight: "700", color: "#60a5fa", fontFamily: "monospace" }}>
                        {log.domain}
                      </div>
                    </td>

                    <td style={{ padding: "10px 14px" }}>
                      <span
                        style={{
                          fontSize: "11px",
                          fontWeight: "700",
                          padding: "3px 8px",
                          borderRadius: "4px",
                          background: badge.bg,
                          color: badge.color,
                          border: `1px solid ${badge.border}`,
                          display: "inline-flex",
                          alignItems: "center",
                          gap: "4px",
                        }}
                      >
                        {badge.label}
                      </span>
                    </td>

                    {/* Enhanced Connection State Column */}
                    <td style={{ padding: "10px 14px" }}>
                      <span
                        style={{
                          fontSize: "11px",
                          fontWeight: "700",
                          padding: "3px 8px",
                          borderRadius: "4px",
                          background: sessionStatus.bg,
                          color: sessionStatus.color,
                          border: `1px solid ${sessionStatus.border}`,
                          display: "inline-flex",
                          alignItems: "center",
                          gap: "6px",
                        }}
                      >
                        <span
                          style={{ width: "6px", height: "6px", borderRadius: "50%", background: sessionStatus.dotColor }}
                          className={sessionStatus.status === "active" ? "live-dot" : ""}
                        />
                        {sessionStatus.label}
                      </span>
                    </td>

                    <td style={{ padding: "10px 14px" }}>
                      {log.is_violation ? (
                        <span
                          style={{
                            fontSize: "11px",
                            fontWeight: "700",
                            padding: "3px 8px",
                            borderRadius: "4px",
                            background: "rgba(239, 68, 68, 0.2)",
                            color: "#f87171",
                            border: "1px solid rgba(239, 68, 68, 0.5)",
                            display: "inline-flex",
                            alignItems: "center",
                            gap: "4px",
                          }}
                        >
                          ⚠️ Flagged (Work Hours)
                        </span>
                      ) : (
                        <span style={{ color: "#64748b", fontSize: "11px" }}>
                          ✓ Monitored
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Policy Modal */}
      {showPolicyModal && policy && (
        <div
          className="modal-overlay"
          onClick={() => setShowPolicyModal(false)}
          style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(0,0,0,0.7)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}
        >
          <div
            className="automation-modal"
            onClick={(e) => e.stopPropagation()}
            style={{ background: "#1e293b", border: "1px solid #334155", borderRadius: "10px", width: "540px", maxWidth: "92vw", padding: "20px" }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px", borderBottom: "1px solid #334155", paddingBottom: "10px" }}>
              <div style={{ fontSize: "16px", fontWeight: "700", color: "#f8fafc", display: "flex", alignItems: "center", gap: "8px" }}>
                <span>⚙️</span> Institution Web Filtering & Monitoring Policy
              </div>
              <button
                type="button"
                onClick={() => setShowPolicyModal(false)}
                style={{ background: "none", border: "none", color: "#94a3b8", fontSize: "18px", cursor: "pointer" }}
              >
                ✕
              </button>
            </div>

            {policyNotice && (
              <div style={{ padding: "8px 12px", borderRadius: "4px", marginBottom: "12px", background: policyNotice.startsWith("✅") ? "rgba(16, 185, 129, 0.15)" : "rgba(239, 68, 68, 0.15)", border: policyNotice.startsWith("✅") ? "1px solid #10b981" : "1px solid #ef4444", fontSize: "12px", color: policyNotice.startsWith("✅") ? "#34d399" : "#f87171" }}>
                {policyNotice}
              </div>
            )}

            <div style={{ display: "flex", flexDirection: "column", gap: "14px", fontSize: "13px" }}>
              <label style={{ display: "flex", alignItems: "center", gap: "10px", cursor: "pointer" }}>
                <input
                  type="checkbox"
                  checked={policy.block_streaming_work_hours}
                  onChange={(e) => setPolicy({ ...policy, block_streaming_work_hours: e.target.checked })}
                />
                <div>
                  <strong>🎬 Prohibit Audio & Video Streaming during Work Hours (08:00–17:00)</strong>
                  <div style={{ fontSize: "11px", color: "#94a3b8" }}>Flags online radio, YouTube, Netflix, Prime Video, TikTok</div>
                </div>
              </label>

              <label style={{ display: "flex", alignItems: "center", gap: "10px", cursor: "pointer" }}>
                <input
                  type="checkbox"
                  checked={policy.block_gaming_work_hours}
                  onChange={(e) => setPolicy({ ...policy, block_gaming_work_hours: e.target.checked })}
                />
                <div>
                  <strong>🎮 Prohibit Online Gaming during Work Hours</strong>
                  <div style={{ fontSize: "11px", color: "#94a3b8" }}>Flags Steam, Epic Games, Roblox, Riot Games, Discord</div>
                </div>
              </label>

              <label style={{ display: "flex", alignItems: "center", gap: "10px", cursor: "pointer" }}>
                <input
                  type="checkbox"
                  checked={policy.block_social_media_work_hours}
                  onChange={(e) => setPolicy({ ...policy, block_social_media_work_hours: e.target.checked })}
                />
                <div>
                  <strong>📱 Prohibit Social Media during Work Hours</strong>
                  <div style={{ fontSize: "11px", color: "#94a3b8" }}>Flags Facebook, Instagram, TikTok, Twitter/X</div>
                </div>
              </label>

              <label style={{ display: "flex", alignItems: "center", gap: "10px", cursor: "pointer" }}>
                <input
                  type="checkbox"
                  checked={policy.block_adult_always}
                  onChange={(e) => setPolicy({ ...policy, block_adult_always: e.target.checked })}
                />
                <div>
                  <strong>🔞 Prohibit Adult & Gambling Sites (24/7)</strong>
                  <div style={{ fontSize: "11px", color: "#94a3b8" }}>Flags betting sites, online casinos, and adult domains</div>
                </div>
              </label>

              <label style={{ display: "flex", alignItems: "center", gap: "10px", cursor: "pointer" }}>
                <input
                  type="checkbox"
                  checked={policy.sniffer_enabled}
                  onChange={(e) => setPolicy({ ...policy, sniffer_enabled: e.target.checked })}
                />
                <div>
                  <strong>📡 Passive Network DNS Sniffer Active</strong>
                  <div style={{ fontSize: "11px", color: "#94a3b8" }}>Captures live network queries across LAN & Wi-Fi</div>
                </div>
              </label>
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px", marginTop: "20px", borderTop: "1px solid #334155", paddingTop: "14px" }}>
              <button
                type="button"
                className="secondary-button"
                onClick={() => setShowPolicyModal(false)}
              >
                Close
              </button>
              <button
                type="button"
                className="primary-button"
                onClick={handleSavePolicy}
                disabled={savingPolicy}
                style={{ background: "#10b981", borderColor: "#059669" }}
              >
                {savingPolicy ? "Saving..." : "Save Policy"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
