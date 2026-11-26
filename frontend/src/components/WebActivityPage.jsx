import React, { useEffect, useState, useRef } from "react";
import {
  Globe,
  Settings,
  Trash2,
  Radar,
  RefreshCw,
  Clock,
  Shield,
  Laptop,
  AlertTriangle,
  CheckCircle2,
  X,
  Film,
  Gamepad2,
  Smartphone,
  ShieldAlert,
  Briefcase,
  Search,
} from "lucide-react";

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
  const [timeRange, setTimeRange] = useState("1h"); // 'live' (<5m), '15m', '1h', '24h', 'all'
  const [searchQuery, setSearchQuery] = useState("");
  const [showPolicyModal, setShowPolicyModal] = useState(false);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [policyNotice, setPolicyNotice] = useState("");
  const [autoRefreshSecs, setAutoRefreshSecs] = useState(5);
  const [lastRefreshedAt, setLastRefreshedAt] = useState(new Date());
  const [clearingHistory, setClearingHistory] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [viewMode, setViewMode] = useState("grouped"); // 'grouped' (one card per machine) or 'flat'
  const [tableMode, setTableMode] = useState("grouped"); // 'grouped' (one row per machine) or 'stream'
  const [hideNoise, setHideNoise] = useState(true); // Filter out msftncsi, msftconnecttest, api pings

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

  const [activeMinutes, setActiveMinutes] = useState(15);

  // Fetch active sessions (devices communicating in the last N minutes)
  const fetchActiveSessions = async (mins = activeMinutes) => {
    try {
      const m = mins || activeMinutes || 5;
      const res = await fetch(`${API_URL}/web-activity/active-sessions?minutes=${m}`, {
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
    try {
      await Promise.all([fetchActiveSessions(), fetchLogs(), fetchAnalytics(), fetchPolicy()]);
      setLastRefreshedAt(new Date());
    } catch (err) {
      console.error("Error loading web activity data:", err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
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
        setPolicyNotice("Institution Web Filtering Policy updated successfully!");
        setTimeout(() => setPolicyNotice(""), 3000);
      } else {
        setPolicyNotice("Failed to save policy.");
      }
    } catch (err) {
      setPolicyNotice(`Error: ${err.message}`);
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

  // Domains representing background OS pings and internal API telemetry
  const isSystemNoise = (domain) => {
    if (!domain) return false;
    const d = domain.toLowerCase();
    const noiseList = [
      // OS & Network Connectivity checks
      "msftncsi.com",
      "msftconnecttest.com",
      "api.netops.co.ke",
      "connectivitycheck.gstatic.com",
      "detectportal.firefox.com",
      "dns.msftncsi.com",
      "ipv6.msftncsi.com",
      "ipv6.msftconnecttest.com",
      "ctldl.windowsupdate.com",
      "windowsupdate.com",
      "dns.google",
      "cloudflare-dns.com",
      "one.one.one.one",

      // Browser & OS background telemetry
      "safebrowsing.googleapis.com",
      "ohttp-relay-safebrowsing-chrome.google.fastly-edge.com",
      "mozilla-ohttp.fastly-edge.com",
      "ads.mozilla.org",
      "firefox.settings.services.mozilla.com",
      "push.services.mozilla.com",
      "nexusrules.officeapps.live.com",
      "daily-cloudcode-pa.googleapis.com",
      "aicode.googleapis.com",
      "notifications-pa.googleapis.com",
      "beacons.gcp.gvt2.com",
      "array514.prod.do.dsp.mp.microsoft.com",

      // Ad Networks, tracking pixels, & analytics SDKs (never typed by users in browser)
      "clarity.ms",
      "rubiconproject.com",
      "tribalfusion.com",
      "blismedia.com",
      "yellowblue.io",
      "adition.com",
      "media.net",
      "yieldmo.com",
      "contextweb.com",
      "kargo.com",
      "appsflyersdk.com",
      "app-measurement.com",
      "braze.com",
      "posthog.consumer.worldcoin.org",
      "toolsforhumanity.com",
      "lokalise.co",
      "doubleclick.net",
      "google-analytics.com",
      "googletagmanager.com",
    ];
    return noiseList.some((n) => d === n || d.endsWith("." + n));
  };

  // Filter logs by search query, category, and optional background noise
  const filteredLogs = logs.filter((log) => {
    if (hideNoise && isSystemNoise(log.domain) && !searchQuery) {
      return false;
    }
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase().trim();
    return (
      (log.domain || "").toLowerCase().includes(q) ||
      (log.hostname || "").toLowerCase().includes(q) ||
      (log.ip_address || "").toLowerCase().includes(q) ||
      (log.category || "").toLowerCase().includes(q)
    );
  });

  // Group filtered logs by machine for consolidated viewing
  const groupedMachineLogs = Object.values(
    filteredLogs.reduce((acc, log) => {
      const key = log.ip_address || log.hostname || "unknown";
      if (!acc[key]) {
        acc[key] = {
          ip_address: log.ip_address,
          hostname: log.hostname || log.ip_address,
          mac_address: log.mac_address,
          lastActive: log.timestamp,
          hasViolation: log.is_violation,
          totalHits: 0,
          sites: {},
        };
      }
      acc[key].totalHits += log.hit_count || 1;
      if (log.is_violation) acc[key].hasViolation = true;
      if (new Date(log.timestamp) > new Date(acc[key].lastActive)) {
        acc[key].lastActive = log.timestamp;
      }
      if (!acc[key].sites[log.domain]) {
        acc[key].sites[log.domain] = {
          domain: log.domain,
          category: log.category,
          is_violation: log.is_violation,
          hit_count: log.hit_count || 1,
          last_timestamp: log.timestamp,
        };
      } else {
        acc[key].sites[log.domain].hit_count += log.hit_count || 1;
        if (log.is_violation) acc[key].sites[log.domain].is_violation = true;
        if (new Date(log.timestamp) > new Date(acc[key].sites[log.domain].last_timestamp)) {
          acc[key].sites[log.domain].last_timestamp = log.timestamp;
        }
      }
      return acc;
    }, {})
  ).sort((a, b) => new Date(b.lastActive) - new Date(a.lastActive));

  const getCategoryBadge = (cat) => {
    switch (cat) {
      case "streaming":
        return { label: "Streaming", Icon: Film, bg: "rgba(239, 68, 68, 0.15)", color: "#f87171", border: "rgba(239, 68, 68, 0.4)" };
      case "gaming":
        return { label: "Gaming", Icon: Gamepad2, bg: "rgba(168, 85, 247, 0.15)", color: "#c084fc", border: "rgba(168, 85, 247, 0.4)" };
      case "social_media":
        return { label: "Social Media", Icon: Smartphone, bg: "rgba(59, 130, 246, 0.15)", color: "#60a5fa", border: "rgba(59, 130, 246, 0.4)" };
      case "gambling_adult":
        return { label: "High Risk / Adult", Icon: ShieldAlert, bg: "rgba(220, 38, 38, 0.25)", color: "#ef4444", border: "#dc2626" };
      case "productivity":
        return { label: "Productivity", Icon: Briefcase, bg: "rgba(16, 185, 129, 0.15)", color: "#34d399", border: "rgba(16, 185, 129, 0.4)" };
      default:
        return { label: "General Web", Icon: Globe, bg: "rgba(148, 163, 184, 0.12)", color: "#94a3b8", border: "rgba(148, 163, 184, 0.3)" };
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
            <Globe size={22} color="#60a5fa" />
            <span>Web & Application Activity Monitor</span>
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
            <Settings size={13} /> Institution Policy
          </button>

          <button
            type="button"
            className="secondary-button"
            onClick={handleClearHistory}
            disabled={clearingHistory}
            style={{ display: "inline-flex", alignItems: "center", gap: "6px", fontSize: "12px", padding: "7px 12px", borderColor: "#475569", color: "#cbd5e1" }}
            title="Clear old logs to start with a clean real-time test"
          >
            <Trash2 size={13} /> Clear History
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
              {scanning ? <RefreshCw size={14} className="spin" /> : <Radar size={14} />}
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
              <RefreshCw size={14} />
            </span>
            {refreshing ? "Reloading..." : "Reload Devices Now"}
          </button>
        </div>
      </div>

      {/* Live Active Connections Card */}
      {(() => {
        // Group all devices from activeSessions first so NO connected device is ever omitted
        const groupedDevices = activeSessions.reduce((acc, s) => {
          const key = s.ip_address || s.hostname || "unknown";
          if (!acc[key]) {
            acc[key] = {
              ip_address: s.ip_address,
              hostname: s.hostname || s.ip_address,
              mac_address: s.mac_address,
              device_id: s.device_id,
              status: s.status,
              minSecondsAgo: s.seconds_ago !== undefined ? s.seconds_ago : 9999,
              hasViolation: s.is_violation,
              sitesMap: {},
            };
          }
          if (s.seconds_ago !== undefined && s.seconds_ago < acc[key].minSecondsAgo) {
            acc[key].minSecondsAgo = s.seconds_ago;
            acc[key].status = s.status;
          }
          if (s.is_violation) {
            acc[key].hasViolation = true;
          }
          // Only add site to the machine's browsed list if it has a real domain and is not filtered noise:
          if (s.domain && s.domain !== "__idle__" && (!hideNoise || !isSystemNoise(s.domain))) {
            if (!acc[key].sitesMap[s.domain]) {
              acc[key].sitesMap[s.domain] = { ...s, count: 1 };
            } else {
              acc[key].sitesMap[s.domain].count += 1;
              if (s.seconds_ago < acc[key].sitesMap[s.domain].seconds_ago) {
                acc[key].sitesMap[s.domain].seconds_ago = s.seconds_ago;
                acc[key].sitesMap[s.domain].status = s.status;
              }
            }
          }
          return acc;
        }, {});

        const deviceList = Object.values(groupedDevices).map((dev) => ({
          ...dev,
          sites: Object.values(dev.sitesMap).sort((a, b) => a.seconds_ago - b.seconds_ago),
        })).sort((a, b) => a.minSecondsAgo - b.minSecondsAgo);

        const displayedDevices = deviceList
          .map((dev) => {
            const q = searchQuery.toLowerCase().trim();
            const devMatches =
              !q ||
              (dev.hostname || "").toLowerCase().includes(q) ||
              (dev.ip_address || "").toLowerCase().includes(q) ||
              (dev.mac_address || "").toLowerCase().includes(q);

            const filteredSites = dev.sites.filter((site) => {
              if (categoryFilter !== "all" && site.category !== categoryFilter) return false;
              if (violationsOnly && !site.is_violation) return false;
              if (!q || devMatches) return true;
              return (site.domain || "").toLowerCase().includes(q);
            });

            if ((categoryFilter !== "all" || violationsOnly || (q && !devMatches)) && filteredSites.length === 0) {
              return null;
            }

            return {
              ...dev,
              sites: filteredSites,
            };
          })
          .filter(Boolean);

        const visibleActiveSitesCount = displayedDevices.reduce((sum, d) => sum + d.sites.length, 0);
        const visibleSessions = activeSessions.filter((s) => {
          if (!s.domain || s.domain === "__idle__") return false;
          if (hideNoise && isSystemNoise(s.domain)) return false;
          if (categoryFilter !== "all" && s.category !== categoryFilter) return false;
          if (violationsOnly && !s.is_violation) return false;
          if (searchQuery) {
            const q = searchQuery.toLowerCase().trim();
            const match =
              (s.domain || "").toLowerCase().includes(q) ||
              (s.hostname || "").toLowerCase().includes(q) ||
              (s.ip_address || "").toLowerCase().includes(q);
            if (!match) return false;
          }
          return true;
        });

        return (
          <div style={{ background: "#1e293b", border: "1px solid #334155", borderRadius: "8px", padding: "16px", marginBottom: "20px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px", flexWrap: "wrap", gap: "10px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
                <span style={{ display: "inline-block", width: "10px", height: "10px", borderRadius: "50%", background: "#10b981" }} className="live-dot" />
                <span style={{ fontSize: "14px", fontWeight: "700", color: "#f8fafc" }}>
                  Connected Computers & Browsing Activity
                </span>
                <span style={{ background: "rgba(16, 185, 129, 0.2)", color: "#34d399", border: "1px solid rgba(16, 185, 129, 0.4)", borderRadius: "12px", padding: "2px 8px", fontSize: "11px", fontWeight: "700" }}>
                  {deviceList.length} computer{deviceList.length === 1 ? "" : "s"} • {visibleActiveSitesCount} active site{visibleActiveSitesCount === 1 ? "" : "s"}
                </span>
              </div>

              {/* Time Window & Noise Controls */}
              <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
                {/* Search input */}
                <input
                  type="text"
                  placeholder="Search host, IP, site..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  style={{
                    fontSize: "11px",
                    padding: "4px 10px",
                    width: "175px",
                    background: "#0f172a",
                    border: "1px solid #334155",
                    color: "#f8fafc",
                    borderRadius: "6px",
                  }}
                />

                {/* Time Range */}
                <div style={{ display: "flex", background: "#0f172a", padding: "2px", borderRadius: "6px", border: "1px solid #334155", gap: "2px" }}>
                  <button
                    type="button"
                    onClick={() => { setActiveMinutes(5); fetchActiveSessions(5); }}
                    style={{
                      background: activeMinutes === 5 ? "#10b981" : "transparent",
                      color: activeMinutes === 5 ? "#ffffff" : "#94a3b8",
                      border: "none",
                      borderRadius: "4px",
                      padding: "4px 8px",
                      fontSize: "11px",
                      cursor: "pointer",
                      fontWeight: activeMinutes === 5 ? "700" : "500",
                    }}
                  >
                    <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#10b981", display: "inline-block", marginRight: 4 }} /> 5m
                  </button>
                  <button
                    type="button"
                    onClick={() => { setActiveMinutes(15); fetchActiveSessions(15); }}
                    style={{
                      background: activeMinutes === 15 ? "#2563eb" : "transparent",
                      color: activeMinutes === 15 ? "#ffffff" : "#94a3b8",
                      border: "none",
                      borderRadius: "4px",
                      padding: "4px 8px",
                      fontSize: "11px",
                      cursor: "pointer",
                      fontWeight: activeMinutes === 15 ? "700" : "500",
                    }}
                  >
                    <Clock size={11} style={{ marginRight: 3, verticalAlign: "middle" }} /> 15m
                  </button>
                  <button
                    type="button"
                    onClick={() => { setActiveMinutes(60); fetchActiveSessions(60); }}
                    style={{
                      background: activeMinutes === 60 ? "#2563eb" : "transparent",
                      color: activeMinutes === 60 ? "#ffffff" : "#94a3b8",
                      border: "none",
                      borderRadius: "4px",
                      padding: "4px 8px",
                      fontSize: "11px",
                      cursor: "pointer",
                      fontWeight: activeMinutes === 60 ? "700" : "500",
                    }}
                  >
                    <Clock size={11} style={{ marginRight: 3, verticalAlign: "middle" }} /> 1h
                  </button>
                </div>

                {/* Noise filter */}
                <label style={{ display: "inline-flex", alignItems: "center", gap: "6px", fontSize: "11px", color: hideNoise ? "#60a5fa" : "#94a3b8", cursor: "pointer", userSelect: "none" }}>
                  <input
                    type="checkbox"
                    checked={hideNoise}
                    onChange={(e) => setHideNoise(e.target.checked)}
                    style={{ cursor: "pointer", accentColor: "#3b82f6" }}
                  />
                  <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}><Shield size={12} /> Hide OS Noise</span>
                </label>

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
                    <Laptop size={12} style={{ marginRight: 4, verticalAlign: "middle" }} /> By Machine
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
                    <Globe size={12} style={{ marginRight: 4, verticalAlign: "middle" }} /> Individual Sites
                  </button>
                </div>
              </div>
            </div>

            {/* Category Filter Pills */}
            <div style={{ display: "flex", gap: "6px", alignItems: "center", marginBottom: "14px", flexWrap: "wrap" }}>
              <span style={{ fontSize: "11px", color: "#94a3b8", fontWeight: "700", marginRight: "2px" }}>CATEGORY:</span>
              <button
                type="button"
                onClick={() => { setCategoryFilter("all"); setViolationsOnly(false); }}
                style={{
                  fontSize: "11px",
                  padding: "3px 10px",
                  borderRadius: "14px",
                  border: "1px solid",
                  borderColor: categoryFilter === "all" && !violationsOnly ? "#3b82f6" : "#334155",
                  background: categoryFilter === "all" && !violationsOnly ? "#2563eb" : "#0f172a",
                  color: categoryFilter === "all" && !violationsOnly ? "#ffffff" : "#94a3b8",
                  cursor: "pointer",
                  fontWeight: "600",
                }}
              >
                All Activity
              </button>
              <button
                type="button"
                onClick={() => { setCategoryFilter("streaming"); setViolationsOnly(false); }}
                style={{
                  fontSize: "11px",
                  padding: "3px 10px",
                  borderRadius: "14px",
                  border: "1px solid",
                  borderColor: categoryFilter === "streaming" ? "#ef4444" : "#334155",
                  background: categoryFilter === "streaming" ? "rgba(239, 68, 68, 0.2)" : "#0f172a",
                  color: categoryFilter === "streaming" ? "#f87171" : "#94a3b8",
                  cursor: "pointer",
                  fontWeight: "600",
                }}
              >
                <Film size={11} style={{ marginRight: 4, verticalAlign: "middle" }} /> Streaming
              </button>
              <button
                type="button"
                onClick={() => { setCategoryFilter("gaming"); setViolationsOnly(false); }}
                style={{
                  fontSize: "11px",
                  padding: "3px 10px",
                  borderRadius: "14px",
                  border: "1px solid",
                  borderColor: categoryFilter === "gaming" ? "#a855f7" : "#334155",
                  background: categoryFilter === "gaming" ? "rgba(168, 85, 247, 0.2)" : "#0f172a",
                  color: categoryFilter === "gaming" ? "#c084fc" : "#94a3b8",
                  cursor: "pointer",
                  fontWeight: "600",
                }}
              >
                <Gamepad2 size={11} style={{ marginRight: 4, verticalAlign: "middle" }} /> Gaming
              </button>
              <button
                type="button"
                onClick={() => { setCategoryFilter("social_media"); setViolationsOnly(false); }}
                style={{
                  fontSize: "11px",
                  padding: "3px 10px",
                  borderRadius: "14px",
                  border: "1px solid",
                  borderColor: categoryFilter === "social_media" ? "#3b82f6" : "#334155",
                  background: categoryFilter === "social_media" ? "rgba(59, 130, 246, 0.2)" : "#0f172a",
                  color: categoryFilter === "social_media" ? "#60a5fa" : "#94a3b8",
                  cursor: "pointer",
                  fontWeight: "600",
                }}
              >
                <Smartphone size={11} style={{ marginRight: 4, verticalAlign: "middle" }} /> Social Media
              </button>
              <button
                type="button"
                onClick={() => { setViolationsOnly(true); setCategoryFilter("all"); }}
                style={{
                  fontSize: "11px",
                  padding: "3px 10px",
                  borderRadius: "14px",
                  border: "1px solid",
                  borderColor: violationsOnly ? "#dc2626" : "#334155",
                  background: violationsOnly ? "#dc2626" : "#0f172a",
                  color: violationsOnly ? "#ffffff" : "#94a3b8",
                  cursor: "pointer",
                  fontWeight: "600",
                }}
              >
                <AlertTriangle size={11} style={{ marginRight: 4, verticalAlign: "middle" }} /> Violations Only
              </button>
            </div>

            {displayedDevices.length === 0 ? (
              <div style={{ padding: "24px", textAlign: "center", background: "#0f172a", borderRadius: "6px", color: "#64748b", fontSize: "12px" }}>
                <span>No web browsing activity detected in the last {activeMinutes} minutes.</span>
                <div style={{ marginTop: "4px", fontSize: "11px", color: "#475569" }}>
                  When any computer streams radio, visits YouTube, or browses websites, it will show up here instantly.
                </div>
              </div>
            ) : viewMode === "grouped" ? (
              /* GROUPED VIEW: Exactly 1 card per machine showing all its sites */
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(360px, 1fr))", gap: "14px" }}>
                {displayedDevices.map((dev, dIdx) => (
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
                        <Laptop size={22} color="#60a5fa" />
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
                        {dev.sites.length > 0 ? (
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
                        ) : (
                          <span
                            style={{
                              fontSize: "10px",
                              fontWeight: "700",
                              padding: "2px 8px",
                              borderRadius: "4px",
                              background: "rgba(16, 185, 129, 0.15)",
                              color: "#34d399",
                              border: "1px solid rgba(16, 185, 129, 0.3)",
                              display: "flex",
                              alignItems: "center",
                              gap: "4px",
                            }}
                          >
                            <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: "#10b981" }} />
                            Online (Idle)
                          </span>
                        )}

                        <span style={{ fontSize: "10px", color: "#94a3b8", background: "#1e293b", padding: "1px 6px", borderRadius: "4px" }}>
                          {dev.sites.length} unique site{dev.sites.length === 1 ? "" : "s"}
                        </span>
                      </div>
                    </div>

                    {/* Websites Browsed by this Machine */}
                    <div style={{ display: "flex", flexDirection: "column", gap: "6px", maxHeight: "240px", overflowY: "auto", paddingRight: "4px" }}>
                      {dev.sites.length === 0 ? (
                        <div style={{ padding: "12px", textAlign: "center", background: "#1e293b", borderRadius: "6px", color: "#64748b", fontSize: "11px" }}>
                          <span style={{ color: "#34d399", fontWeight: "600", display: "inline-flex", alignItems: "center", gap: "4px" }}>
                            <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: "#10b981", display: "inline-block" }} /> Online & Monitored
                          </span>
                          <div style={{ fontSize: "10px", color: "#475569", marginTop: "2px" }}>
                            Connected to network — No new websites visited in the last {activeMinutes}m window.
                          </div>
                        </div>
                      ) : (
                        dev.sites.map((site, sIdx) => {
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
                              {site.count > 1 && (
                                <span style={{ fontSize: "9px", background: "rgba(255,255,255,0.1)", borderRadius: "10px", padding: "1px 5px", color: "#cbd5e1" }}>
                                  ×{site.count}
                                </span>
                              )}
                              {site.is_violation && (
                                <AlertTriangle size={12} color="#f87171" />
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
                                  display: "inline-flex",
                                  alignItems: "center",
                                  gap: "3px",
                                }}
                              >
                                {badge.Icon && <badge.Icon size={10} />}
                                {badge.label}
                              </span>
                              <span style={{ fontSize: "10px", color: "#64748b" }}>
                                {site.seconds_ago < 60 ? `${site.seconds_ago}s ago` : `${Math.floor(site.seconds_ago / 60)}m ago`}
                              </span>
                            </div>
                          </div>
                        );
                      }))}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              /* FLAT VIEW: Repeating individual site tiles */
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: "12px" }}>
                {visibleSessions.map((s, idx) => {
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
                            display: "inline-flex",
                            alignItems: "center",
                            gap: "3px",
                          }}
                        >
                          {badge.Icon && <badge.Icon size={10} />}
                          {badge.label}
                        </span>
                      </div>

                      <div style={{ fontSize: "13px", fontWeight: "700", color: "#60a5fa", fontFamily: "monospace", wordBreak: "break-all" }}>
                        {s.domain}
                      </div>

                      {s.is_violation && (
                        <div style={{ fontSize: "11px", color: "#f87171", background: "rgba(239, 68, 68, 0.1)", padding: "4px 8px", borderRadius: "4px", border: "1px solid rgba(239, 68, 68, 0.3)", display: "flex", alignItems: "center", gap: "4px" }}>
                          <AlertTriangle size={11} /> Prohibited activity during working hours
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
          <div style={{ fontSize: "11px", color: "#f87171", textTransform: "uppercase", fontWeight: "700", display: "flex", alignItems: "center", gap: "6px" }}>
            <Film size={13} /> Audio & Video Streaming
          </div>
          <div style={{ fontSize: "26px", fontWeight: "800", color: "#f87171", marginTop: "4px" }}>
            {analytics?.category_counts?.streaming ?? 0}
          </div>
          <div style={{ fontSize: "11px", color: "#94a3b8", marginTop: "4px" }}>Radio streams, YouTube, Netflix</div>
        </div>

        <div style={{ background: "#1e293b", border: "1px solid rgba(168, 85, 247, 0.4)", borderRadius: "8px", padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "#c084fc", textTransform: "uppercase", fontWeight: "700", display: "flex", alignItems: "center", gap: "6px" }}>
            <Gamepad2 size={13} /> Online Gaming
          </div>
          <div style={{ fontSize: "26px", fontWeight: "800", color: "#c084fc", marginTop: "4px" }}>
            {analytics?.category_counts?.gaming ?? 0}
          </div>
          <div style={{ fontSize: "11px", color: "#94a3b8", marginTop: "4px" }}>Steam, Roblox, Epic, Discord</div>
        </div>

        <div style={{ background: "#1e293b", border: "1px solid rgba(59, 130, 246, 0.4)", borderRadius: "8px", padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "#60a5fa", textTransform: "uppercase", fontWeight: "700", display: "flex", alignItems: "center", gap: "6px" }}>
            <Smartphone size={13} /> Social Media
          </div>
          <div style={{ fontSize: "26px", fontWeight: "800", color: "#60a5fa", marginTop: "4px" }}>
            {analytics?.category_counts?.social_media ?? 0}
          </div>
          <div style={{ fontSize: "11px", color: "#94a3b8", marginTop: "4px" }}>Facebook, TikTok, Instagram</div>
        </div>

        <div style={{ background: "#1e293b", border: "1px solid rgba(245, 158, 11, 0.4)", borderRadius: "8px", padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "#fbbf24", textTransform: "uppercase", fontWeight: "700", display: "flex", alignItems: "center", gap: "6px" }}>
            <AlertTriangle size={13} /> Work-Hours Violations
          </div>
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
            <Film size={15} /> Top Audio & Video Streaming Computers
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
            <Gamepad2 size={15} /> Top Online Gaming Computers
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
                <Settings size={18} color="#94a3b8" /> Institution Web Filtering & Monitoring Policy
              </div>
              <button
                type="button"
                onClick={() => setShowPolicyModal(false)}
                style={{ background: "none", border: "none", color: "#94a3b8", cursor: "pointer", display: "flex", alignItems: "center", padding: 0 }}
              >
                <X size={18} />
              </button>
            </div>

            {policyNotice && (
              <div style={{ padding: "8px 12px", borderRadius: "4px", marginBottom: "12px", background: policyNotice.includes("fail") || policyNotice.includes("Error") ? "rgba(239, 68, 68, 0.15)" : "rgba(16, 185, 129, 0.15)", border: policyNotice.includes("fail") || policyNotice.includes("Error") ? "1px solid #ef4444" : "1px solid #10b981", fontSize: "12px", color: policyNotice.includes("fail") || policyNotice.includes("Error") ? "#f87171" : "#34d399", display: "flex", alignItems: "center", gap: "6px" }}>
                {policyNotice.includes("fail") || policyNotice.includes("Error") ? <AlertTriangle size={14} /> : <CheckCircle2 size={14} />}
                <span>{policyNotice.replace(/^[\u2705\u274C\u26A0\uFE0F]\s*/, "")}</span>
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
                  <strong style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                    <Film size={14} color="#f87171" /> Prohibit Audio & Video Streaming during Work Hours (08:00–17:00)
                  </strong>
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
                  <strong style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                    <Gamepad2 size={14} color="#c084fc" /> Prohibit Online Gaming during Work Hours
                  </strong>
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
                  <strong style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                    <Smartphone size={14} color="#60a5fa" /> Prohibit Social Media during Work Hours
                  </strong>
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
                  <strong style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                    <ShieldAlert size={14} color="#ef4444" /> Prohibit Adult & Gambling Sites (24/7)
                  </strong>
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
                  <strong style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                    <Radar size={14} color="#38bdf8" /> Passive Network DNS Sniffer Active
                  </strong>
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
