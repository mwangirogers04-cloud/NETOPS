import React, { useEffect, useState, useRef } from "react";

export default function WebActivityPage({
  API_URL,
  currentUser,
  getAuthHeaders,
  setActivePage,
}) {
  const [logs, setLogs] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [policy, setPolicy] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [violationsOnly, setViolationsOnly] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [showPolicyModal, setShowPolicyModal] = useState(false);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [policyNotice, setPolicyNotice] = useState("");
  const [autoRefreshSecs, setAutoRefreshSecs] = useState(5);
  const timerRef = useRef(null);

  // Fetch live activity logs
  const fetchLogs = async () => {
    try {
      let url = `${API_URL}/web-activity/logs?limit=150`;
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
    await Promise.all([fetchLogs(), fetchAnalytics(), fetchPolicy()]);
    setLoading(false);
    setRefreshing(false);
  };

  useEffect(() => {
    loadAll();
  }, [categoryFilter, violationsOnly]);

  // Auto-refresh timer
  useEffect(() => {
    if (autoRefreshSecs <= 0) return;
    const interval = setInterval(() => {
      fetchLogs();
      fetchAnalytics();
    }, autoRefreshSecs * 1000);
    return () => clearInterval(interval);
  }, [autoRefreshSecs, categoryFilter, violationsOnly]);

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
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px", flexWrap: "wrap", gap: "12px" }}>
        <div>
          <h1 style={{ fontSize: "22px", fontWeight: "800", color: "#f1f5f9", margin: "0 0 4px 0", display: "flex", alignItems: "center", gap: "8px" }}>
            <span>🌐</span> Web & Application Activity Monitor
          </h1>
          <p style={{ margin: 0, fontSize: "13px", color: "#94a3b8" }}>
            Real-time passive visibility into domains, video streams, online games, and social media accessed by connected computers.
          </p>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
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
            className="primary-button"
            onClick={loadAll}
            disabled={refreshing}
            style={{ display: "inline-flex", alignItems: "center", gap: "6px", fontSize: "12px", padding: "7px 14px", background: "#3b82f6", borderColor: "#2563eb" }}
          >
            {refreshing ? "⏳ Refreshing..." : "🔄 Refresh"}
          </button>
        </div>
      </div>

      {/* Metrics Summary Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: "14px", marginBottom: "22px" }}>
        <div style={{ background: "#1e293b", border: "1px solid #334155", borderRadius: "8px", padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "#94a3b8", textTransform: "uppercase", fontWeight: "700" }}>Total Queries (24h)</div>
          <div style={{ fontSize: "26px", fontWeight: "800", color: "#f8fafc", marginTop: "4px" }}>
            {analytics?.total_queries?.toLocaleString() ?? 0}
          </div>
          <div style={{ fontSize: "11px", color: "#64748b", marginTop: "4px" }}>Active DNS & SNI queries</div>
        </div>

        <div style={{ background: "#1e293b", border: "1px solid rgba(239, 68, 68, 0.4)", borderRadius: "8px", padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "#f87171", textTransform: "uppercase", fontWeight: "700" }}>🎬 Video Streaming</div>
          <div style={{ fontSize: "26px", fontWeight: "800", color: "#f87171", marginTop: "4px" }}>
            {analytics?.category_counts?.streaming ?? 0}
          </div>
          <div style={{ fontSize: "11px", color: "#94a3b8", marginTop: "4px" }}>YouTube, Netflix, Prime, etc.</div>
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
          <div style={{ fontSize: "11px", color: "#94a3b8", marginTop: "4px" }}>TikTok, Instagram, Facebook</div>
        </div>

        <div style={{ background: "#1e293b", border: "1px solid rgba(245, 158, 11, 0.4)", borderRadius: "8px", padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "#fbbf24", textTransform: "uppercase", fontWeight: "700" }}>⚠️ Work-Hours Violations</div>
          <div style={{ fontSize: "26px", fontWeight: "800", color: "#fbbf24", marginTop: "4px" }}>
            {analytics?.violations_count ?? 0}
          </div>
          <div style={{ fontSize: "11px", color: "#94a3b8", marginTop: "4px" }}>Prohibited streaming/gaming during 08:00–17:00</div>
        </div>
      </div>

      {/* Top Consumers Leaderboards (Streaming & Gaming) */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "22px" }}>
        {/* Top Streaming PCs */}
        <div style={{ background: "#1e293b", border: "1px solid #334155", borderRadius: "8px", padding: "16px" }}>
          <div style={{ fontSize: "13px", fontWeight: "700", color: "#f87171", display: "flex", alignItems: "center", gap: "6px", marginBottom: "12px" }}>
            <span>🎬</span> Top Video Streaming Computers
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
        <div style={{ display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" }}>
          <button
            type="button"
            className={categoryFilter === "all" && !violationsOnly ? "primary-button small" : "secondary-button small"}
            onClick={() => { setCategoryFilter("all"); setViolationsOnly(false); }}
            style={{ fontSize: "11px", padding: "4px 10px" }}
          >
            All Activity
          </button>
          <button
            type="button"
            className={violationsOnly ? "primary-button small" : "secondary-button small"}
            onClick={() => { setViolationsOnly(true); setCategoryFilter("all"); }}
            style={{ fontSize: "11px", padding: "4px 10px", background: violationsOnly ? "#dc2626" : undefined, borderColor: violationsOnly ? "#b91c1c" : undefined }}
          >
            ⚠️ Violations Only
          </button>
          <button
            type="button"
            className={categoryFilter === "streaming" ? "primary-button small" : "secondary-button small"}
            onClick={() => { setCategoryFilter("streaming"); setViolationsOnly(false); }}
            style={{ fontSize: "11px", padding: "4px 10px", background: categoryFilter === "streaming" ? "#ef4444" : undefined }}
          >
            🎬 Streaming
          </button>
          <button
            type="button"
            className={categoryFilter === "gaming" ? "primary-button small" : "secondary-button small"}
            onClick={() => { setCategoryFilter("gaming"); setViolationsOnly(false); }}
            style={{ fontSize: "11px", padding: "4px 10px", background: categoryFilter === "gaming" ? "#a855f7" : undefined }}
          >
            🎮 Gaming
          </button>
          <button
            type="button"
            className={categoryFilter === "social_media" ? "primary-button small" : "secondary-button small"}
            onClick={() => { setCategoryFilter("social_media"); setViolationsOnly(false); }}
            style={{ fontSize: "11px", padding: "4px 10px", background: categoryFilter === "social_media" ? "#3b82f6" : undefined }}
          >
            📱 Social Media
          </button>
        </div>

        <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
          <input
            type="text"
            className="form-control"
            placeholder="Search domain, IP, or machine..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{ fontSize: "12px", padding: "5px 10px", width: "230px", background: "#0f172a", border: "1px solid #334155", color: "#f8fafc", borderRadius: "4px" }}
          />

          <select
            className="form-control"
            value={autoRefreshSecs}
            onChange={(e) => setAutoRefreshSecs(parseInt(e.target.value, 10))}
            style={{ fontSize: "11px", padding: "5px 8px", background: "#0f172a", border: "1px solid #334155", color: "#94a3b8", borderRadius: "4px" }}
          >
            <option value="5">Live (5s)</option>
            <option value="15">Auto (15s)</option>
            <option value="0">Paused</option>
          </select>
        </div>
      </div>

      {/* Live Activity Table */}
      <div style={{ background: "#1e293b", border: "1px solid #334155", borderRadius: "8px", overflow: "hidden" }}>
        <table className="netops-table" style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
          <thead>
            <tr style={{ background: "#0f172a", borderBottom: "1px solid #334155", textAlign: "left", color: "#94a3b8" }}>
              <th style={{ padding: "10px 14px" }}>TIME</th>
              <th style={{ padding: "10px 14px" }}>COMPUTER / USER</th>
              <th style={{ padding: "10px 14px" }}>IP & MAC ADDRESS</th>
              <th style={{ padding: "10px 14px" }}>DOMAIN / WEBSITE</th>
              <th style={{ padding: "10px 14px" }}>CATEGORY</th>
              <th style={{ padding: "10px 14px" }}>STATUS</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan="6" style={{ textAlign: "center", padding: "30px", color: "#64748b" }}>
                  {loading ? "⏳ Loading web activity logs..." : "No web activity logs match the selected filter."}
                </td>
              </tr>
            ) : (
              filteredLogs.map((log) => {
                const badge = getCategoryBadge(log.category);
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
                  <strong>🎬 Prohibit Video Streaming during Work Hours (08:00–17:00)</strong>
                  <div style={{ fontSize: "11px", color: "#94a3b8" }}>Flags YouTube, Netflix, Prime Video, Hulu, Disney+, TikTok</div>
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
                  <div style={{ fontSize: "11px", color: "#94a3b8" }}>Flags Instagram, Facebook, TikTok, Twitter/X</div>
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
