import React, { useEffect, useState } from "react";

export default function UsersPage({ API_URL, currentUser, getAuthHeaders }) {
  const [usersList, setUsersList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [createdResult, setCreatedResult] = useState(null);
  const [actionNotice, setActionNotice] = useState("");
  const [copiedId, setCopiedId] = useState(null);
  const [actionLoadingId, setActionLoadingId] = useState(null);

  // Edit user state
  const [editingUser, setEditingUser] = useState(null);
  const [showEditModal, setShowEditModal] = useState(false);
  const [editFormState, setEditFormState] = useState({
    username: "",
    email: "",
    phone_number: "",
    role: "user",
    password: "",
    is_active: true,
    is_verified: true,
  });
  const [editLoading, setEditLoading] = useState(false);
  const [editError, setEditError] = useState("");

  // Create user form state
  const isSuperAdmin = currentUser?.role === "super_admin";
  const [formState, setFormState] = useState({
    username: "",
    email: "",
    phone_number: "",
    role: "user",
    password: "",
  });
  const [formLoading, setFormLoading] = useState(false);
  const [formError, setFormError] = useState("");

  const loadUsers = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/users/`, {
        headers: getAuthHeaders(),
      });
      if (!res.ok) {
        throw new Error(`Failed to load users: ${res.status}`);
      }
      const data = await res.json();
      setUsersList(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error("Failed to load users:", err);
      setActionNotice("❌ Could not load users: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadUsers();
  }, []);

  const handleCreateUser = async (e) => {
    e.preventDefault();
    if (!formState.username.trim() || !formState.email.trim() || !formState.phone_number.trim() || !formState.password) {
      setFormError("All fields (Username, Email, Phone Number, Password) are required.");
      return;
    }
    if (formState.password.length < 6) {
      setFormError("Password must be at least 6 characters.");
      return;
    }

    setFormLoading(true);
    setFormError("");
    try {
      const res = await fetch(`${API_URL}/users/`, {
        method: "POST",
        headers: getAuthHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(formState),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Failed to create user account.");
      }
      setCreatedResult(data);
      setFormState({
        username: "",
        email: "",
        phone_number: "",
        role: "user",
        password: "",
      });
      await loadUsers();
    } catch (err) {
      setFormError(err.message || "Failed to create user.");
    } finally {
      setFormLoading(false);
    }
  };

  const handleResendActivation = async (user) => {
    setActionLoadingId(`resend-${user.id}`);
    try {
      const res = await fetch(`${API_URL}/users/${user.id}/resend-activation`, {
        method: "POST",
        headers: getAuthHeaders(),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to resend link.");
      setActionNotice(`✅ Activation link dispatched to ${user.email}!`);
      await loadUsers();
      setTimeout(() => setActionNotice(""), 6000);
    } catch (err) {
      alert("Failed to resend activation link: " + err.message);
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleDeleteUser = async (user) => {
    if (user.id === currentUser?.id) {
      alert("You cannot delete your own logged-in account.");
      return;
    }
    if (user.role === "super_admin") {
      alert("Super Administrator accounts cannot be deleted.");
      return;
    }
    if (!window.confirm(`Are you sure you want to permanently delete user account '${user.username}'?`)) {
      return;
    }

    setActionLoadingId(`delete-${user.id}`);
    try {
      const res = await fetch(`${API_URL}/users/${user.id}`, {
        method: "DELETE",
        headers: getAuthHeaders(),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to delete user.");
      setActionNotice(`✅ User '${user.username}' has been deleted.`);
      await loadUsers();
      setTimeout(() => setActionNotice(""), 6000);
    } catch (err) {
      alert("Failed to delete user: " + err.message);
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleOpenEdit = (user) => {
    if (user.role === "super_admin" && !isSuperAdmin) {
      alert("Permission Denied: Only Super Administrators can edit Super Administrator accounts.");
      return;
    }
    setEditingUser(user);
    setEditFormState({
      username: user.username || "",
      email: user.email || "",
      phone_number: user.phone_number || "",
      role: user.role || "user",
      password: "",
      is_active: user.is_active ?? true,
      is_verified: user.is_verified ?? false,
    });
    setEditError("");
    setShowEditModal(true);
  };

  const handleUpdateUser = async (e) => {
    e.preventDefault();
    if (!editingUser) return;
    if (!editFormState.username.trim() || !editFormState.email.trim() || !editFormState.phone_number.trim()) {
      setEditError("Username, Email, and Phone Number cannot be blank.");
      return;
    }
    if (editFormState.password && editFormState.password.length < 6) {
      setEditError("Password must be at least 6 characters (or leave empty to keep existing password).");
      return;
    }

    setEditLoading(true);
    setEditError("");

    const payload = {
      username: editFormState.username.trim(),
      email: editFormState.email.trim(),
      phone_number: editFormState.phone_number.trim(),
      role: editFormState.role,
      is_active: editFormState.is_active,
      is_verified: editFormState.is_verified,
    };
    if (editFormState.password && editFormState.password.trim()) {
      payload.password = editFormState.password.trim();
    }

    try {
      const res = await fetch(`${API_URL}/users/${editingUser.id}`, {
        method: "PATCH",
        headers: getAuthHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Failed to update user.");
      }
      setShowEditModal(false);
      setEditingUser(null);
      setActionNotice(`✅ User '${data.user?.username || editFormState.username}' updated successfully!`);
      await loadUsers();

      if (editingUser.id === currentUser?.id) {
        try {
          const currentStored = JSON.parse(localStorage.getItem("netops_user") || "{}");
          const updatedStored = { ...currentStored, ...data.user };
          localStorage.setItem("netops_user", JSON.stringify(updatedStored));
        } catch (_) {}
      }

      setTimeout(() => setActionNotice(""), 6000);
    } catch (err) {
      setEditError(err.message || "Failed to update user.");
    } finally {
      setEditLoading(false);
    }
  };

  const handleCopyLink = (link, id) => {
    if (!link) return;
    navigator.clipboard.writeText(link).then(() => {
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 3000);
    });
  };

  // User counts
  const totalUsers = usersList.length;
  const superAdmins = usersList.filter((u) => u.role === "super_admin").length;
  const admins = usersList.filter((u) => u.role === "admin").length;
  const normalUsers = usersList.filter((u) => u.role === "user").length;

  return (
    <div className="page users-page-root">
      <style>{`
        .users-page-root {
          padding: 24px;
        }
        .users-stats-grid {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 16px;
          margin-bottom: 24px;
        }
        @media (max-width: 900px) {
          .users-stats-grid {
            grid-template-columns: repeat(2, 1fr);
          }
        }
        .user-stat-card {
          background: #0d1526;
          border: 1px solid #1e293b;
          border-radius: 12px;
          padding: 16px 20px;
          display: flex;
          align-items: center;
          gap: 14px;
        }
        .user-stat-icon {
          width: 44px;
          height: 44px;
          border-radius: 10px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 20px;
        }
        .user-stat-icon.blue { background: rgba(37, 99, 235, 0.15); color: #60a5fa; }
        .user-stat-icon.gold { background: rgba(245, 158, 11, 0.15); color: #fbbf24; }
        .user-stat-icon.green { background: rgba(16, 185, 129, 0.15); color: #34d399; }
        .user-stat-icon.slate { background: rgba(148, 163, 184, 0.15); color: #cbd5e1; }
        .user-stat-val {
          font-size: 24px;
          font-weight: 800;
          color: #f8fafc;
          line-height: 1;
        }
        .user-stat-label {
          font-size: 12px;
          color: #94a3b8;
          margin-top: 4px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          font-weight: 600;
        }
        .user-avatar-circle {
          width: 34px;
          height: 34px;
          border-radius: 50%;
          background: linear-gradient(135deg, #2563eb, #7c3aed);
          color: #ffffff;
          font-size: 13px;
          font-weight: 700;
          display: inline-flex;
          align-items: center;
          justify-content: center;
          text-transform: uppercase;
        }
        .user-table-cell-primary {
          font-weight: 700;
          color: #f8fafc;
          font-size: 14px;
        }
        .user-table-cell-sub {
          font-size: 12px;
          color: #94a3b8;
        }
        .role-chip {
          display: inline-flex;
          align-items: center;
          gap: 5px;
          padding: 3px 8px;
          border-radius: 6px;
          font-size: 11px;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        .role-chip.super_admin {
          background: rgba(245, 158, 11, 0.15);
          color: #fbbf24;
          border: 1px solid rgba(245, 158, 11, 0.4);
        }
        .role-chip.admin {
          background: rgba(37, 99, 235, 0.15);
          color: #60a5fa;
          border: 1px solid rgba(37, 99, 235, 0.4);
        }
        .role-chip.user {
          background: rgba(148, 163, 184, 0.15);
          color: #cbd5e1;
          border: 1px solid rgba(148, 163, 184, 0.3);
        }
        .modal-overlay {
          position: fixed;
          inset: 0;
          background: rgba(0, 0, 0, 0.75);
          backdrop-filter: blur(4px);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 9999;
          padding: 20px;
        }
        .user-modal-box {
          background: #0d1526;
          border: 1px solid #1e293b;
          border-radius: 16px;
          padding: 28px;
          width: 100%;
          max-width: 520px;
          box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7);
        }
        .copy-pill-btn {
          background: #1e293b;
          border: 1px solid #334155;
          color: #60a5fa;
          padding: 4px 8px;
          border-radius: 6px;
          font-size: 11px;
          cursor: pointer;
          transition: all 0.2s;
        }
        .copy-pill-btn:hover {
          background: #2563eb;
          color: #ffffff;
        }
      `}</style>

      {/* HEADER */}
      <div className="page-header" style={{ marginBottom: "20px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <div className="page-title" style={{ fontSize: "22px", fontWeight: "800", color: "#f8fafc" }}>
            User Management & RBAC Access
          </div>
          <div className="page-description" style={{ color: "#94a3b8", fontSize: "13px", marginTop: "4px" }}>
            Super Administrators and Administrators can manage console users, assign permissions, and send email activation login links.
          </div>
        </div>

        <button
          className="primary-button"
          type="button"
          onClick={() => {
            setShowCreateModal(true);
            setCreatedResult(null);
            setFormError("");
          }}
          style={{ display: "flex", alignItems: "center", gap: "8px", padding: "10px 18px", fontWeight: "700" }}
        >
          <span>➕</span>
          <span>Create New User</span>
        </button>
      </div>

      {/* ACTION NOTICE */}
      {actionNotice && (
        <div style={{ background: "rgba(16, 185, 129, 0.15)", border: "1px solid rgba(16, 185, 129, 0.4)", color: "#6ee7b7", padding: "10px 16px", borderRadius: "8px", marginBottom: "20px", fontSize: "13px" }}>
          {actionNotice}
        </div>
      )}

      {/* STATS SUMMARY */}
      <div className="users-stats-grid">
        <div className="user-stat-card">
          <div className="user-stat-icon blue">👥</div>
          <div>
            <div className="user-stat-val">{totalUsers}</div>
            <div className="user-stat-label">Total Users</div>
          </div>
        </div>

        <div className="user-stat-card">
          <div className="user-stat-icon gold">👑</div>
          <div>
            <div className="user-stat-val">{superAdmins}</div>
            <div className="user-stat-label">Super Admin (Dev)</div>
          </div>
        </div>

        <div className="user-stat-card">
          <div className="user-stat-icon green">🛡️</div>
          <div>
            <div className="user-stat-val">{admins}</div>
            <div className="user-stat-label">Administrators</div>
          </div>
        </div>

        <div className="user-stat-card">
          <div className="user-stat-icon slate">👤</div>
          <div>
            <div className="user-stat-val">{normalUsers}</div>
            <div className="user-stat-label">Standard Users</div>
          </div>
        </div>
      </div>

      {/* USERS TABLE */}
      <div className="panel">
        <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
          <div>
            <div className="panel-title" style={{ fontSize: "16px", fontWeight: "700" }}>Console Accounts</div>
            <div className="panel-subtitle" style={{ fontSize: "12px", color: "#94a3b8" }}>
              Active and pending accounts registered in NETOPS.
            </div>
          </div>
          <button
            className="secondary-button small"
            type="button"
            onClick={loadUsers}
            disabled={loading}
          >
            {loading ? "Refreshing..." : "🔄 Refresh"}
          </button>
        </div>

        <div className="table-responsive">
          <table className="data-table">
            <thead>
              <tr>
                <th>User</th>
                <th>Contact Details</th>
                <th>Role & Privileges</th>
                <th>Activation Status</th>
                <th>Created</th>
                <th style={{ textAlign: "right" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {usersList.length === 0 ? (
                <tr>
                  <td colSpan="6" style={{ textAlign: "center", padding: "28px", color: "#64748b" }}>
                    {loading ? "Loading users..." : "No users found."}
                  </td>
                </tr>
              ) : (
                usersList.map((u) => {
                  const initials = (u.username || "U").slice(0, 2).toUpperCase();
                  const isCurrent = u.id === currentUser?.id;
                  return (
                    <tr key={u.id}>
                      <td>
                        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                          <div className="user-avatar-circle">{initials}</div>
                          <div>
                            <div className="user-table-cell-primary">
                              {u.username} {isCurrent && <span style={{ fontSize: "10px", color: "#60a5fa" }}>(You)</span>}
                            </div>
                            <div className="user-table-cell-sub">ID: #{u.id}</div>
                          </div>
                        </div>
                      </td>

                      <td>
                        <div style={{ fontSize: "13px", color: "#f8fafc" }}>📧 {u.email}</div>
                        <div style={{ fontSize: "12px", color: "#94a3b8" }}>📱 {u.phone_number || "No phone"}</div>
                      </td>

                      <td>
                        {u.role === "super_admin" && (
                          <span className="role-chip super_admin">👑 Developer (Super Admin)</span>
                        )}
                        {u.role === "admin" && (
                          <span className="role-chip admin">🛡️ Administrator</span>
                        )}
                        {u.role === "user" && (
                          <span className="role-chip user">👤 Standard User</span>
                        )}
                      </td>

                      <td>
                        {u.is_verified ? (
                          <span className="status-badge online" style={{ fontSize: "10px" }}>
                            🟢 Verified & Active
                          </span>
                        ) : (
                          <span className="status-badge pending" style={{ fontSize: "10px" }}>
                            🟡 Pending Activation
                          </span>
                        )}
                      </td>

                      <td>
                        <div style={{ fontSize: "12px", color: "#cbd5e1" }}>
                          {u.created_at ? new Date(u.created_at).toLocaleDateString() : "—"}
                        </div>
                      </td>

                      <td style={{ textAlign: "right" }}>
                        <div style={{ display: "flex", justifyContent: "flex-end", gap: "6px", flexWrap: "wrap" }}>
                          {/* EDIT USER */}
                          <button
                            type="button"
                            className="secondary-button small"
                            onClick={() => handleOpenEdit(u)}
                            disabled={u.role === "super_admin" && !isSuperAdmin}
                            title={u.role === "super_admin" && !isSuperAdmin ? "Only Super Admin can edit this account" : "Edit user profile, role, status & credentials"}
                            style={{ borderColor: "#3b82f6", color: "#60a5fa" }}
                          >
                            ✏️ Edit
                          </button>

                          {/* COPY ACTIVATION LINK */}
                          {u.activation_link && (
                            <button
                              type="button"
                              className="copy-pill-btn"
                              onClick={() => handleCopyLink(u.activation_link, u.id)}
                              title="Copy account activation login link to clipboard"
                            >
                              {copiedId === u.id ? "✅ Copied!" : "📋 Copy Link"}
                            </button>
                          )}

                          {/* RESEND ACTIVATION LINK */}
                          {!u.is_verified && (
                            <button
                              type="button"
                              className="secondary-button small"
                              onClick={() => handleResendActivation(u)}
                              disabled={actionLoadingId === `resend-${u.id}`}
                              title="Resend activation email to user"
                            >
                              {actionLoadingId === `resend-${u.id}` ? "Sending..." : "✉️ Resend Link"}
                            </button>
                          )}

                          {/* DELETE USER */}
                          {!isCurrent && u.role !== "super_admin" && (
                            <button
                              type="button"
                              className="secondary-button small"
                              style={{ color: "#f87171", borderColor: "#7f1d1d" }}
                              onClick={() => handleDeleteUser(u)}
                              disabled={actionLoadingId === `delete-${u.id}`}
                              title="Delete user"
                            >
                              {actionLoadingId === `delete-${u.id}` ? "..." : "🗑️ Delete"}
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

      {/* CREATE USER MODAL */}
      {showCreateModal && (
        <div className="modal-overlay" onClick={() => setShowCreateModal(false)}>
          <div className="user-modal-box" onClick={(e) => e.stopPropagation()}>
            {createdResult ? (
              /* SUCCESS STATE */
              <div>
                <div style={{ textAlign: "center", marginBottom: "16px" }}>
                  <div style={{ fontSize: "40px", marginBottom: "8px" }}>🎉</div>
                  <div style={{ fontSize: "18px", fontWeight: "800", color: "#f8fafc" }}>
                    User Account Created!
                  </div>
                  <div style={{ fontSize: "13px", color: "#94a3b8", marginTop: "4px" }}>
                    An activation link has been sent to <strong>{createdResult.user?.email}</strong>.
                  </div>
                </div>

                <div style={{ background: "#111c33", border: "1px solid #1e293b", borderRadius: "8px", padding: "14px", marginBottom: "18px" }}>
                  <div style={{ fontSize: "11px", fontWeight: "700", color: "#64748b", textTransform: "uppercase", marginBottom: "6px" }}>
                    Activation Login Link
                  </div>
                  <div style={{ wordBreak: "break-all", fontSize: "12px", color: "#60a5fa", fontFamily: "monospace", background: "#0b1120", padding: "8px", borderRadius: "6px", marginBottom: "10px" }}>
                    {createdResult.activation_link}
                  </div>
                  <button
                    type="button"
                    className="primary-button small"
                    style={{ width: "100%" }}
                    onClick={() => {
                      navigator.clipboard.writeText(createdResult.activation_link);
                      alert("Activation link copied to clipboard!");
                    }}
                  >
                    📋 Copy Activation Link
                  </button>
                </div>

                <div style={{ fontSize: "12px", color: "#94a3b8", marginBottom: "20px", lineHeight: "1.4" }}>
                  The user clicks this link in their email, which verifies access and prompts them to sign in using the password you configured.
                </div>

                <button
                  type="button"
                  className="secondary-button"
                  style={{ width: "100%" }}
                  onClick={() => {
                    setShowCreateModal(false);
                    setCreatedResult(null);
                  }}
                >
                  Close
                </button>
              </div>
            ) : (
              /* FORM STATE */
              <form onSubmit={handleCreateUser}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
                  <div>
                    <div style={{ fontSize: "18px", fontWeight: "800", color: "#f8fafc" }}>
                      Create New Account
                    </div>
                    <div style={{ fontSize: "12px", color: "#94a3b8", marginTop: "2px" }}>
                      The user will receive an email activation link to verify access before signing in.
                    </div>
                  </div>
                  <button
                    type="button"
                    style={{ background: "none", border: "none", color: "#94a3b8", fontSize: "20px", cursor: "pointer" }}
                    onClick={() => setShowCreateModal(false)}
                  >
                    ✕
                  </button>
                </div>

                {formError && (
                  <div style={{ background: "rgba(239, 68, 68, 0.15)", border: "1px solid rgba(239, 68, 68, 0.4)", color: "#fca5a5", padding: "10px 12px", borderRadius: "8px", fontSize: "12px", marginBottom: "14px" }}>
                    {formError}
                  </div>
                )}

                <div className="form-group" style={{ marginBottom: "14px" }}>
                  <label className="form-label" style={{ fontSize: "11px", fontWeight: "700", color: "#cbd5e1", display: "block", marginBottom: "4px" }}>
                    Username *
                  </label>
                  <input
                    type="text"
                    className="login-input"
                    placeholder="e.g. jdoe"
                    value={formState.username}
                    onChange={(e) => setFormState({ ...formState, username: e.target.value })}
                    disabled={formLoading}
                    required
                  />
                </div>

                <div className="form-group" style={{ marginBottom: "14px" }}>
                  <label className="form-label" style={{ fontSize: "11px", fontWeight: "700", color: "#cbd5e1", display: "block", marginBottom: "4px" }}>
                    Email Address (For Activation Link) *
                  </label>
                  <input
                    type="email"
                    className="login-input"
                    placeholder="e.g. user@domain.com"
                    value={formState.email}
                    onChange={(e) => setFormState({ ...formState, email: e.target.value })}
                    disabled={formLoading}
                    required
                  />
                </div>

                <div className="form-group" style={{ marginBottom: "14px" }}>
                  <label className="form-label" style={{ fontSize: "11px", fontWeight: "700", color: "#cbd5e1", display: "block", marginBottom: "4px" }}>
                    Phone Number (For Password Reset OTP) *
                  </label>
                  <input
                    type="tel"
                    className="login-input"
                    placeholder="e.g. +254712345678"
                    value={formState.phone_number}
                    onChange={(e) => setFormState({ ...formState, phone_number: e.target.value })}
                    disabled={formLoading}
                    required
                  />
                </div>

                <div className="form-group" style={{ marginBottom: "14px" }}>
                  <label className="form-label" style={{ fontSize: "11px", fontWeight: "700", color: "#cbd5e1", display: "block", marginBottom: "4px" }}>
                    Role & Permissions *
                  </label>
                  <select
                    className="login-input"
                    value={formState.role}
                    onChange={(e) => setFormState({ ...formState, role: e.target.value })}
                    disabled={formLoading}
                  >
                    <option value="user">Standard User (Read-Only Monitoring)</option>
                    {isSuperAdmin && (
                      <option value="admin">Administrator (LAN Ops & User Management)</option>
                    )}
                  </select>
                </div>

                <div className="form-group" style={{ marginBottom: "20px" }}>
                  <label className="form-label" style={{ fontSize: "11px", fontWeight: "700", color: "#cbd5e1", display: "block", marginBottom: "4px" }}>
                    Initial Password (min 6 characters) *
                  </label>
                  <input
                    type="password"
                    className="login-input"
                    placeholder="Assign initial password"
                    value={formState.password}
                    onChange={(e) => setFormState({ ...formState, password: e.target.value })}
                    disabled={formLoading}
                    required
                  />
                </div>

                <div style={{ display: "flex", gap: "10px", justifyContent: "flex-end" }}>
                  <button
                    type="button"
                    className="secondary-button"
                    onClick={() => setShowCreateModal(false)}
                    disabled={formLoading}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="primary-button"
                    disabled={formLoading}
                  >
                    {formLoading ? "Creating..." : "Create & Send Activation Link"}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}

      {/* EDIT USER MODAL */}
      {showEditModal && editingUser && (
        <div className="modal-overlay" onClick={() => setShowEditModal(false)}>
          <div className="user-modal-box" onClick={(e) => e.stopPropagation()}>
            <form onSubmit={handleUpdateUser}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
                <div>
                  <div style={{ fontSize: "18px", fontWeight: "800", color: "#f8fafc" }}>
                    Edit User: {editingUser.username}
                  </div>
                  <div style={{ fontSize: "12px", color: "#94a3b8", marginTop: "2px" }}>
                    Update profile information, roles, and status for account #{editingUser.id}.
                  </div>
                </div>
                <button
                  type="button"
                  style={{ background: "none", border: "none", color: "#94a3b8", fontSize: "20px", cursor: "pointer" }}
                  onClick={() => setShowEditModal(false)}
                >
                  ✕
                </button>
              </div>

              {editError && (
                <div style={{ background: "rgba(239, 68, 68, 0.15)", border: "1px solid rgba(239, 68, 68, 0.4)", color: "#fca5a5", padding: "10px 12px", borderRadius: "8px", fontSize: "12px", marginBottom: "14px" }}>
                  {editError}
                </div>
              )}

              <div className="form-group" style={{ marginBottom: "14px" }}>
                <label className="form-label" style={{ fontSize: "11px", fontWeight: "700", color: "#cbd5e1", display: "block", marginBottom: "4px" }}>
                  Username *
                </label>
                <input
                  type="text"
                  className="login-input"
                  value={editFormState.username}
                  onChange={(e) => setEditFormState({ ...editFormState, username: e.target.value })}
                  disabled={editLoading}
                  required
                />
              </div>

              <div className="form-group" style={{ marginBottom: "14px" }}>
                <label className="form-label" style={{ fontSize: "11px", fontWeight: "700", color: "#cbd5e1", display: "block", marginBottom: "4px" }}>
                  Email Address *
                </label>
                <input
                  type="email"
                  className="login-input"
                  value={editFormState.email}
                  onChange={(e) => setEditFormState({ ...editFormState, email: e.target.value })}
                  disabled={editLoading}
                  required
                />
              </div>

              <div className="form-group" style={{ marginBottom: "14px" }}>
                <label className="form-label" style={{ fontSize: "11px", fontWeight: "700", color: "#cbd5e1", display: "block", marginBottom: "4px" }}>
                  Phone Number *
                </label>
                <input
                  type="tel"
                  className="login-input"
                  value={editFormState.phone_number}
                  onChange={(e) => setEditFormState({ ...editFormState, phone_number: e.target.value })}
                  disabled={editLoading}
                  required
                />
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "14px" }}>
                <div className="form-group">
                  <label className="form-label" style={{ fontSize: "11px", fontWeight: "700", color: "#cbd5e1", display: "block", marginBottom: "4px" }}>
                    Role & Permissions
                  </label>
                  {isSuperAdmin ? (
                    <select
                      className="login-input"
                      value={editFormState.role}
                      onChange={(e) => setEditFormState({ ...editFormState, role: e.target.value })}
                      disabled={editLoading}
                    >
                      <option value="user">Standard User</option>
                      <option value="admin">Administrator</option>
                      <option value="super_admin">Super Administrator</option>
                    </select>
                  ) : (
                    <input
                      type="text"
                      className="login-input"
                      value={editFormState.role === "admin" ? "Administrator" : "Standard User"}
                      disabled
                      style={{ opacity: 0.7 }}
                    />
                  )}
                </div>

                <div className="form-group">
                  <label className="form-label" style={{ fontSize: "11px", fontWeight: "700", color: "#cbd5e1", display: "block", marginBottom: "4px" }}>
                    Account Status
                  </label>
                  <select
                    className="login-input"
                    value={editFormState.is_active ? "active" : "inactive"}
                    onChange={(e) => setEditFormState({ ...editFormState, is_active: e.target.value === "active" })}
                    disabled={editLoading}
                  >
                    <option value="active">Active (Enabled)</option>
                    <option value="inactive">Deactivated (Blocked)</option>
                  </select>
                </div>
              </div>

              <div className="form-group" style={{ marginBottom: "14px" }}>
                <label className="form-label" style={{ fontSize: "11px", fontWeight: "700", color: "#cbd5e1", display: "block", marginBottom: "4px" }}>
                  Activation Verification
                </label>
                <select
                  className="login-input"
                  value={editFormState.is_verified ? "verified" : "pending"}
                  onChange={(e) => setEditFormState({ ...editFormState, is_verified: e.target.value === "verified" })}
                  disabled={editLoading}
                >
                  <option value="verified">Verified (Access Confirmed)</option>
                  <option value="pending">Pending Email Activation</option>
                </select>
              </div>

              <div className="form-group" style={{ marginBottom: "20px" }}>
                <label className="form-label" style={{ fontSize: "11px", fontWeight: "700", color: "#cbd5e1", display: "block", marginBottom: "4px" }}>
                  Change Password (Optional)
                </label>
                <input
                  type="password"
                  className="login-input"
                  placeholder="Leave blank to keep existing password"
                  value={editFormState.password}
                  onChange={(e) => setEditFormState({ ...editFormState, password: e.target.value })}
                  disabled={editLoading}
                />
                <div style={{ fontSize: "11px", color: "#64748b", marginTop: "3px" }}>
                  Only enter a value if you wish to reset this user's password.
                </div>
              </div>

              <div style={{ display: "flex", gap: "10px", justifyContent: "flex-end" }}>
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() => setShowEditModal(false)}
                  disabled={editLoading}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="primary-button"
                  disabled={editLoading}
                >
                  {editLoading ? "Saving Changes..." : "Save Changes"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
