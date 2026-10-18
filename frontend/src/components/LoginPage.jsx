import React, { useEffect, useState } from "react";

export default function LoginPage({ API_URL, onLoginSuccess, initialActivationToken }) {
  const [mode, setMode] = useState("signin"); // "signin" | "forgot"
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const [activationNotice, setActivationNotice] = useState("");

  // Forgot password flow states
  const [forgotStep, setForgotStep] = useState(1); // 1: search identifier, 2: choose channel, 3: verify otp & reset
  const [forgotIdentifier, setForgotIdentifier] = useState("");
  const [channels, setChannels] = useState(null);
  const [selectedChannel, setSelectedChannel] = useState("email");
  const [otpCode, setOtpCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [otpSecondsLeft, setOtpSecondsLeft] = useState(300);
  const [devOtpPreview, setDevOtpPreview] = useState("");

  // Handle auto-activation when URL has ?activation_token=...
  useEffect(() => {
    if (!initialActivationToken) return;
    setLoading(true);
    setErrorMessage("");
    fetch(`${API_URL}/auth/activate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ activation_token: initialActivationToken }),
    })
      .then(async (res) => {
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          throw new Error(data.detail || "Activation token is invalid or has expired.");
        }
        setActivationNotice(
          `🎉 Account for '${data.username}' successfully activated! Please enter your password to sign in.`
        );
        if (data.username) {
          setIdentifier(data.username);
        }
        try {
          window.history.replaceState({}, document.title, window.location.pathname);
        } catch (_) {}
      })
      .catch((err) => {
        setErrorMessage(err.message || "Failed to activate account with link.");
      })
      .finally(() => setLoading(false));
  }, [initialActivationToken, API_URL]);

  // 5-minute countdown timer for OTP
  useEffect(() => {
    if (mode !== "forgot" || forgotStep !== 3 || otpSecondsLeft <= 0) return;
    const interval = setInterval(() => {
      setOtpSecondsLeft((prev) => {
        if (prev <= 1) {
          clearInterval(interval);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [mode, forgotStep, otpSecondsLeft]);

  const formatTimer = (seconds) => {
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`;
  };

  // Sign In handler
  const handleSignIn = async (e) => {
    if (e) e.preventDefault();
    if (!identifier.trim() || !password) {
      setErrorMessage("Please enter both username/email and password.");
      return;
    }
    setLoading(true);
    setErrorMessage("");
    try {
      const response = await fetch(`${API_URL}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: identifier.trim(),
          password: password,
        }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Authentication failed. Check your credentials.");
      }
      onLoginSuccess(data.user, data.access_token);
    } catch (err) {
      setErrorMessage(err.message || "Sign in failed.");
    } finally {
      setLoading(false);
    }
  };

  // Forgot Password: Step 1 (Search account)
  const handleSearchChannels = async (e) => {
    if (e) e.preventDefault();
    if (!forgotIdentifier.trim()) {
      setErrorMessage("Please enter your username or registered email.");
      return;
    }
    setLoading(true);
    setErrorMessage("");
    try {
      const res = await fetch(`${API_URL}/auth/forgot-password/channels`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ identifier: forgotIdentifier.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "No account found matching this identifier.");
      }
      setChannels(data);
      setSelectedChannel(data.has_email ? "email" : "sms");
      setForgotStep(2);
    } catch (err) {
      setErrorMessage(err.message || "Could not find account.");
    } finally {
      setLoading(false);
    }
  };

  // Forgot Password: Step 2 (Send 5-min OTP)
  const handleSendOtp = async (e) => {
    if (e) e.preventDefault();
    setLoading(true);
    setErrorMessage("");
    try {
      const res = await fetch(`${API_URL}/auth/forgot-password/send-otp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          identifier: forgotIdentifier.trim(),
          channel: selectedChannel,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Failed to dispatch OTP.");
      }
      setOtpSecondsLeft(300); // 5 minutes strictly
      setDevOtpPreview(data.dev_otp_preview || "");
      setForgotStep(3);
      setSuccessMessage(data.message || "A 6-digit OTP has been dispatched.");
    } catch (err) {
      setErrorMessage(err.message || "Failed to dispatch OTP.");
    } finally {
      setLoading(false);
    }
  };

  // Forgot Password: Step 3 (Reset Password with OTP)
  const handleResetPassword = async (e) => {
    if (e) e.preventDefault();
    if (!otpCode.trim()) {
      setErrorMessage("Please enter the 6-digit OTP code.");
      return;
    }
    if (newPassword.length < 6) {
      setErrorMessage("New password must be at least 6 characters long.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setErrorMessage("Passwords do not match.");
      return;
    }
    if (otpSecondsLeft <= 0) {
      setErrorMessage("The OTP has expired (5-minute limit exceeded). Please request a new OTP.");
      return;
    }

    setLoading(true);
    setErrorMessage("");
    try {
      const res = await fetch(`${API_URL}/auth/forgot-password/reset`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          identifier: forgotIdentifier.trim(),
          otp_code: otpCode.trim(),
          new_password: newPassword,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Failed to reset password.");
      }
      setMode("signin");
      setForgotStep(1);
      setIdentifier(forgotIdentifier);
      setPassword("");
      setSuccessMessage("✅ Password reset successfully! You can now sign in with your new password.");
    } catch (err) {
      setErrorMessage(err.message || "Failed to reset password.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-root">
      <style>{`
        .login-root {
          min-height: 100vh;
          width: 100%;
          display: flex;
          align-items: center;
          justify-content: center;
          background: radial-gradient(circle at 50% 15%, #172554 0%, #0b1120 70%);
          font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          color: #e2e8f0;
          padding: 24px 16px;
          box-sizing: border-box;
        }
        .login-card {
          width: 100%;
          max-width: 460px;
          background: #0d1526;
          border: 1px solid #1e293b;
          border-radius: 16px;
          padding: 36px 32px;
          box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7), 0 0 0 1px rgba(255, 255, 255, 0.03);
          box-sizing: border-box;
        }
        .login-brand-header {
          text-align: center;
          margin-bottom: 28px;
        }
        .login-brand-icon {
          width: 54px;
          height: 54px;
          border-radius: 14px;
          background: linear-gradient(135deg, #2563eb 0%, #1e40af 100%);
          display: inline-flex;
          align-items: center;
          justify-content: center;
          font-size: 26px;
          color: #ffffff;
          box-shadow: 0 0 24px rgba(37, 99, 235, 0.4);
          margin-bottom: 12px;
        }
        .login-brand-title {
          font-size: 24px;
          font-weight: 800;
          letter-spacing: -0.5px;
          color: #ffffff;
          margin: 0;
        }
        .login-brand-subtitle {
          font-size: 13px;
          color: #94a3b8;
          margin-top: 4px;
        }
        .login-alert {
          border-radius: 8px;
          padding: 12px 14px;
          font-size: 13px;
          line-height: 1.4;
          margin-bottom: 20px;
          display: flex;
          align-items: flex-start;
          gap: 10px;
        }
        .login-alert.success {
          background: rgba(16, 185, 129, 0.12);
          border: 1px solid rgba(16, 185, 129, 0.4);
          color: #6ee7b7;
        }
        .login-alert.error {
          background: rgba(239, 68, 68, 0.12);
          border: 1px solid rgba(239, 68, 68, 0.4);
          color: #fca5a5;
        }
        .login-alert.info {
          background: rgba(59, 130, 246, 0.12);
          border: 1px solid rgba(59, 130, 246, 0.4);
          color: #93c5fd;
        }
        .form-group {
          margin-bottom: 18px;
        }
        .form-label {
          display: block;
          font-size: 12px;
          font-weight: 600;
          color: #cbd5e1;
          margin-bottom: 6px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        .input-wrapper {
          position: relative;
        }
        .login-input {
          width: 100%;
          background: #111c33;
          border: 1px solid #1e293b;
          border-radius: 8px;
          padding: 11px 14px;
          color: #f8fafc;
          font-size: 14px;
          outline: none;
          transition: border-color 0.2s, box-shadow 0.2s;
          box-sizing: border-box;
        }
        .login-input:focus {
          border-color: #3b82f6;
          box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
        }
        .password-toggle-btn {
          position: absolute;
          right: 12px;
          top: 50%;
          transform: translateY(-50%);
          background: none;
          border: none;
          color: #94a3b8;
          cursor: pointer;
          font-size: 14px;
          padding: 4px;
        }
        .password-toggle-btn:hover {
          color: #f8fafc;
        }
        .login-submit-btn {
          width: 100%;
          background: #2563eb;
          color: #ffffff;
          border: none;
          border-radius: 8px;
          padding: 12px 16px;
          font-size: 14px;
          font-weight: 700;
          cursor: pointer;
          transition: background 0.2s, transform 0.1s;
          margin-top: 6px;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
        }
        .login-submit-btn:hover:not(:disabled) {
          background: #1d4ed8;
        }
        .login-submit-btn:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }
        .login-link-btn {
          background: none;
          border: none;
          color: #60a5fa;
          font-size: 13px;
          cursor: pointer;
          padding: 0;
          transition: color 0.15s;
        }
        .login-link-btn:hover {
          color: #93c5fd;
          text-decoration: underline;
        }
        .quick-roles-panel {
          margin-top: 24px;
          padding-top: 20px;
          border-top: 1px solid #1e293b;
        }
        .quick-roles-title {
          font-size: 11px;
          font-weight: 700;
          color: #64748b;
          text-transform: uppercase;
          letter-spacing: 0.6px;
          margin-bottom: 10px;
          text-align: center;
        }
        .quick-chips-grid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 8px;
        }
        .quick-chip {
          background: #111c33;
          border: 1px solid #1e293b;
          border-radius: 8px;
          padding: 8px 10px;
          color: #cbd5e1;
          font-size: 12px;
          font-weight: 600;
          cursor: pointer;
          text-align: left;
          transition: all 0.2s;
          display: flex;
          flex-direction: column;
          gap: 2px;
        }
        .quick-chip:hover {
          border-color: #3b82f6;
          background: #172554;
          color: #ffffff;
        }
        .quick-chip small {
          font-size: 10px;
          color: #64748b;
        }
        .channel-card {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 12px 14px;
          background: #111c33;
          border: 1px solid #1e293b;
          border-radius: 8px;
          cursor: pointer;
          margin-bottom: 10px;
          transition: all 0.2s;
        }
        .channel-card:hover {
          border-color: #3b82f6;
        }
        .channel-card.selected {
          border-color: #3b82f6;
          background: rgba(37, 99, 235, 0.12);
        }
        .timer-badge {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          padding: 6px 12px;
          border-radius: 20px;
          font-size: 13px;
          font-weight: 700;
          background: #1e293b;
          color: #60a5fa;
          margin-bottom: 16px;
        }
        .timer-badge.warning {
          background: rgba(245, 158, 11, 0.15);
          color: #fbbf24;
        }
        .timer-badge.danger {
          background: rgba(239, 68, 68, 0.15);
          color: #f87171;
        }
        .otp-input-field {
          letter-spacing: 8px;
          font-size: 22px;
          font-weight: 700;
          text-align: center;
          font-family: monospace;
        }
        .dev-preview-box {
          background: rgba(245, 158, 11, 0.1);
          border: 1px dashed rgba(245, 158, 11, 0.5);
          border-radius: 8px;
          padding: 8px 12px;
          font-size: 12px;
          color: #fcd34d;
          margin-bottom: 16px;
          display: flex;
          align-items: center;
          justify-content: space-between;
        }
      `}</style>

      <div className="login-card">
        {/* BRAND HEADER */}
        <div className="login-brand-header">
          <div className="login-brand-icon">🛡️</div>
          <h1 className="login-brand-title">NETOPS CONSOLE</h1>
          <div className="login-brand-subtitle">
            Role-Based Network Operations & Enforcement Platform
          </div>
        </div>

        {/* ALERTS */}
        {activationNotice && (
          <div className="login-alert success">
            <span>🎉</span>
            <div>{activationNotice}</div>
          </div>
        )}

        {successMessage && (
          <div className="login-alert success">
            <span>✅</span>
            <div>{successMessage}</div>
          </div>
        )}

        {errorMessage && (
          <div className="login-alert error">
            <span>⚠️</span>
            <div>{errorMessage}</div>
          </div>
        )}

        {/* ======================================================== */}
        {/* VIEW 1: SIGN IN                                          */}
        {/* ======================================================== */}
        {mode === "signin" && (
          <form onSubmit={handleSignIn}>
            <div className="form-group">
              <label className="form-label">Username or Email</label>
              <div className="input-wrapper">
                <input
                  type="text"
                  className="login-input"
                  placeholder="e.g. developer or admin"
                  value={identifier}
                  onChange={(e) => setIdentifier(e.target.value)}
                  disabled={loading}
                  autoFocus
                />
              </div>
            </div>

            <div className="form-group">
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                <label className="form-label" style={{ margin: 0 }}>Password</label>
                <button
                  type="button"
                  className="login-link-btn"
                  onClick={() => {
                    setErrorMessage("");
                    setSuccessMessage("");
                    setMode("forgot");
                    setForgotStep(1);
                    setForgotIdentifier(identifier);
                  }}
                >
                  Forgot password?
                </button>
              </div>
              <div className="input-wrapper">
                <input
                  type={showPassword ? "text" : "password"}
                  className="login-input"
                  placeholder="Enter your password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={loading}
                />
                <button
                  type="button"
                  className="password-toggle-btn"
                  onClick={() => setShowPassword(!showPassword)}
                  title={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? "👁️‍🗨️" : "👁️"}
                </button>
              </div>
            </div>

            <button
              type="submit"
              className="login-submit-btn"
              disabled={loading}
            >
              {loading ? "Authenticating..." : "Sign In to Console →"}
            </button>

            {/* QUICK DEMO ROLES */}
            <div className="quick-roles-panel">
              <div className="quick-roles-title">Demo & Development Quick Sign In</div>
              <div className="quick-chips-grid">
                <button
                  type="button"
                  className="quick-chip"
                  onClick={() => {
                    setIdentifier("developer");
                    setPassword("Admin@1234");
                    setErrorMessage("");
                  }}
                >
                  <span>👑 Developer</span>
                  <small>Super Admin (Full Access)</small>
                </button>

                <button
                  type="button"
                  className="quick-chip"
                  onClick={() => {
                    setIdentifier("admin");
                    setPassword("Admin@1234");
                    setErrorMessage("");
                  }}
                >
                  <span>🛡️ Administrator</span>
                  <small>LAN Ops & User Admin</small>
                </button>
              </div>
            </div>
          </form>
        )}

        {/* ======================================================== */}
        {/* VIEW 2: FORGOT PASSWORD (MULTI-STEP WITH 5-MIN OTP)     */}
        {/* ======================================================== */}
        {mode === "forgot" && (
          <div>
            {/* STEP 1: IDENTIFY USER */}
            {forgotStep === 1 && (
              <form onSubmit={handleSearchChannels}>
                <div style={{ marginBottom: "16px" }}>
                  <div style={{ fontSize: "16px", fontWeight: "700", color: "#f8fafc" }}>
                    Forgot Password
                  </div>
                  <div style={{ fontSize: "13px", color: "#94a3b8", marginTop: "4px" }}>
                    Enter your username or registered email to request a 5-minute security OTP.
                  </div>
                </div>

                <div className="form-group">
                  <label className="form-label">Username or Registered Email</label>
                  <input
                    type="text"
                    className="login-input"
                    placeholder="e.g. developer or user@netops.local"
                    value={forgotIdentifier}
                    onChange={(e) => setForgotIdentifier(e.target.value)}
                    disabled={loading}
                    autoFocus
                  />
                </div>

                <button
                  type="submit"
                  className="login-submit-btn"
                  disabled={loading}
                >
                  {loading ? "Searching..." : "Find Account & Channels →"}
                </button>

                <div style={{ textAlign: "center", marginTop: "16px" }}>
                  <button
                    type="button"
                    className="login-link-btn"
                    onClick={() => {
                      setMode("signin");
                      setErrorMessage("");
                    }}
                  >
                    ← Back to Sign In
                  </button>
                </div>
              </form>
            )}

            {/* STEP 2: CHOOSE OTP CHANNEL (EMAIL OR SMS) */}
            {forgotStep === 2 && channels && (
              <form onSubmit={handleSendOtp}>
                <div style={{ marginBottom: "16px" }}>
                  <div style={{ fontSize: "16px", fontWeight: "700", color: "#f8fafc" }}>
                    Select OTP Delivery Destination
                  </div>
                  <div style={{ fontSize: "13px", color: "#94a3b8", marginTop: "4px" }}>
                    Where would you like us to dispatch your verification code? It expires in <strong>5 minutes</strong>.
                  </div>
                </div>

                {channels.has_email && (
                  <div
                    className={`channel-card ${selectedChannel === "email" ? "selected" : ""}`}
                    onClick={() => setSelectedChannel("email")}
                  >
                    <input
                      type="radio"
                      name="otp_channel"
                      checked={selectedChannel === "email"}
                      onChange={() => setSelectedChannel("email")}
                    />
                    <div>
                      <div style={{ fontWeight: "700", fontSize: "13px", color: "#f8fafc" }}>
                        📧 Email Address
                      </div>
                      <div style={{ fontSize: "12px", color: "#94a3b8" }}>
                        {channels.email_masked}
                      </div>
                    </div>
                  </div>
                )}

                {channels.has_phone && (
                  <div
                    className={`channel-card ${selectedChannel === "sms" ? "selected" : ""}`}
                    onClick={() => setSelectedChannel("sms")}
                  >
                    <input
                      type="radio"
                      name="otp_channel"
                      checked={selectedChannel === "sms"}
                      onChange={() => setSelectedChannel("sms")}
                    />
                    <div>
                      <div style={{ fontWeight: "700", fontSize: "13px", color: "#f8fafc" }}>
                        📱 SMS / Mobile Phone
                      </div>
                      <div style={{ fontSize: "12px", color: "#94a3b8" }}>
                        {channels.phone_masked}
                      </div>
                    </div>
                  </div>
                )}

                <button
                  type="submit"
                  className="login-submit-btn"
                  disabled={loading}
                >
                  {loading ? "Dispatching OTP..." : "Send 5-Minute OTP →"}
                </button>

                <div style={{ textAlign: "center", marginTop: "16px" }}>
                  <button
                    type="button"
                    className="login-link-btn"
                    onClick={() => {
                      setForgotStep(1);
                      setErrorMessage("");
                    }}
                  >
                    ← Back to Step 1
                  </button>
                </div>
              </form>
            )}

            {/* STEP 3: ENTER OTP & NEW PASSWORD */}
            {forgotStep === 3 && (
              <form onSubmit={handleResetPassword}>
                <div style={{ marginBottom: "14px", textAlign: "center" }}>
                  <div style={{ fontSize: "16px", fontWeight: "700", color: "#f8fafc" }}>
                    Verify OTP & Reset Password
                  </div>
                  <div style={{ fontSize: "13px", color: "#94a3b8", marginTop: "4px" }}>
                    Enter the 6-digit code sent to your registered {selectedChannel.toUpperCase()}.
                  </div>
                </div>

                {/* TIMER BADGE */}
                <div style={{ textAlign: "center" }}>
                  <div
                    className={`timer-badge ${
                      otpSecondsLeft <= 30
                        ? "danger"
                        : otpSecondsLeft <= 120
                        ? "warning"
                        : ""
                    }`}
                  >
                    <span>⏳</span>
                    <span>
                      {otpSecondsLeft > 0
                        ? `OTP expires in: ${formatTimer(otpSecondsLeft)}`
                        : "⚠️ OTP EXPIRED (5-minute limit exceeded)"}
                    </span>
                  </div>
                </div>

                {/* DEV PREVIEW */}
                {devOtpPreview && (
                  <div className="dev-preview-box">
                    <span>🔑 Dev Preview OTP: <strong>{devOtpPreview}</strong></span>
                    <button
                      type="button"
                      style={{ background: "#2563eb", border: "none", color: "#fff", borderRadius: "4px", padding: "2px 6px", fontSize: "10px", cursor: "pointer" }}
                      onClick={() => setOtpCode(devOtpPreview)}
                    >
                      Auto-Fill
                    </button>
                  </div>
                )}

                <div className="form-group">
                  <label className="form-label" style={{ textAlign: "center" }}>
                    6-Digit OTP Code
                  </label>
                  <input
                    type="text"
                    maxLength={6}
                    className="login-input otp-input-field"
                    placeholder="••••••"
                    value={otpCode}
                    onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, ""))}
                    disabled={loading || otpSecondsLeft <= 0}
                    autoFocus
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">New Password (min 6 characters)</label>
                  <div className="input-wrapper">
                    <input
                      type={showNewPassword ? "text" : "password"}
                      className="login-input"
                      placeholder="Enter new secure password"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      disabled={loading || otpSecondsLeft <= 0}
                    />
                    <button
                      type="button"
                      className="password-toggle-btn"
                      onClick={() => setShowNewPassword(!showNewPassword)}
                    >
                      {showNewPassword ? "👁️‍🗨️" : "👁️"}
                    </button>
                  </div>
                </div>

                <div className="form-group">
                  <label className="form-label">Confirm New Password</label>
                  <input
                    type={showNewPassword ? "text" : "password"}
                    className="login-input"
                    placeholder="Re-enter new password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    disabled={loading || otpSecondsLeft <= 0}
                  />
                </div>

                <button
                  type="submit"
                  className="login-submit-btn"
                  disabled={loading || otpSecondsLeft <= 0}
                >
                  {loading ? "Validating & Resetting..." : "Reset Password & Sign In →"}
                </button>

                <div style={{ display: "flex", justifyContent: "space-between", marginTop: "16px" }}>
                  <button
                    type="button"
                    className="login-link-btn"
                    onClick={handleSendOtp}
                    disabled={loading}
                  >
                    🔄 Resend OTP
                  </button>

                  <button
                    type="button"
                    className="login-link-btn"
                    onClick={() => {
                      setMode("signin");
                      setForgotStep(1);
                      setErrorMessage("");
                    }}
                  >
                    Cancel & Sign In
                  </button>
                </div>
              </form>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
