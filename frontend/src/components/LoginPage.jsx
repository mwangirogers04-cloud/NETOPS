import React, { useEffect, useState } from "react";

export default function LoginPage({ API_URL, onLoginSuccess, initialActivationToken }) {
  const [mode, setMode] = useState("signin"); // "signin" | "register" | "forgot"
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const [activationNotice, setActivationNotice] = useState("");

  // Track failed login attempts: lock and prompt contact admin on 3rd failure
  const [failedAttempts, setFailedAttempts] = useState(() => {
    try {
      const saved = sessionStorage.getItem("netops_failed_login_attempts");
      return saved ? parseInt(saved, 10) : 0;
    } catch (_) {
      return 0;
    }
  });
  const [isLockedOut, setIsLockedOut] = useState(() => {
    try {
      const saved = sessionStorage.getItem("netops_failed_login_attempts");
      return saved ? parseInt(saved, 10) >= 3 : false;
    } catch (_) {
      return false;
    }
  });

  // Register account states & duplicate recheck prompts
  const [regUsername, setRegUsername] = useState("");
  const [regEmail, setRegEmail] = useState("");
  const [regPhone, setRegPhone] = useState("");
  const [regPassword, setRegPassword] = useState("");
  const [regConfirmPassword, setRegConfirmPassword] = useState("");
  const [showRegPassword, setShowRegPassword] = useState(false);
  const [emailConflictMsg, setEmailConflictMsg] = useState("");
  const [phoneConflictMsg, setPhoneConflictMsg] = useState("");
  const [usernameConflictMsg, setUsernameConflictMsg] = useState("");
  const [emailCheckedOk, setEmailCheckedOk] = useState(false);
  const [phoneCheckedOk, setPhoneCheckedOk] = useState(false);

  // Forgot password flow states
  const [forgotStep, setForgotStep] = useState(1); // 1: search identifier, 2: choose channel, 3: verify otp & reset
  const [resetMethod, setResetMethod] = useState("otp"); // "otp" | "admin"
  const [forgotIdentifier, setForgotIdentifier] = useState("");
  const [channels, setChannels] = useState(null);
  const [selectedChannel, setSelectedChannel] = useState("email");
  const [otpCode, setOtpCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [otpSecondsLeft, setOtpSecondsLeft] = useState(300);
  const [devOtpPreview, setDevOtpPreview] = useState("");

  // Admin / Developer direct password reset states (No OTP required)
  const [adminTargetUser, setAdminTargetUser] = useState("");
  const [adminAuthUsername, setAdminAuthUsername] = useState("");
  const [adminAuthPassword, setAdminAuthPassword] = useState("");
  const [showAdminAuthPassword, setShowAdminAuthPassword] = useState(false);
  const [adminNewPassword, setAdminNewPassword] = useState("");
  const [adminConfirmPassword, setAdminConfirmPassword] = useState("");
  const [showAdminNewPassword, setShowAdminNewPassword] = useState(false);

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

  // Validate password complexity: min 8 chars, 1 uppercase, 1 lowercase, 1 special character
  const getPasswordRuleStatus = (pwd = "") => ({
    minLength: pwd.length >= 8,
    hasUpper: /[A-Z]/.test(pwd),
    hasLower: /[a-z]/.test(pwd),
    hasSpecial: /[^A-Za-z0-9\s]/.test(pwd),
  });

  const validatePasswordComplexity = (pwd = "") => {
    const rules = getPasswordRuleStatus(pwd);
    if (!rules.minLength) {
      return "Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, and one special character.";
    }
    if (!rules.hasUpper) {
      return "Password must contain at least one uppercase letter (A-Z).";
    }
    if (!rules.hasLower) {
      return "Password must contain at least one lowercase letter (a-z).";
    }
    if (!rules.hasSpecial) {
      return "Password must contain at least one special character (e.g. @, #, $, %, !, &, *).";
    }
    return null;
  };

  const renderPasswordChecklist = (pwd = "") => {
    const r = getPasswordRuleStatus(pwd);
    const itemStyle = (ok) => ({
      display: "flex",
      alignItems: "center",
      gap: "6px",
      fontSize: "11px",
      fontWeight: ok ? "700" : "500",
      color: ok ? "#059669" : "#64748b",
    });
    return (
      <div
        style={{
          background: "#f8fafc",
          border: "1px solid #cbd5e1",
          borderRadius: "8px",
          padding: "8px 10px",
          marginTop: "6px",
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "4px 10px",
        }}
      >
        <div style={itemStyle(r.minLength)}>{r.minLength ? "✓" : "○"} Min 8 characters</div>
        <div style={itemStyle(r.hasUpper)}>{r.hasUpper ? "✓" : "○"} 1 Uppercase (A–Z)</div>
        <div style={itemStyle(r.hasLower)}>{r.hasLower ? "✓" : "○"} 1 Lowercase (a–z)</div>
        <div style={itemStyle(r.hasSpecial)}>{r.hasSpecial ? "✓" : "○"} 1 Special (@#$%!&*)</div>
      </div>
    );
  };

  // Recheck Email / Phone / Username availability against existing accounts
  const recheckAvailability = async ({
    usernameVal = regUsername,
    emailVal = regEmail,
    phoneVal = regPhone,
    field = "all",
  } = {}) => {
    const cleanUser = (usernameVal || "").trim();
    const cleanEmail = (emailVal || "").trim();
    const cleanPhone = (phoneVal || "").trim();

    if (!cleanUser && !cleanEmail && !cleanPhone) return { available: true };

    try {
      const res = await fetch(`${API_URL}/auth/check-availability`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: cleanUser || null,
          email: cleanEmail || null,
          phone_number: cleanPhone || null,
        }),
      });
      if (!res.ok) return { available: true };
      const data = await res.json();

      if (field === "all" || field === "email") {
        if (cleanEmail && data.email_exists) {
          setEmailConflictMsg(
            data.email_message ||
              "The email address already exists, please try another email address."
          );
          setEmailCheckedOk(false);
        } else if (cleanEmail && cleanEmail.includes("@")) {
          setEmailConflictMsg("");
          setEmailCheckedOk(true);
        } else {
          setEmailConflictMsg("");
          setEmailCheckedOk(false);
        }
      }

      if (field === "all" || field === "phone") {
        if (cleanPhone && data.phone_exists) {
          setPhoneConflictMsg(
            data.phone_message ||
              "The phone number already exists, please try another number."
          );
          setPhoneCheckedOk(false);
        } else if (cleanPhone && cleanPhone.length >= 7) {
          setPhoneConflictMsg("");
          setPhoneCheckedOk(true);
        } else {
          setPhoneConflictMsg("");
          setPhoneCheckedOk(false);
        }
      }

      if (field === "all" || field === "username") {
        if (cleanUser && data.username_exists) {
          setUsernameConflictMsg(
            data.username_message ||
              `Username '${cleanUser}' is already taken, please try another username.`
          );
        } else {
          setUsernameConflictMsg("");
        }
      }

      return data;
    } catch (_) {
      return { available: true };
    }
  };

  // Register new account handler
  const handleRegisterAccount = async (e) => {
    if (e) e.preventDefault();
    setErrorMessage("");
    setSuccessMessage("");

    if (!regUsername.trim() || !regEmail.trim() || !regPhone.trim() || !regPassword) {
      setErrorMessage("Please fill in Username, Email Address, Phone Number, and Password.");
      return;
    }
    if (regUsername.trim().length < 3) {
      setErrorMessage("Username must be at least 3 characters long.");
      return;
    }
    if (!regEmail.trim().includes("@")) {
      setErrorMessage("Please enter a valid email address.");
      return;
    }
    if (regPhone.trim().length < 7) {
      setErrorMessage("Please enter a valid phone number.");
      return;
    }
    const pwdErr = validatePasswordComplexity(regPassword);
    if (pwdErr) {
      setErrorMessage(pwdErr);
      return;
    }
    if (regPassword !== regConfirmPassword) {
      setErrorMessage("Passwords do not match.");
      return;
    }

    setLoading(true);
    try {
      // Recheck email & phone number before submitting registration
      const checkData = await recheckAvailability({
        usernameVal: regUsername,
        emailVal: regEmail,
        phoneVal: regPhone,
        field: "all",
      });

      if (checkData && checkData.available === false) {
        setErrorMessage(
          checkData.detail ||
            checkData.email_message ||
            checkData.phone_message ||
            checkData.username_message
        );
        setLoading(false);
        return;
      }

      const res = await fetch(`${API_URL}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: regUsername.trim(),
          email: regEmail.trim(),
          phone_number: regPhone.trim(),
          password: regPassword,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        const msg =
          typeof data.detail === "string"
            ? data.detail
            : "Registration failed. Please check your details.";
        if (msg.toLowerCase().includes("email")) {
          setEmailConflictMsg(msg);
          setEmailCheckedOk(false);
        }
        if (msg.toLowerCase().includes("phone") || msg.toLowerCase().includes("number")) {
          setPhoneConflictMsg(msg);
          setPhoneCheckedOk(false);
        }
        throw new Error(msg);
      }

      const createdUsername = data.user?.username || regUsername.trim();
      setRegUsername("");
      setRegEmail("");
      setRegPhone("");
      setRegPassword("");
      setRegConfirmPassword("");
      setEmailConflictMsg("");
      setPhoneConflictMsg("");
      setUsernameConflictMsg("");
      setEmailCheckedOk(false);
      setPhoneCheckedOk(false);
      setMode("signin");
      setIdentifier(createdUsername);
      setPassword("");
      setSuccessMessage(
        data.message || `✅ Account '${createdUsername}' created! Please sign in.`
      );
    } catch (err) {
      setErrorMessage(err.message || "Failed to register account.");
    } finally {
      setLoading(false);
    }
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
        const nextAttempts = failedAttempts + 1;
        setFailedAttempts(nextAttempts);
        try {
          sessionStorage.setItem("netops_failed_login_attempts", String(nextAttempts));
        } catch (_) {}

        const detailMsg = data.detail || "Authentication failed. Check your credentials.";
        const isContactAdmin =
          nextAttempts >= 3 ||
          detailMsg.toLowerCase().includes("contact the administrator");

        if (isContactAdmin) {
          setIsLockedOut(true);
          throw new Error(
            detailMsg ||
              "You have entered an incorrect password 3 times. Please contact the administrator."
          );
        }

        throw new Error(detailMsg);
      }

      // Successful sign in: reset failed attempts
      setFailedAttempts(0);
      setIsLockedOut(false);
      try {
        sessionStorage.removeItem("netops_failed_login_attempts");
      } catch (_) {}

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
      setErrorMessage("");
      setSuccessMessage(
        data.message || "A 6-digit OTP has been generated (valid for 5 minutes)."
      );
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
    const complexityErr = validatePasswordComplexity(newPassword);
    if (complexityErr) {
      setErrorMessage(complexityErr);
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
        const msg =
          typeof data.detail === "string"
            ? data.detail
            : Array.isArray(data.detail)
            ? data.detail.map((d) => d.msg || JSON.stringify(d)).join(", ")
            : "Failed to reset password.";
        throw new Error(msg);
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

  // Admin / Developer Direct Password Reset (without sending OTP to phone or email)
  const handleAdminDirectReset = async (e) => {
    if (e) e.preventDefault();
    setErrorMessage("");
    setSuccessMessage("");

    const targetIdent = (adminTargetUser || forgotIdentifier || "").trim();
    if (!targetIdent) {
      setErrorMessage("Please enter the username, email, or phone number of the user whose password you want to reset.");
      return;
    }
    if (!adminAuthUsername.trim() || !adminAuthPassword) {
      setErrorMessage("Please enter your Administrator or Developer username/email and password to authorize the reset.");
      return;
    }
    const complexityErr = validatePasswordComplexity(adminNewPassword);
    if (complexityErr) {
      setErrorMessage(complexityErr);
      return;
    }
    if (adminNewPassword !== adminConfirmPassword) {
      setErrorMessage("New passwords do not match.");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/auth/forgot-password/admin-reset`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_identifier: targetIdent,
          admin_identifier: adminAuthUsername.trim(),
          admin_password: adminAuthPassword,
          new_password: adminNewPassword,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        const msg =
          typeof data.detail === "string"
            ? data.detail
            : Array.isArray(data.detail)
            ? data.detail.map((d) => d.msg || JSON.stringify(d)).join(", ")
            : "Failed to reset user password with Admin/Developer credentials.";
        throw new Error(msg);
      }

      const resetUsername = data.username || targetIdent;
      setAdminTargetUser("");
      setAdminAuthPassword("");
      setAdminNewPassword("");
      setAdminConfirmPassword("");
      setMode("signin");
      setForgotStep(1);
      setResetMethod("otp");
      setIdentifier(resetUsername);
      setPassword("");
      setSuccessMessage(
        data.message ||
          `✅ Password for '${resetUsername}' has been directly reset using Admin/Developer rights (no OTP required).`
      );
    } catch (err) {
      setErrorMessage(err.message || "Failed to reset user password.");
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
          background: radial-gradient(circle at 50% 15%, #dbeafe 0%, #f1f5f9 70%);
          font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          color: #0f172a;
          padding: 24px 16px;
          box-sizing: border-box;
        }
        .login-card {
          width: 100%;
          max-width: 460px;
          background: #ffffff;
          border: 1px solid #cbd5e1;
          border-radius: 16px;
          padding: 36px 32px;
          box-shadow: 0 20px 40px -12px rgba(15, 23, 42, 0.12), 0 0 0 1px rgba(15, 23, 42, 0.04);
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
          box-shadow: 0 8px 20px rgba(37, 99, 235, 0.25);
          margin-bottom: 12px;
        }
        .login-brand-title {
          font-size: 24px;
          font-weight: 800;
          letter-spacing: -0.5px;
          color: #0f172a;
          margin: 0;
        }
        .login-brand-subtitle {
          font-size: 13px;
          color: #475569;
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
          background: #ecfdf5;
          border: 1px solid #6ee7b7;
          color: #065f46;
        }
        .login-alert.error {
          background: #fef2f2;
          border: 1px solid #fca5a5;
          color: #991b1b;
        }
        .login-alert.info {
          background: #eff6ff;
          border: 1px solid #93c5fd;
          color: #1e40af;
        }
        .form-group {
          margin-bottom: 18px;
        }
        .form-label {
          display: block;
          font-size: 12px;
          font-weight: 600;
          color: #334155;
          margin-bottom: 6px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        .input-wrapper {
          position: relative;
        }
        .login-input {
          width: 100%;
          background: #f8fafc;
          border: 1px solid #cbd5e1;
          border-radius: 8px;
          padding: 11px 14px;
          color: #0f172a;
          font-size: 14px;
          outline: none;
          transition: border-color 0.2s, box-shadow 0.2s;
          box-sizing: border-box;
        }
        .login-input:focus {
          border-color: #2563eb;
          background: #ffffff;
          box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15);
        }
        .password-toggle-btn {
          position: absolute;
          right: 12px;
          top: 50%;
          transform: translateY(-50%);
          background: none;
          border: none;
          color: #64748b;
          cursor: pointer;
          font-size: 14px;
          padding: 4px;
        }
        .password-toggle-btn:hover {
          color: #0f172a;
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
          color: #2563eb;
          font-size: 13px;
          cursor: pointer;
          padding: 0;
          transition: color 0.15s;
        }
        .login-link-btn:hover {
          color: #1d4ed8;
          text-decoration: underline;
        }
        .quick-roles-panel {
          margin-top: 24px;
          padding-top: 20px;
          border-top: 1px solid #e2e8f0;
        }
        .quick-roles-title {
          font-size: 11px;
          font-weight: 700;
          color: #475569;
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
          background: #f8fafc;
          border: 1px solid #cbd5e1;
          border-radius: 8px;
          padding: 8px 10px;
          color: #334155;
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
          border-color: #2563eb;
          background: #eff6ff;
          color: #1e40af;
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
          background: #f8fafc;
          border: 1px solid #cbd5e1;
          border-radius: 8px;
          cursor: pointer;
          margin-bottom: 10px;
          transition: all 0.2s;
        }
        .channel-card:hover {
          border-color: #2563eb;
        }
        .channel-card.selected {
          border-color: #2563eb;
          background: #eff6ff;
        }
        .timer-badge {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          padding: 6px 12px;
          border-radius: 20px;
          font-size: 13px;
          font-weight: 700;
          background: #eff6ff;
          color: #1d4ed8;
          margin-bottom: 16px;
        }
        .timer-badge.warning {
          background: #fef3c7;
          color: #b45309;
        }
        .timer-badge.danger {
          background: #fee2e2;
          color: #b91c1c;
        }
        .otp-input-field {
          letter-spacing: 8px;
          font-size: 22px;
          font-weight: 700;
          text-align: center;
          font-family: monospace;
        }
        .dev-preview-box {
          background: #fffbeb;
          border: 1px dashed #f59e0b;
          border-radius: 8px;
          padding: 8px 12px;
          font-size: 12px;
          color: #92400e;
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

        {/* MODE SWITCHER TABS (SIGN IN / REGISTER ACCOUNT) */}
        {mode !== "forgot" && (
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "6px",
              background: "#f1f5f9",
              padding: "4px",
              borderRadius: "10px",
              border: "1px solid #cbd5e1",
              marginBottom: "20px",
            }}
          >
            <button
              type="button"
              onClick={() => {
                setMode("signin");
                setErrorMessage("");
                setSuccessMessage("");
              }}
              style={{
                background: mode === "signin" ? "#2563eb" : "transparent",
                color: mode === "signin" ? "#ffffff" : "#475569",
                border: "none",
                borderRadius: "7px",
                padding: "9px 12px",
                fontSize: "13px",
                fontWeight: "700",
                cursor: "pointer",
                transition: "all 0.2s",
              }}
            >
              🔑 Sign In
            </button>
            <button
              type="button"
              onClick={() => {
                setMode("register");
                setErrorMessage("");
                setSuccessMessage("");
              }}
              style={{
                background: mode === "register" ? "#2563eb" : "transparent",
                color: mode === "register" ? "#ffffff" : "#475569",
                border: "none",
                borderRadius: "7px",
                padding: "9px 12px",
                fontSize: "13px",
                fontWeight: "700",
                cursor: "pointer",
                transition: "all 0.2s",
              }}
            >
              📝 Register Account
            </button>
          </div>
        )}

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

        {isLockedOut ? (
          <div
            className="login-alert error"
            style={{
              background: "#450a0a",
              border: "1px solid #ef4444",
              color: "#fecaca",
              flexDirection: "column",
              gap: "10px",
              padding: "16px",
              borderRadius: "10px",
              boxShadow: "0 4px 14px rgba(239, 68, 68, 0.25)",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "10px", width: "100%" }}>
              <span style={{ fontSize: "22px" }}>🚨</span>
              <div>
                <div style={{ fontWeight: "800", fontSize: "14px", color: "#fca5a5" }}>
                  Account Locked: 3 Incorrect Password Attempts
                </div>
                <div style={{ fontSize: "12px", color: "#f87171" }}>
                  Please contact the administrator for assistance.
                </div>
              </div>
            </div>

            <div style={{ fontSize: "13px", lineHeight: "1.5", color: "#fee2e2" }}>
              {errorMessage || "You have entered an incorrect password 3 times. Please contact the administrator to unlock your account or reset your password."}
            </div>

            <div
              style={{
                background: "rgba(0, 0, 0, 0.35)",
                border: "1px solid rgba(239, 68, 68, 0.3)",
                borderRadius: "8px",
                padding: "10px 12px",
                fontSize: "12px",
                color: "#f1f5f9",
                lineHeight: "1.6",
                width: "100%",
                boxSizing: "border-box",
              }}
            >
              <div style={{ fontWeight: "700", marginBottom: "4px", color: "#fca5a5" }}>
                📞 Administrator Contacts:
              </div>
              <div>🛡️ <strong>System Administrator:</strong> <a href="mailto:admin@netops.local" style={{ color: "#93c5fd", textDecoration: "underline" }}>admin@netops.local</a></div>
              <div>👑 <strong>Lead Developer (Super Admin):</strong> <a href="mailto:developer@netops.local" style={{ color: "#93c5fd", textDecoration: "underline" }}>developer@netops.local</a></div>
            </div>

            <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", marginTop: "4px", alignItems: "center" }}>
              <button
                type="button"
                className="login-link-btn"
                style={{
                  color: "#93c5fd",
                  fontWeight: "700",
                  textDecoration: "underline",
                  fontSize: "12px",
                }}
                onClick={() => {
                  setErrorMessage("");
                  setMode("forgot");
                  setResetMethod("admin");
                  setAdminTargetUser(identifier);
                }}
              >
                🛡️ Direct Admin / Dev Password Reset →
              </button>
              <span style={{ color: "#64748b" }}>•</span>
              <button
                type="button"
                className="login-link-btn"
                style={{
                  color: "#93c5fd",
                  fontWeight: "700",
                  textDecoration: "underline",
                  fontSize: "12px",
                }}
                onClick={() => {
                  setErrorMessage("");
                  setMode("forgot");
                  setResetMethod("otp");
                  setForgotStep(1);
                  setForgotIdentifier(identifier);
                }}
              >
                🔑 Reset with 5-Minute OTP →
              </button>
            </div>
          </div>
        ) : errorMessage ? (
          <div className="login-alert error">
            <span>⚠️</span>
            <div>{errorMessage}</div>
          </div>
        ) : null}

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
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px", flexWrap: "wrap", gap: "6px" }}>
                <label className="form-label" style={{ margin: 0 }}>Password</label>
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                  <button
                    type="button"
                    className="login-link-btn"
                    onClick={() => {
                      setErrorMessage("");
                      setSuccessMessage("");
                      setMode("forgot");
                      setResetMethod("otp");
                      setForgotStep(1);
                      setForgotIdentifier(identifier);
                    }}
                  >
                    Forgot password?
                  </button>
                  <span style={{ color: "#cbd5e1", fontSize: "12px" }}>|</span>
                  <button
                    type="button"
                    className="login-link-btn"
                    style={{ fontWeight: "700", color: "#1d4ed8" }}
                    onClick={() => {
                      setErrorMessage("");
                      setSuccessMessage("");
                      setMode("forgot");
                      setResetMethod("admin");
                      setAdminTargetUser(identifier);
                    }}
                    title="Reset any user password directly using Administrator or Developer rights without sending an OTP"
                  >
                    🛡️ Admin / Dev Reset
                  </button>
                </div>
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
              disabled={loading || isLockedOut}
              style={
                isLockedOut
                  ? {
                      background: "#7f1d1d",
                      borderColor: "#ef4444",
                      color: "#fca5a5",
                      cursor: "not-allowed",
                      opacity: 0.9,
                    }
                  : {}
              }
            >
              {loading
                ? "Authenticating..."
                : isLockedOut
                ? "🔒 Locked — Please Contact Administrator"
                : "Sign In to Console →"}
            </button>

            {isLockedOut && (
              <div style={{ textAlign: "center", marginTop: "12px" }}>
                <button
                  type="button"
                  className="login-link-btn"
                  style={{ color: "#64748b", fontSize: "12px", textDecoration: "underline" }}
                  onClick={() => {
                    setIsLockedOut(false);
                    setFailedAttempts(0);
                    setErrorMessage("");
                    setPassword("");
                    try {
                      sessionStorage.removeItem("netops_failed_login_attempts");
                    } catch (_) {}
                  }}
                >
                  🔄 Try logging in as another account
                </button>
              </div>
            )}

            <div style={{ textAlign: "center", marginTop: "14px", fontSize: "13px", color: "#94a3b8" }}>
              Don&apos;t have an account?{" "}
              <button
                type="button"
                className="login-link-btn"
                style={{ fontWeight: "700" }}
                onClick={() => {
                  setMode("register");
                  setErrorMessage("");
                  setSuccessMessage("");
                }}
              >
                Register New Account →
              </button>
            </div>

            {/* ROLE-BASED SECURITY POLICY */}
            <div className="quick-roles-panel">
              <div className="quick-roles-title">🔒 Role-Based Security Policy</div>
              <div
                style={{
                  background: "#f8fafc",
                  border: "1px solid #cbd5e1",
                  borderRadius: "8px",
                  padding: "10px 12px",
                  fontSize: "11px",
                  color: "#475569",
                  lineHeight: 1.5,
                }}
              >
                <div><strong style={{ color: "#2563eb" }}>🛡️ Administrators:</strong> Full access to LAN scanning, endpoint patching, firewall enforcement & report exports.</div>
                <div style={{ marginTop: "4px" }}><strong style={{ color: "#0f172a" }}>👤 Standard Users:</strong> Restricted to read-only Dashboard view only (LAN scan updates & report downloads disabled).</div>
              </div>
            </div>
          </form>
        )}

        {/* ======================================================== */}
        {/* VIEW 1B: REGISTER ACCOUNT (WITH EMAIL & PHONE RECHECK)   */}
        {/* ======================================================== */}
        {mode === "register" && (
          <form onSubmit={handleRegisterAccount}>
            <div className="form-group">
              <label className="form-label">Username *</label>
              <div className="input-wrapper">
                <input
                  type="text"
                  className="login-input"
                  style={
                    usernameConflictMsg
                      ? { borderColor: "#ef4444", boxShadow: "0 0 0 2px rgba(239, 68, 68, 0.2)" }
                      : {}
                  }
                  placeholder="Choose a username (min 3 chars)"
                  value={regUsername}
                  onChange={(e) => {
                    setRegUsername(e.target.value);
                    if (usernameConflictMsg) setUsernameConflictMsg("");
                  }}
                  onBlur={(e) =>
                    recheckAvailability({ usernameVal: e.target.value, field: "username" })
                  }
                  disabled={loading}
                  required
                />
              </div>
              {usernameConflictMsg && (
                <div style={{ color: "#f87171", fontSize: "12px", marginTop: "5px", fontWeight: "600" }}>
                  ⚠️ {usernameConflictMsg}
                </div>
              )}
            </div>

            <div className="form-group">
              <label className="form-label">Email Address *</label>
              <div className="input-wrapper">
                <input
                  type="email"
                  className="login-input"
                  style={
                    emailConflictMsg
                      ? { borderColor: "#ef4444", boxShadow: "0 0 0 2px rgba(239, 68, 68, 0.2)" }
                      : emailCheckedOk
                      ? { borderColor: "#10b981" }
                      : {}
                  }
                  placeholder="e.g. user@domain.com"
                  value={regEmail}
                  onChange={(e) => {
                    setRegEmail(e.target.value);
                    if (emailConflictMsg) setEmailConflictMsg("");
                    setEmailCheckedOk(false);
                  }}
                  onBlur={(e) =>
                    recheckAvailability({ emailVal: e.target.value, field: "email" })
                  }
                  disabled={loading}
                  required
                />
              </div>
              {emailConflictMsg && (
                <div style={{ color: "#f87171", fontSize: "12px", marginTop: "5px", fontWeight: "600" }}>
                  ⚠️ {emailConflictMsg}
                </div>
              )}
              {!emailConflictMsg && emailCheckedOk && (
                <div style={{ color: "#34d399", fontSize: "11px", marginTop: "4px", fontWeight: "600" }}>
                  ✓ Email address is available
                </div>
              )}
            </div>

            <div className="form-group">
              <label className="form-label">Phone Number *</label>
              <div className="input-wrapper">
                <input
                  type="tel"
                  className="login-input"
                  style={
                    phoneConflictMsg
                      ? { borderColor: "#ef4444", boxShadow: "0 0 0 2px rgba(239, 68, 68, 0.2)" }
                      : phoneCheckedOk
                      ? { borderColor: "#10b981" }
                      : {}
                  }
                  placeholder="e.g. +254712345678 or 0712345678"
                  value={regPhone}
                  onChange={(e) => {
                    setRegPhone(e.target.value);
                    if (phoneConflictMsg) setPhoneConflictMsg("");
                    setPhoneCheckedOk(false);
                  }}
                  onBlur={(e) =>
                    recheckAvailability({ phoneVal: e.target.value, field: "phone" })
                  }
                  disabled={loading}
                  required
                />
              </div>
              {phoneConflictMsg && (
                <div style={{ color: "#f87171", fontSize: "12px", marginTop: "5px", fontWeight: "600" }}>
                  ⚠️ {phoneConflictMsg}
                </div>
              )}
              {!phoneConflictMsg && phoneCheckedOk && (
                <div style={{ color: "#34d399", fontSize: "11px", marginTop: "4px", fontWeight: "600" }}>
                  ✓ Phone number is available
                </div>
              )}
            </div>

            <div className="form-group">
              <label className="form-label">Password (min 8 chars, A-Z, a-z, special) *</label>
              <div className="input-wrapper">
                <input
                  type={showRegPassword ? "text" : "password"}
                  className="login-input"
                  placeholder="e.g. SecurePass@123"
                  value={regPassword}
                  onChange={(e) => setRegPassword(e.target.value)}
                  disabled={loading}
                  required
                />
                <button
                  type="button"
                  className="password-toggle-btn"
                  onClick={() => setShowRegPassword(!showRegPassword)}
                  title={showRegPassword ? "Hide password" : "Show password"}
                >
                  {showRegPassword ? "👁️‍🗨️" : "👁️"}
                </button>
              </div>
              {renderPasswordChecklist(regPassword)}
            </div>

            <div className="form-group">
              <label className="form-label">Confirm Password *</label>
              <div className="input-wrapper">
                <input
                  type={showRegPassword ? "text" : "password"}
                  className="login-input"
                  placeholder="Confirm your password"
                  value={regConfirmPassword}
                  onChange={(e) => setRegConfirmPassword(e.target.value)}
                  disabled={loading}
                  required
                />
              </div>
            </div>

            <button
              type="submit"
              className="login-submit-btn"
              disabled={loading || Boolean(emailConflictMsg) || Boolean(phoneConflictMsg) || Boolean(usernameConflictMsg)}
            >
              {loading ? "Checking & Registering..." : "Create Account →"}
            </button>

            <div style={{ textAlign: "center", marginTop: "14px", fontSize: "13px", color: "#94a3b8" }}>
              Already have an account?{" "}
              <button
                type="button"
                className="login-link-btn"
                style={{ fontWeight: "700" }}
                onClick={() => {
                  setMode("signin");
                  setErrorMessage("");
                  setSuccessMessage("");
                }}
              >
                ← Back to Sign In
              </button>
            </div>
          </form>
        )}

        {/* ======================================================== */}
        {/* VIEW 2: FORGOT PASSWORD (OTP OR ADMIN/DEV DIRECT RESET) */}
        {/* ======================================================== */}
        {mode === "forgot" && (
          <div>
            {/* METHOD SWITCHER: OTP vs ADMIN / DEVELOPER DIRECT RESET */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: "6px",
                background: "#f1f5f9",
                padding: "4px",
                borderRadius: "10px",
                border: "1px solid #cbd5e1",
                marginBottom: "18px",
              }}
            >
              <button
                type="button"
                onClick={() => {
                  setResetMethod("otp");
                  setErrorMessage("");
                  setSuccessMessage("");
                }}
                style={{
                  background: resetMethod === "otp" ? "#2563eb" : "transparent",
                  color: resetMethod === "otp" ? "#ffffff" : "#475569",
                  border: "none",
                  borderRadius: "7px",
                  padding: "8px 10px",
                  fontSize: "12px",
                  fontWeight: "700",
                  cursor: "pointer",
                  transition: "all 0.2s",
                }}
              >
                📲 Send OTP (Email / SMS)
              </button>
              <button
                type="button"
                onClick={() => {
                  setResetMethod("admin");
                  if (!adminTargetUser && (channels?.username || forgotIdentifier)) {
                    setAdminTargetUser(channels?.username || forgotIdentifier);
                  }
                  setErrorMessage("");
                  setSuccessMessage("");
                }}
                style={{
                  background: resetMethod === "admin" ? "#2563eb" : "transparent",
                  color: resetMethod === "admin" ? "#ffffff" : "#475569",
                  border: "none",
                  borderRadius: "7px",
                  padding: "8px 10px",
                  fontSize: "12px",
                  fontWeight: "700",
                  cursor: "pointer",
                  transition: "all 0.2s",
                }}
              >
                🛡️ Admin / Dev Direct Reset
              </button>
            </div>

            {/* ==================================================== */}
            {/* ADMIN / DEVELOPER DIRECT PASSWORD RESET (NO OTP)     */}
            {/* ==================================================== */}
            {resetMethod === "admin" && (
              <form onSubmit={handleAdminDirectReset}>
                <div style={{ marginBottom: "14px" }}>
                  <div style={{ fontSize: "16px", fontWeight: "700", color: "#0f172a" }}>
                    🛡️ Admin / Developer Direct Password Reset
                  </div>
                  <div style={{ fontSize: "12px", color: "#475569", marginTop: "4px", lineHeight: 1.45 }}>
                    With <strong>Administrator</strong> or <strong>Developer (Super Admin)</strong> rights, you can directly reset a user&apos;s password here without sending OTPs to their phone number or email.
                  </div>
                </div>

                <div className="form-group">
                  <label className="form-label">User Account to Reset (Username, Email, or Phone) *</label>
                  <input
                    type="text"
                    className="login-input"
                    placeholder="e.g. jdoe, user@domain.com, or 0712345678"
                    value={adminTargetUser}
                    onChange={(e) => setAdminTargetUser(e.target.value)}
                    disabled={loading}
                    required
                    autoFocus
                  />
                </div>

                <div
                  style={{
                    background: "#eff6ff",
                    border: "1px solid #bfdbfe",
                    borderRadius: "10px",
                    padding: "12px 14px",
                    marginBottom: "16px",
                  }}
                >
                  <div style={{ fontSize: "11px", fontWeight: "800", color: "#1d4ed8", textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: "6px" }}>
                    🔐 Authorize with Admin / Developer Credentials
                  </div>
                  <div style={{ fontSize: "11px", color: "#b45309", background: "#fef3c7", border: "1px solid #fde68a", borderRadius: "6px", padding: "6px 8px", marginBottom: "10px", fontWeight: "600" }}>
                    ⚠️ Note: An Administrator cannot reset the password for the Developer (Super Admin) account.
                  </div>

                  <div className="form-group" style={{ marginBottom: "12px" }}>
                    <label className="form-label" style={{ color: "#1e3a8a" }}>
                      Admin / Developer Username or Email *
                    </label>
                    <input
                      type="text"
                      className="login-input"
                      style={{ background: "#ffffff" }}
                      placeholder="e.g. developer or admin"
                      value={adminAuthUsername}
                      onChange={(e) => setAdminAuthUsername(e.target.value)}
                      disabled={loading}
                      required
                    />
                  </div>

                  <div className="form-group" style={{ marginBottom: 0 }}>
                    <label className="form-label" style={{ color: "#1e3a8a" }}>
                      Admin / Developer Password *
                    </label>
                    <div className="input-wrapper">
                      <input
                        type={showAdminAuthPassword ? "text" : "password"}
                        className="login-input"
                        style={{ background: "#ffffff" }}
                        placeholder="Enter Admin or Developer password"
                        value={adminAuthPassword}
                        onChange={(e) => setAdminAuthPassword(e.target.value)}
                        disabled={loading}
                        required
                      />
                      <button
                        type="button"
                        className="password-toggle-btn"
                        onClick={() => setShowAdminAuthPassword(!showAdminAuthPassword)}
                        title={showAdminAuthPassword ? "Hide password" : "Show password"}
                      >
                        {showAdminAuthPassword ? "👁️‍🗨️" : "👁️"}
                      </button>
                    </div>
                  </div>
                </div>

                <div className="form-group">
                  <label className="form-label">New Password for User (min 8 chars, A-Z, a-z, special) *</label>
                  <div className="input-wrapper">
                    <input
                      type={showAdminNewPassword ? "text" : "password"}
                      className="login-input"
                      placeholder="e.g. SecurePass@123"
                      value={adminNewPassword}
                      onChange={(e) => setAdminNewPassword(e.target.value)}
                      disabled={loading}
                      required
                    />
                    <button
                      type="button"
                      className="password-toggle-btn"
                      onClick={() => setShowAdminNewPassword(!showAdminNewPassword)}
                      title={showAdminNewPassword ? "Hide password" : "Show password"}
                    >
                      {showAdminNewPassword ? "👁️‍🗨️" : "👁️"}
                    </button>
                  </div>
                  {renderPasswordChecklist(adminNewPassword)}
                </div>

                <div className="form-group">
                  <label className="form-label">Confirm New Password *</label>
                  <input
                    type={showAdminNewPassword ? "text" : "password"}
                    className="login-input"
                    placeholder="Re-enter new password"
                    value={adminConfirmPassword}
                    onChange={(e) => setAdminConfirmPassword(e.target.value)}
                    disabled={loading}
                    required
                  />
                </div>

                <button
                  type="submit"
                  className="login-submit-btn"
                  disabled={loading}
                >
                  {loading ? "Authorizing & Resetting Password..." : "🛡️ Reset User Password Now (No OTP) →"}
                </button>

                <div style={{ textAlign: "center", marginTop: "16px" }}>
                  <button
                    type="button"
                    className="login-link-btn"
                    onClick={() => {
                      setMode("signin");
                      setForgotStep(1);
                      setResetMethod("otp");
                      setErrorMessage("");
                    }}
                  >
                    ← Back to Sign In
                  </button>
                </div>
              </form>
            )}

            {/* STEP 1: IDENTIFY USER (OTP FLOW) */}
            {resetMethod === "otp" && forgotStep === 1 && (
              <form onSubmit={handleSearchChannels}>
                <div style={{ marginBottom: "16px" }}>
                  <div style={{ fontSize: "16px", fontWeight: "700", color: "#0f172a" }}>
                    Forgot Password
                  </div>
                  <div style={{ fontSize: "13px", color: "#475569", marginTop: "4px" }}>
                    Enter your username, registered email, or phone number to request a 5-minute security OTP, or use <strong>Admin / Dev Direct Reset</strong> above.
                  </div>
                </div>

                <div className="form-group">
                  <label className="form-label">Username, Email, or Phone Number</label>
                  <input
                    type="text"
                    className="login-input"
                    placeholder="e.g. developer, user@netops.local, or 0712345678"
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

            {/* STEP 2: CHOOSE OTP CHANNEL (EMAIL OR SMS OR ADMIN DIRECT RESET) */}
            {resetMethod === "otp" && forgotStep === 2 && channels && (
              <form onSubmit={handleSendOtp}>
                <div style={{ marginBottom: "16px" }}>
                  <div style={{ fontSize: "16px", fontWeight: "700", color: "#0f172a" }}>
                    Select Password Reset Method
                  </div>
                  <div style={{ fontSize: "13px", color: "#475569", marginTop: "4px" }}>
                    Dispatch a <strong>5-minute verification OTP</strong> to <strong>{channels.username}</strong>, or reset directly with Administrator / Developer rights:
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
                      <div style={{ fontWeight: "700", fontSize: "13px", color: "#0f172a" }}>
                        📧 Email Address (5-Minute OTP)
                      </div>
                      <div style={{ fontSize: "12px", color: "#475569" }}>
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
                      <div style={{ fontWeight: "700", fontSize: "13px", color: "#0f172a" }}>
                        📱 SMS / Mobile Phone (5-Minute OTP)
                      </div>
                      <div style={{ fontSize: "12px", color: "#475569" }}>
                        {channels.phone_masked}
                      </div>
                    </div>
                  </div>
                )}

                {/* DIRECT ADMIN / DEVELOPER RESET CARD */}
                <div
                  className="channel-card"
                  style={{
                    borderColor: "#93c5fd",
                    background: "#eff6ff",
                  }}
                  onClick={() => {
                    setAdminTargetUser(channels.username || forgotIdentifier);
                    setResetMethod("admin");
                    setErrorMessage("");
                  }}
                >
                  <span style={{ fontSize: "18px" }}>🛡️</span>
                  <div>
                    <div style={{ fontWeight: "700", fontSize: "13px", color: "#1d4ed8" }}>
                      Reset Directly with Admin / Developer Rights (No OTP)
                    </div>
                    <div style={{ fontSize: "12px", color: "#475569" }}>
                      Bypass Email/SMS OTP using Administrator or Developer credentials →
                    </div>
                  </div>
                </div>

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
            {resetMethod === "otp" && forgotStep === 3 && (
              <form onSubmit={handleResetPassword}>
                <div style={{ marginBottom: "14px", textAlign: "center" }}>
                  <div style={{ fontSize: "16px", fontWeight: "700", color: "#0f172a" }}>
                    Verify OTP & Reset Password
                  </div>
                  <div style={{ fontSize: "13px", color: "#475569", marginTop: "4px" }}>
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

                {/* DEV PREVIEW / LOCAL LAN FALLBACK OTP */}
                {devOtpPreview && (
                  <div className="dev-preview-box">
                    <span>🔑 Local LAN Fallback OTP: <strong style={{ fontSize: "15px", letterSpacing: "2px", color: "#0f172a" }}>{devOtpPreview}</strong></span>
                    <button
                      type="button"
                      style={{ background: "#2563eb", border: "none", color: "#fff", borderRadius: "4px", padding: "4px 10px", fontSize: "11px", fontWeight: "700", cursor: "pointer" }}
                      onClick={() => setOtpCode(devOtpPreview)}
                    >
                      Auto-Fill OTP
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
                  <label className="form-label">New Password (min 8 chars, A-Z, a-z, special)</label>
                  <div className="input-wrapper">
                    <input
                      type={showNewPassword ? "text" : "password"}
                      className="login-input"
                      placeholder="e.g. SecurePass@123"
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
                  {renderPasswordChecklist(newPassword)}
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
