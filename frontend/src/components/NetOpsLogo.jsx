import React from "react";

export default function NetOpsLogo({ size = 36, className = "", style = {} }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 100 100"
      width={size}
      height={size}
      fill="none"
      className={className}
      style={{ display: "inline-block", verticalAlign: "middle", ...style }}
    >
      <defs>
        <linearGradient id="logoShieldBg" x1="50" y1="8" x2="50" y2="94" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#0f172a" />
          <stop offset="50%" stopColor="#0a0f1d" />
          <stop offset="100%" stopColor="#020617" />
        </linearGradient>

        <linearGradient id="logoBorderGrad" x1="15" y1="8" x2="85" y2="94" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#38bdf8" />
          <stop offset="35%" stopColor="#2563eb" />
          <stop offset="70%" stopColor="#6366f1" />
          <stop offset="100%" stopColor="#06b6d4" />
        </linearGradient>

        <linearGradient id="logoTraceGrad" x1="30" y1="30" x2="70" y2="70" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#38bdf8" />
          <stop offset="50%" stopColor="#60a5fa" />
          <stop offset="100%" stopColor="#06b6d4" />
        </linearGradient>

        <filter id="logoGlow" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="2.5" result="blur" />
          <feComposite in="SourceGraphic" in2="blur" operator="over" />
        </filter>

        <filter id="logoCoreGlow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feComposite in="SourceGraphic" in2="blur" operator="over" />
        </filter>
      </defs>

      {/* Cyber Shield Contour */}
      <path
        d="M50 7 L86 23 C86 23 87 53 86 54 C84 74 68 89 50 95 C32 89 16 74 14 54 C13 53 14 23 14 23 L50 7 Z"
        fill="url(#logoShieldBg)"
        stroke="url(#logoBorderGrad)"
        strokeWidth="3.2"
        strokeLinejoin="round"
      />

      {/* Inner Inset Path */}
      <path
        d="M50 13 L80 26.5 C80 26.5 81 50 80 51 C78 68 64 81 50 87 C36 81 22 68 20 51 C19 50 20 26.5 20 26.5 L50 13 Z"
        stroke="#1e293b"
        strokeWidth="1.5"
        fill="none"
      />

      {/* Bus Data Links */}
      <path d="M22 50 L34 50" stroke="#0ea5e9" strokeWidth="1.5" strokeOpacity="0.6" strokeLinecap="round" />
      <path d="M66 50 L78 50" stroke="#0ea5e9" strokeWidth="1.5" strokeOpacity="0.6" strokeLinecap="round" />
      <path d="M50 18 L50 32" stroke="#38bdf8" strokeWidth="1.5" strokeOpacity="0.5" strokeLinecap="round" strokeDasharray="2 3" />
      <path d="M50 68 L50 82" stroke="#38bdf8" strokeWidth="1.5" strokeOpacity="0.5" strokeLinecap="round" strokeDasharray="2 3" />

      {/* Stylized 'N' Network Circuit */}
      <g filter="url(#logoGlow)">
        <path d="M34 32 L66 68" stroke="url(#logoTraceGrad)" strokeWidth="3.5" strokeLinecap="round" />
        <path d="M34 68 L34 32" stroke="url(#logoTraceGrad)" strokeWidth="3.5" strokeLinecap="round" />
        <path d="M66 68 L66 32" stroke="url(#logoTraceGrad)" strokeWidth="3.5" strokeLinecap="round" />
      </g>

      <path d="M34 50 L66 50" stroke="#06b6d4" strokeWidth="1.5" strokeOpacity="0.7" strokeDasharray="3 3" />

      {/* Peripheral Nodes */}
      <circle cx="22" cy="50" r="2.5" fill="#38bdf8" opacity="0.8" />
      <circle cx="78" cy="50" r="2.5" fill="#38bdf8" opacity="0.8" />
      <circle cx="50" cy="18" r="2" fill="#06b6d4" opacity="0.7" />
      <circle cx="50" cy="82" r="2" fill="#06b6d4" opacity="0.7" />

      {/* Primary Corner Nodes */}
      <circle cx="34" cy="32" r="4.5" fill="#0f172a" stroke="#38bdf8" strokeWidth="2.5" />
      <circle cx="34" cy="32" r="2" fill="#38bdf8" />

      <circle cx="34" cy="68" r="4.5" fill="#0f172a" stroke="#2563eb" strokeWidth="2.5" />
      <circle cx="34" cy="68" r="2" fill="#60a5fa" />

      <circle cx="66" cy="32" r="4.5" fill="#0f172a" stroke="#6366f1" strokeWidth="2.5" />
      <circle cx="66" cy="32" r="2" fill="#818cf8" />

      <circle cx="66" cy="68" r="4.5" fill="#0f172a" stroke="#06b6d4" strokeWidth="2.5" />
      <circle cx="66" cy="68" r="2" fill="#22d3ee" />

      {/* Center Security Core Node */}
      <circle cx="50" cy="50" r="7" fill="#06b6d4" fillOpacity="0.18" />
      <circle cx="50" cy="50" r="4.5" fill="#0f172a" stroke="#10b981" strokeWidth="2" filter="url(#logoCoreGlow)" />
      <circle cx="50" cy="50" r="2.2" fill="#10b981" />
    </svg>
  );
}
