import React from 'react';

interface LogoProps {
  className?: string;
  size?: number;
  showText?: boolean;
}

export const Logo: React.FC<LogoProps> = ({
  className = 'w-9 h-9',
  size = 36,
  showText = false,
}) => {
  return (
    <div className={`flex items-center gap-3 ${className}`}>
      <svg
        viewBox="0 0 512 512"
        width={size}
        height={size}
        className="shrink-0 drop-shadow-sm"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          <linearGradient id="logoShieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#3B82F6" />
            <stop offset="50%" stopColor="#1D4ED8" />
            <stop offset="100%" stopColor="#0F172A" />
          </linearGradient>

          <linearGradient id="logoCyanGlow" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#38BDF8" />
            <stop offset="100%" stopColor="#06B6D4" />
          </linearGradient>

          <linearGradient id="logoAccentBeam" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#93C5FD" stopOpacity="0.9" />
            <stop offset="100%" stopColor="#38BDF8" stopOpacity="0.3" />
          </linearGradient>
        </defs>

        {/* Outer Hex-Shield Body */}
        <path
          d="M256 36 L432 108 C432 272 360 396 256 468 C152 396 80 272 80 108 Z"
          fill="url(#logoShieldGrad)"
          stroke="#60A5FA"
          strokeWidth="10"
          strokeLinejoin="round"
        />

        {/* Inner Shield Trim Line */}
        <path
          d="M256 68 L404 130 C404 268 340 376 256 436 C172 376 108 268 108 130 Z"
          fill="none"
          stroke="url(#logoAccentBeam)"
          strokeWidth="5"
          strokeDasharray="14 8"
          opacity="0.8"
        />

        {/* Left Gate Pylon */}
        <path
          d="M184 190 L220 190 L220 310 L184 310 L160 250 Z"
          fill="#1E293B"
          stroke="#38BDF8"
          strokeWidth="6"
          strokeLinejoin="round"
        />

        {/* Right Gate Pylon */}
        <path
          d="M328 190 L292 190 L292 310 L328 310 L352 250 Z"
          fill="#1E293B"
          stroke="#38BDF8"
          strokeWidth="6"
          strokeLinejoin="round"
        />

        {/* Central Telemetry Pulse Radar Rings */}
        <circle
          cx="256"
          cy="250"
          r="76"
          fill="none"
          stroke="#38BDF8"
          strokeWidth="4"
          strokeDasharray="12 6"
          opacity="0.5"
        />
        <circle
          cx="256"
          cy="250"
          r="54"
          fill="none"
          stroke="#60A5FA"
          strokeWidth="5"
          opacity="0.65"
        />

        {/* Core Nexus */}
        <circle cx="256" cy="250" r="28" fill="url(#logoCyanGlow)" />
        <circle cx="256" cy="250" r="14" fill="#FFFFFF" />

        {/* Telemetry Sensor Nodes */}
        <circle cx="256" cy="136" r="11" fill="#38BDF8" />
        <line
          x1="256"
          y1="148"
          x2="256"
          y2="222"
          stroke="#38BDF8"
          strokeWidth="5"
          strokeDasharray="6 4"
          opacity="0.85"
        />

        <circle cx="256" cy="370" r="9" fill="#38BDF8" />
        <line
          x1="256"
          y1="278"
          x2="256"
          y2="361"
          stroke="#38BDF8"
          strokeWidth="5"
          strokeDasharray="6 4"
          opacity="0.85"
        />

        <circle cx="160" cy="250" r="7" fill="#60A5FA" />
        <circle cx="352" cy="250" r="7" fill="#60A5FA" />
      </svg>

      {showText && (
        <div className="flex flex-col">
          <span className="font-bold text-slate-900 text-sm tracking-tight flex items-center gap-1.5">
            Gatekeeper <span className="text-blue-600">Security</span>
          </span>
          <span className="text-[10px] text-slate-500 font-mono tracking-wider uppercase">
            Central Ingest Platform
          </span>
        </div>
      )}
    </div>
  );
};
