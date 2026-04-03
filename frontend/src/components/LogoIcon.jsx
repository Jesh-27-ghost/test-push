import React from 'react';

export default function LogoIcon({ size = 40, color = 'currentColor' }) {
  // A mathematically smoothed shield path with soft rounded corners using elliptical arcs
  const shieldPath = "M 58.5 13.4 A 4 4 0 0 0 51.3 13.4 L 33.7 20.5 A 4 4 0 0 0 30 26 V 52 C 30 72 40 85 52 91 A 4 4 0 0 0 58 91 C 70 85 80 72 80 52 V 26 A 4 4 0 0 0 76.3 20.5 Z";


  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 100 100"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      style={{ overflow: 'visible' }}
    >
      <defs>
        <linearGradient id="shieldGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity={0.4} />
          <stop offset="100%" stopColor={color} stopOpacity={0.05} />
        </linearGradient>
      </defs>

      {/* Back shield (Shifted Left & slightly Down) */}
      <path
        d={shieldPath}
        fill="url(#shieldGrad)"
        stroke={color}
        strokeWidth={6}
        opacity={0.2}
        strokeLinejoin="round"
        transform="translate(-20, 8)"
      />
      
      {/* Middle shield */}
      <path
        d={shieldPath}
        fill="url(#shieldGrad)"
        stroke={color}
        strokeWidth={6}
        opacity={0.5}
        strokeLinejoin="round"
        transform="translate(-10, 4)"
      />
      
      {/* Front shield (Anchor) */}
      <path
        d={shieldPath}
        fill="url(#shieldGrad)"
        stroke={color}
        strokeWidth={6}
        opacity={1}
        strokeLinejoin="round"
      />
    </svg>
  );
}
