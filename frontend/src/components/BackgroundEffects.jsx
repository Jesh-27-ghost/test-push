import React, { useMemo } from 'react';

export default function BackgroundEffects() {
  const particles = useMemo(() => {
    return Array.from({ length: 20 }, (_, i) => ({
      id: i,
      left: `${Math.random() * 100}%`,
      delay: `${(Math.random() * 5).toFixed(1)}s`,
      duration: `${(10 + Math.random() * 10).toFixed(1)}s`,
      color: i % 2 === 0 ? 'rgba(0,255,157,0.4)' : 'rgba(0,227,253,0.3)',
      size: Math.random() > 0.5 ? 2 : 3,
    }));
  }, []);

  return (
    <>
      {/* Aurora Drift */}
      <div className="aurora-bg" />

      {/* Floating Orbs */}
      <div className="orb orb-1" />
      <div className="orb orb-2" />
      <div className="orb orb-3" />

      {/* Wave Lines */}
      <div className="wave-lines">
        <svg className="wave-1" viewBox="0 0 2400 400" preserveAspectRatio="none">
          <path
            d="M0 200 C400 100 800 300 1200 200 C1600 100 2000 300 2400 200 L2400 400 L0 400 Z"
            fill="rgba(0,255,157,0.08)"
          />
        </svg>
        <svg className="wave-2" viewBox="0 0 2400 400" preserveAspectRatio="none">
          <path
            d="M0 250 C300 150 700 350 1200 250 C1700 150 2100 350 2400 250 L2400 400 L0 400 Z"
            fill="rgba(0,227,253,0.05)"
          />
        </svg>
        <svg className="wave-3" viewBox="0 0 2400 400" preserveAspectRatio="none">
          <path
            d="M0 300 C500 200 900 380 1200 300 C1500 220 1900 380 2400 300 L2400 400 L0 400 Z"
            fill="rgba(228,196,79,0.03)"
          />
        </svg>
      </div>

      {/* Particles */}
      {particles.map((p) => (
        <div
          key={p.id}
          className="particle"
          style={{
            left: p.left,
            width: `${p.size}px`,
            height: `${p.size}px`,
            background: p.color,
            animationDelay: p.delay,
            animationDuration: p.duration,
          }}
        />
      ))}

      {/* Scanline */}
      <div className="scanline" />
    </>
  );
}
