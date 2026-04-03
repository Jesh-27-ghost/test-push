import React, { useState, useEffect, useRef } from 'react';
import { generateInterceptionFeed, generateNewIntercept } from '../data/mockData';

function DonutChart() {
  const segments = [
    { label: 'Injection', pct: 58, color: '#00ff9d' },
    { label: 'Spoofing', pct: 29, color: '#00e3fd' },
    { label: 'Overflow', pct: 13, color: '#e4c44f' },
  ];
  const radius = 70;
  const cx = 90;
  const cy = 90;
  const strokeWidth = 18;
  const circ = 2 * Math.PI * radius;
  let offset = 0;

  return (
    <div className="donut-chart" style={{ width: '180px', height: '180px', margin: '0 auto' }}>
      <svg width="180" height="180" viewBox="0 0 180 180">
        {segments.map((seg, i) => {
          const dash = (seg.pct / 100) * circ;
          const gap = circ - dash;
          const currentOffset = offset;
          offset += dash;
          return (
            <circle
              key={i}
              cx={cx}
              cy={cy}
              r={radius}
              fill="none"
              stroke={seg.color}
              strokeWidth={strokeWidth}
              strokeDasharray={`${dash} ${gap}`}
              strokeDashoffset={-currentOffset}
              transform={`rotate(-90 ${cx} ${cy})`}
              style={{ opacity: 0.85 }}
            />
          );
        })}
      </svg>
      <div className="donut-center-text">
        <div style={{ fontSize: '1.25rem', fontWeight: 600, color: 'var(--primary)' }}>276</div>
        <div className="label" style={{ color: 'var(--outline)' }}>Active Hits</div>
      </div>
    </div>
  );
}

export default function Overview() {
  const [feed, setFeed] = useState(() => generateInterceptionFeed(12));
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [stats, setStats] = useState({
    blockRate: 97.4,
    threats: 1247,
    latency: 12,
    nodes: 8,
  });
  const feedRef = useRef(feed);
  feedRef.current = feed;

  // Live feed — every 3s
  useEffect(() => {
    if (!autoRefresh) return;
    const iv = setInterval(() => {
      const newItem = generateNewIntercept();
      setFeed((prev) => [newItem, ...prev.slice(0, 19)]);
    }, 3000);
    return () => clearInterval(iv);
  }, [autoRefresh]);

  // Stats refresh — every 10s
  useEffect(() => {
    const iv = setInterval(() => {
      setStats({
        blockRate: (97 + Math.random() * 2.5).toFixed(1),
        threats: 1247 + Math.floor(Math.random() * 20),
        latency: (10 + Math.random() * 8).toFixed(0),
        nodes: 8 + Math.floor(Math.random() * 3),
      });
    }, 10000);
    return () => clearInterval(iv);
  }, []);

  const severityBadge = (sev) => {
    const map = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low' };
    return <span className={`badge ${map[sev] || 'badge-low'}`}>{sev}</span>;
  };

  return (
    <div className="fade-in-up">
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '2rem' }}>
        <div>
          <h1 style={{ fontFamily: 'var(--font-headline)', fontSize: '2.25rem', color: 'var(--primary)', marginBottom: '0.5rem' }}>
            Network Sovereignty Overview
          </h1>
          <p style={{ color: 'var(--outline)', fontSize: '0.875rem', maxWidth: '500px' }}>
            Real-time surveillance and interception metrics across all sovereign defense nodes.
          </p>
        </div>
        <div style={{ textAlign: 'right' }}>
          <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.25rem' }}>Node Location</div>
          <div className="label" style={{ color: 'var(--secondary-container)', fontSize: '11px' }}>ZURICH_VAULT_01</div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="stat-grid stat-grid-4" style={{ marginBottom: '2rem' }}>
        <div className="glass-panel stat-card light-cap emerald-glow">
          <div className="label" style={{ color: 'var(--outline)' }}>Global Efficiency</div>
          <div className="stat-value" style={{ color: 'var(--primary-container)' }}>{stats.blockRate}%</div>
          <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.5rem' }}>Overall Block Rate</div>
          <div className="progress-bar">
            <div className="progress-bar-fill" style={{ width: `${stats.blockRate}%` }} />
          </div>
        </div>

        <div className="glass-panel stat-card light-cap emerald-glow">
          <div className="label" style={{ color: 'var(--outline)' }}>Threats Neutralized</div>
          <div className="stat-value">{stats.threats.toLocaleString()}</div>
          <div className="stat-delta" style={{ color: 'var(--primary-container)' }}>
            <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>trending_up</span>
            +12.4% from last epoch
          </div>
        </div>

        <div className="glass-panel stat-card light-cap emerald-glow">
          <div className="label" style={{ color: 'var(--outline)' }}>Array Latency</div>
          <div className="stat-value" style={{ color: 'var(--secondary-container)' }}>{stats.latency}ms</div>
          <div className="label" style={{ color: 'var(--outline)' }}>AVG Response Time</div>
        </div>

        <div className="glass-panel stat-card light-cap emerald-glow">
          <div className="label" style={{ color: 'var(--outline)' }}>Sovereign Nodes</div>
          <div className="stat-value">{stats.nodes}</div>
          <div className="stat-delta" style={{ color: 'var(--primary-container)' }}>
            <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>check_circle</span>
            All Systems Operational
          </div>
        </div>
      </div>

      {/* Main Content — 3 column */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.5rem', marginBottom: '2rem' }}>
        {/* Live Interception Feed */}
        <div className="glass-card emerald-glow" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <span className="material-symbols-outlined" style={{ color: 'var(--primary-container)', fontSize: '20px' }}>stream</span>
              <span style={{ fontFamily: 'var(--font-headline)', fontSize: '1.25rem', color: 'var(--primary)' }}>Live Interception Feed</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span className="label" style={{ color: 'var(--outline)' }}>Auto-Refresh</span>
              <button
                className={`toggle-switch${autoRefresh ? ' active' : ''}`}
                onClick={() => setAutoRefresh(!autoRefresh)}
              />
            </div>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Classification</th>
                  <th>Source Vector</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {feed.map((item, i) => (
                  <tr key={item.id + i}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>{item.timestamp}</td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        {severityBadge(item.severity)}
                        <span style={{ fontSize: '0.8125rem' }}>{item.classification}</span>
                      </div>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--outline)' }}>{item.source}</td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                        <div style={{
                          width: '6px',
                          height: '6px',
                          borderRadius: '50%',
                          background: item.status === 'BLOCKED' ? 'var(--primary-container)' : 'var(--outline)',
                          boxShadow: item.status === 'BLOCKED' ? '0 0 6px var(--primary-container)' : 'none',
                        }} />
                        <span className="label" style={{ color: item.status === 'BLOCKED' ? 'var(--primary-container)' : 'var(--outline)' }}>
                          {item.status}
                        </span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Threat Vectors */}
        <div className="glass-card emerald-glow" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
            <span className="material-symbols-outlined" style={{ color: 'var(--primary-container)', fontSize: '20px' }}>pie_chart</span>
            <span style={{ fontFamily: 'var(--font-headline)', fontSize: '1.25rem', color: 'var(--primary)' }}>Threat Vectors</span>
          </div>

          <DonutChart />

          <div style={{ marginTop: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {[
              { label: 'Prompt Injection', pct: '58%', color: '#00ff9d' },
              { label: 'Identity Spoofing', pct: '29%', color: '#00e3fd' },
              { label: 'Context Overflow', pct: '13%', color: '#e4c44f' },
            ].map((item, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: item.color }} />
                <span style={{ flex: 1, fontSize: '0.8125rem', color: 'var(--on-surface-variant)' }}>{item.label}</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', color: item.color }}>{item.pct}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* System Intelligence Footer */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        <div className="glass-card emerald-glow" style={{ padding: '1.5rem', position: 'relative', overflow: 'hidden' }}>
          <div style={{ position: 'absolute', top: '-20px', right: '-20px', width: '100px', height: '100px', borderRadius: '50%', background: 'rgba(0,255,157,0.06)', filter: 'blur(30px)' }} />
          <h3 style={{ fontFamily: 'var(--font-headline)', fontSize: '1.125rem', color: 'var(--primary)', marginBottom: '1rem' }}>Neural Defense Log</h3>
          <p style={{ fontSize: '0.8125rem', color: 'var(--on-surface-variant)', lineHeight: '1.7', fontStyle: 'italic' }}>
            Sentry AI has completed its 14th cycle of deep-pattern analysis across all sovereign defense nodes. 
            The neural mesh has identified and cataloged 47 new adversarial prompt patterns within the last 24 hours, 
            including a sophisticated multi-language obfuscation technique targeting Indic language models. 
            All patterns have been integrated into the heuristic engine and distributed across the global node network. 
            Current threat landscape suggests a 23% increase in AI-targeted attacks originating from Eastern European 
            infrastructure, with particular emphasis on business logic bypass vectors targeting fintech applications.
          </p>
        </div>

        <div className="glass-card emerald-glow" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '28px', color: 'var(--primary-container)' }}>shield</span>
              <div>
                <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.25rem' }}>Sentry Integrity</div>
                <div style={{ fontSize: '1.5rem', fontWeight: 300, color: 'var(--primary)' }}>99.999%</div>
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '28px', color: 'var(--secondary-container)' }}>vpn_key</span>
              <div>
                <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.25rem' }}>Current Key Rotation</div>
                <div style={{ fontSize: '1.5rem', fontWeight: 300, color: 'var(--primary)' }}>14 Minutes</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="deco-footer">
        NODE_COORD: 47.3769° N, 8.5417° E // SOVEREIGNTY_ENGINE_v4.2.0
      </div>
    </div>
  );
}
