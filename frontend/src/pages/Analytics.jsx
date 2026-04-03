import React, { useState, useMemo } from 'react';
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell
} from 'recharts';
import { ComposableMap, Geographies, Geography, Marker } from 'react-simple-maps';
import { generateRequestVolumeData, generateLatencyBuckets, generateGeoData } from '../data/mockData';

const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="glass-panel" style={{ padding: '0.75rem 1rem', borderRadius: 'var(--radius-md)' }}>
      <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.25rem' }}>{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ fontSize: '0.8125rem', color: p.color || 'var(--on-surface)' }}>
          {p.name}: {p.value?.toLocaleString()}
        </div>
      ))}
    </div>
  );
}

export default function Analytics() {
  const [timeRange, setTimeRange] = useState('24H');
  const volumeData = useMemo(() => generateRequestVolumeData(), []);
  const latencyData = useMemo(() => generateLatencyBuckets(), []);
  const geoData = useMemo(() => generateGeoData(), []);
  const [aiTipVisible, setAiTipVisible] = useState(true);
  const [hoveredGeo, setHoveredGeo] = useState(null);

  const maxLatency = Math.max(...latencyData.map((d) => d.count));

  const attackVectors = [
    { label: 'Prompt Injection', pct: 42, color: '#00ff9d' },
    { label: 'Jailbreak Attempts', pct: 28, color: '#00e3fd' },
    { label: 'System Prompt Leaks', pct: 18, color: '#e4c44f' },
    { label: 'Social Engineering', pct: 12, color: '#849587' },
  ];

  return (
    <div className="fade-in-up">
      {/* Hero Stats */}
      <div className="stat-grid stat-grid-4" style={{ marginBottom: '2rem' }}>
        <div className="glass-panel stat-card light-cap emerald-glow">
          <div className="label" style={{ color: 'var(--outline)' }}>Throughput</div>
          <div className="stat-value" style={{ color: 'var(--primary-container)' }}>1.24 TB/s</div>
          <div className="progress-bar" style={{ marginTop: '0.5rem' }}>
            <div className="progress-bar-fill" style={{ width: '78%' }} />
          </div>
        </div>
        <div className="glass-panel stat-card light-cap emerald-glow">
          <div className="label" style={{ color: 'var(--outline)' }}>Active Nodes</div>
          <div className="stat-value">8,422</div>
          <div className="stat-delta" style={{ color: 'var(--primary-container)' }}>
            <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>trending_up</span>
            +12%
          </div>
        </div>
        <div className="glass-panel stat-card light-cap emerald-glow">
          <div className="label" style={{ color: 'var(--outline)' }}>Threats Neutralized</div>
          <div className="stat-value" style={{ color: 'var(--error)' }}>42.8k</div>
          <div style={{ display: 'flex', gap: '2px', marginTop: '0.5rem' }}>
            {[0.3, 0.5, 0.7, 0.9, 0.6, 0.8, 0.4].map((o, i) => (
              <div key={i} style={{ width: '8px', height: '8px', background: 'var(--error)', opacity: o, borderRadius: '1px' }} />
            ))}
          </div>
        </div>
        <div className="glass-panel stat-card light-cap emerald-glow">
          <div className="label" style={{ color: 'var(--outline)' }}>Global Health</div>
          <div className="stat-value" style={{ color: 'var(--primary-container)' }}>99.98%</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
            <div className="pulse-dot-sm" />
            <span className="label" style={{ color: 'var(--primary-container)' }}>SECURE_ESTABLISHED</span>
          </div>
        </div>
      </div>

      {/* Main Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.5rem', marginBottom: '1.5rem' }}>
        {/* Request Volume Chart */}
        <div className="glass-card emerald-glow" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h3 style={{ fontFamily: 'var(--font-headline)', fontSize: '1.125rem', color: 'var(--primary)' }}>Request Volume</h3>
            <div style={{ display: 'flex', gap: '0' }}>
              {['24H', '7D', '30D'].map((t) => (
                <button
                  key={t}
                  onClick={() => setTimeRange(t)}
                  style={{
                    background: 'none',
                    border: 'none',
                    borderBottom: timeRange === t ? '1px solid var(--primary-container)' : '1px solid transparent',
                    padding: '0.25rem 0.75rem',
                    fontSize: '10px',
                    textTransform: 'uppercase',
                    letterSpacing: '0.15em',
                    color: timeRange === t ? 'var(--primary-container)' : 'var(--outline)',
                    transition: 'all 0.2s',
                  }}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={volumeData}>
              <defs>
                <linearGradient id="volGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#00ff9d" stopOpacity={0.25} />
                  <stop offset="100%" stopColor="#00ff9d" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#3b4a3f" strokeOpacity={0.3} />
              <XAxis dataKey="hour" tick={{ fontSize: 10, fill: '#849587' }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 10, fill: '#849587' }} tickLine={false} axisLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="requests" stroke="#00ff9d" fill="url(#volGrad)" strokeWidth={2} name="Requests" />
              <Area type="monotone" dataKey="blocked" stroke="#ffb4ab" fill="none" strokeWidth={1.5} strokeDasharray="4 4" name="Blocked" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Attack Vectors */}
        <div className="glass-card emerald-glow" style={{ padding: '1.5rem' }}>
          <h3 style={{ fontFamily: 'var(--font-headline)', fontSize: '1.125rem', color: 'var(--primary)', marginBottom: '1.5rem' }}>Attack Vectors</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {attackVectors.map((v, i) => (
              <div key={i}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.375rem' }}>
                  <span style={{ fontSize: '0.8125rem', color: 'var(--on-surface-variant)' }}>{v.label}</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', color: v.color }}>{v.pct}%</span>
                </div>
                <div style={{ width: '100%', height: '6px', background: 'var(--surface-container)', borderRadius: '3px', overflow: 'hidden' }}>
                  <div style={{
                    width: `${v.pct}%`,
                    height: '100%',
                    background: v.color,
                    borderRadius: '3px',
                    boxShadow: `0 0 8px ${v.color}40`,
                    transition: 'width 1s ease',
                  }} />
                </div>
              </div>
            ))}
          </div>
          <p style={{ fontStyle: 'italic', fontSize: '0.75rem', color: 'var(--outline)', marginTop: '1.5rem', lineHeight: '1.5' }}>
            "Sentry AI detects a 23% surge in multi-vector injection attacks targeting fintech endpoints. 
            Recommend enabling enhanced Hinglish pattern detection."
          </p>
        </div>
      </div>

      {/* Second Row */}
      <div style={{ display: 'grid', gridTemplateColumns: '7fr 5fr', gap: '1.5rem', marginBottom: '1.5rem' }}>
        {/* Geo Distribution */}
        <div className="glass-card emerald-glow" style={{ padding: '1.5rem' }}>
          <h3 style={{ fontFamily: 'var(--font-headline)', fontSize: '1.125rem', color: 'var(--primary)', marginBottom: '1rem' }}>Geo-Distribution</h3>
          <div style={{ position: 'relative' }}>
            <ComposableMap
              projection="geoMercator"
              projectionConfig={{ scale: 110, center: [0, 35] }}
              style={{ width: '100%', height: 'auto' }}
            >
              <Geographies geography={GEO_URL}>
                {({ geographies }) =>
                  geographies.map((geo) => (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      style={{
                        default: { fill: '#1a1c1e', stroke: '#3b4a3f', strokeWidth: 0.5 },
                        hover: { fill: '#282a2c', stroke: '#00ff9d', strokeWidth: 1 },
                        pressed: { fill: '#282a2c' },
                      }}
                    />
                  ))
                }
              </Geographies>
              {geoData.map((marker, i) => {
                const intensityColor = { high: '#ffb4ab', medium: '#00ff9d', low: '#00e3fd' };
                const size = { high: 8, medium: 5, low: 3 };
                return (
                  <Marker key={i} coordinates={marker.coords}>
                    <circle
                      r={size[marker.intensity]}
                      fill={intensityColor[marker.intensity]}
                      opacity={0.7}
                      style={{ animation: 'pulse-glow 2s ease-in-out infinite' }}
                      onMouseEnter={() => setHoveredGeo(marker)}
                      onMouseLeave={() => setHoveredGeo(null)}
                    />
                  </Marker>
                );
              })}
            </ComposableMap>
            {hoveredGeo && (
              <div className="glass-panel" style={{
                position: 'absolute',
                top: '1rem',
                right: '1rem',
                padding: '0.75rem 1rem',
                zIndex: 10,
              }}>
                <div style={{ fontWeight: 600, fontSize: '0.875rem', color: 'var(--on-surface)', marginBottom: '0.25rem' }}>{hoveredGeo.name}</div>
                <div className="label" style={{ color: hoveredGeo.intensity === 'high' ? 'var(--error)' : 'var(--primary-container)' }}>
                  {hoveredGeo.attacks.toLocaleString()} attacks
                </div>
              </div>
            )}
          </div>
          <div style={{ display: 'flex', gap: '1.5rem', marginTop: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
              <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#ffb4ab' }} />
              <span className="label" style={{ color: 'var(--outline)' }}>High Intensity</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
              <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#00ff9d' }} />
              <span className="label" style={{ color: 'var(--outline)' }}>Traffic Surge</span>
            </div>
          </div>
        </div>

        {/* Latency Distribution */}
        <div className="glass-card emerald-glow" style={{ padding: '1.5rem' }}>
          <h3 style={{ fontFamily: 'var(--font-headline)', fontSize: '1.125rem', color: 'var(--primary)', marginBottom: '1rem' }}>Latency Distribution</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={latencyData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#3b4a3f" strokeOpacity={0.3} />
              <XAxis dataKey="range" tick={{ fontSize: 10, fill: '#849587' }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 10, fill: '#849587' }} tickLine={false} axisLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="count" radius={[2, 2, 0, 0]}>
                {latencyData.map((entry, i) => (
                  <Cell
                    key={i}
                    fill={entry.count === maxLatency ? '#00ff9d' : 'rgba(0,255,157,0.15)'}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginTop: '1rem' }}>
            <div className="glass-panel" style={{ padding: '0.75rem', textAlign: 'center' }}>
              <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.25rem' }}>P95 Latency</div>
              <div style={{ fontSize: '1.25rem', fontWeight: 300, color: 'var(--secondary-container)' }}>18.4ms</div>
            </div>
            <div className="glass-panel" style={{ padding: '0.75rem', textAlign: 'center' }}>
              <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.25rem' }}>Packet Loss</div>
              <div style={{ fontSize: '1.25rem', fontWeight: 300, color: 'var(--primary-container)' }}>0.002%</div>
            </div>
          </div>
        </div>
      </div>

      {/* AI Tip Widget */}
      {aiTipVisible && (
        <div className="ai-tip-widget glass-card emerald-glow" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
            <div className="pulse-dot-sm" />
            <span className="label" style={{ color: 'var(--primary-container)' }}>Sentry AI: Optimization Tip</span>
          </div>
          <p style={{ fontSize: '0.8125rem', color: 'var(--on-surface-variant)', lineHeight: '1.5', marginBottom: '1rem' }}>
            Enable adaptive rate limiting on Node APAC-03 to reduce latency spikes by an estimated 34%.
          </p>
          <div style={{ display: 'flex', gap: '0.75rem' }}>
            <button className="btn btn-primary" style={{ padding: '0.375rem 1rem', fontSize: '9px' }}>Execute</button>
            <button className="btn btn-outline" style={{ padding: '0.375rem 1rem', fontSize: '9px' }} onClick={() => setAiTipVisible(false)}>Dismiss</button>
          </div>
        </div>
      )}

      <div className="deco-footer">
        ANALYTICS_CORE_v2.8.0 // SENTINEL_GRID_ACTIVE
      </div>
    </div>
  );
}
