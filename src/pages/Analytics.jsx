import { useState, useEffect } from 'react';
import { api } from '../api.js';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  LineChart, Line, Area, AreaChart,
  PieChart, Pie, Cell, Label,
} from 'recharts';

const CATEGORY_COLORS = {
  jailbreak: '#ff3d5a',
  prompt_leak: '#f59e0b',
  prompt_injection: '#7c3aed',
  social_engineering: '#00d4ff',
  harmful_content: '#ef4444',
  business_logic: '#8b5cf6',
  safe: '#10b981',
};

function GlassTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="custom-tooltip">
      <div className="label">{label}</div>
      {payload.map((p, i) => (
        <div key={i} className="value" style={{ color: p.color }}>
          {p.name}: {p.value}
        </div>
      ))}
    </div>
  );
}

export default function Analytics() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    const fetchStats = async () => {
      try {
        const data = await api.stats();
        if (active) { setStats(data); setLoading(false); }
      } catch {
        setLoading(false);
      }
    };
    fetchStats();
    return () => { active = false; };
  }, []);

  if (loading) {
    return (
      <div>
        <div className="page-header"><h1>Analytics</h1></div>
        <div className="chart-grid">
          {[1, 2, 3].map(i => (
            <div key={i} className="glass-card skeleton-card chart-card skeleton" style={{ height: 340 }} />
          ))}
        </div>
      </div>
    );
  }

  // Prepare category breakdown data
  const catData = stats?.category_breakdown
    ? Object.entries(stats.category_breakdown)
        .filter(([k]) => k !== 'safe')
        .map(([name, count]) => ({
          name: name.replace(/_/g, ' '),
          count,
          fill: CATEGORY_COLORS[name] || '#7c3aed',
        }))
        .sort((a, b) => b.count - a.count)
    : [];

  // Hourly data
  const hourlyData = stats?.hourly_data || [];

  // Pie data
  const blocked = stats?.total_blocked || 0;
  const passed = (stats?.total_requests || 0) - blocked;
  const pieData = [
    { name: 'Blocked', value: blocked, color: '#ff3d5a' },
    { name: 'Passed', value: passed, color: '#00d4ff' },
  ];

  return (
    <div>
      <div className="page-header">
        <h1>Analytics</h1>
        <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          {stats?.total_requests || 0} total events
        </span>
      </div>

      <div className="chart-grid">
        {/* Category Breakdown Bar Chart */}
        <div className="glass-card chart-card">
          <h3>Threat Categories</h3>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={catData} barSize={28}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis
                dataKey="name"
                tick={{ fill: '#94a3b8', fontSize: 11 }}
                axisLine={{ stroke: 'rgba(255,255,255,0.08)' }}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: '#94a3b8', fontSize: 11 }}
                axisLine={{ stroke: 'rgba(255,255,255,0.08)' }}
                tickLine={false}
              />
              <Tooltip content={<GlassTooltip />} />
              <defs>
                <linearGradient id="barGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#7c3aed" stopOpacity={1} />
                  <stop offset="100%" stopColor="#00d4ff" stopOpacity={0.8} />
                </linearGradient>
              </defs>
              <Bar dataKey="count" fill="url(#barGradient)" radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Block vs Pass Donut */}
        <div className="glass-card chart-card">
          <h3>Block vs Pass</h3>
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie
                data={pieData}
                cx="50%"
                cy="50%"
                innerRadius={68}
                outerRadius={105}
                paddingAngle={3}
                dataKey="value"
                stroke="none"
              >
                {pieData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
                <Label
                  value={`${stats?.block_rate || 0}%`}
                  position="center"
                  style={{
                    fontSize: '1.6rem',
                    fontWeight: 700,
                    fill: '#f1f5f9',
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                />
              </Pie>
              <Tooltip content={<GlassTooltip />} />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: 'flex', justifyContent: 'center', gap: 24, marginTop: 8 }}>
            {pieData.map(d => (
              <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                <span style={{ width: 10, height: 10, borderRadius: 3, background: d.color, display: 'inline-block' }} />
                {d.name}: {d.value}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Hourly Line Chart — full width */}
      <div className="glass-card chart-card">
        <h3>Hourly Activity (Last 24h)</h3>
        <ResponsiveContainer width="100%" height={300}>
          <AreaChart data={hourlyData}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
            <XAxis
              dataKey="hour"
              tick={{ fill: '#94a3b8', fontSize: 11 }}
              axisLine={{ stroke: 'rgba(255,255,255,0.08)' }}
              tickLine={false}
            />
            <YAxis
              tick={{ fill: '#94a3b8', fontSize: 11 }}
              axisLine={{ stroke: 'rgba(255,255,255,0.08)' }}
              tickLine={false}
            />
            <Tooltip content={<GlassTooltip />} />
            <defs>
              <linearGradient id="cyanFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#00d4ff" stopOpacity={0.15} />
                <stop offset="100%" stopColor="#00d4ff" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="redFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#ff3d5a" stopOpacity={0.15} />
                <stop offset="100%" stopColor="#ff3d5a" stopOpacity={0} />
              </linearGradient>
            </defs>
            <Area
              type="monotone"
              dataKey="requests"
              stroke="#00d4ff"
              strokeWidth={2}
              fill="url(#cyanFill)"
              dot={false}
              activeDot={{ r: 5, fill: '#00d4ff', stroke: '#0a0a0f', strokeWidth: 2 }}
            />
            <Area
              type="monotone"
              dataKey="blocked"
              stroke="#ff3d5a"
              strokeWidth={2}
              fill="url(#redFill)"
              dot={false}
              activeDot={{ r: 5, fill: '#ff3d5a', stroke: '#0a0a0f', strokeWidth: 2 }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Top Attack Categories Table */}
      {stats?.top_attack_categories?.length > 0 && (
        <div className="glass-card chart-card" style={{ marginTop: 20 }}>
          <h3>Top Attack Categories</h3>
          <table className="data-table">
            <thead>
              <tr>
                <th>Category</th>
                <th>Count</th>
                <th>Percentage</th>
                <th>Distribution</th>
              </tr>
            </thead>
            <tbody>
              {stats.top_attack_categories.map((cat) => (
                <tr key={cat.category} className="row-animate">
                  <td>
                    <span className="badge badge-category" style={{ background: `${CATEGORY_COLORS[cat.category]}22`, color: CATEGORY_COLORS[cat.category], borderColor: `${CATEGORY_COLORS[cat.category]}44` }}>
                      {cat.category.replace(/_/g, ' ')}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{cat.count}</td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{cat.percentage}%</td>
                  <td style={{ width: '40%' }}>
                    <div className="progress-bar-container">
                      <div
                        className="progress-bar-fill"
                        style={{
                          width: `${cat.percentage}%`,
                          background: CATEGORY_COLORS[cat.category] || 'var(--cyan)',
                        }}
                      />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
