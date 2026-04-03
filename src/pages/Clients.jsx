import { useState, useEffect } from 'react';
import { api } from '../api.js';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
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
        <div key={i} className="value" style={{ color: p.fill }}>{p.name}: {p.value}</div>
      ))}
    </div>
  );
}

function ClientDetail({ client }) {
  const catData = client.category_breakdown
    ? Object.entries(client.category_breakdown).map(([name, count]) => ({
        name: name.replace(/_/g, ' '),
        count,
        fill: CATEGORY_COLORS[name] || '#7c3aed',
      }))
    : [];

  return (
    <tr>
      <td colSpan="7">
        <div className="client-detail">
          <h4 style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 12 }}>
            Category Breakdown — {client.api_key}
          </h4>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={catData} barSize={20}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 10 }} tickLine={false} />
              <YAxis tick={{ fill: '#94a3b8', fontSize: 10 }} tickLine={false} />
              <Tooltip content={<GlassTooltip />} />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {catData.map((entry, i) => (
                  <rect key={i} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </td>
    </tr>
  );
}

export default function Clients() {
  const [clients, setClients] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [expandedKey, setExpandedKey] = useState(null);

  useEffect(() => {
    let active = true;
    const fetchClients = async () => {
      try {
        const data = await api.clients();
        if (active) { setClients(data); setLoading(false); }
      } catch {
        setLoading(false);
      }
    };
    fetchClients();
    return () => { active = false; };
  }, []);

  const filtered = clients.filter((c) =>
    c.api_key.toLowerCase().includes(search.toLowerCase())
  );

  function formatTime(iso) {
    try {
      const d = new Date(iso);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch {
      return iso;
    }
  }

  if (loading) {
    return (
      <div>
        <div className="page-header"><h1>Clients</h1></div>
        <div className="glass-card" style={{ padding: 24 }}>
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="skeleton skeleton-line" style={{ marginBottom: 16, height: 24 }} />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <h1>Clients</h1>
        <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          {clients.length} API keys tracked
        </span>
      </div>

      <div className="search-wrapper">
        <span className="search-icon">🔍</span>
        <input
          id="client-search"
          className="search-input"
          type="text"
          placeholder="Filter by API key..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      <div className="glass-card" style={{ padding: 0, overflow: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>API Key</th>
              <th>Requests</th>
              <th>Blocked</th>
              <th>Block Rate</th>
              <th>Top Category</th>
              <th>Last Seen</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((client) => (
              <>
                <tr
                  key={client.api_key}
                  className="row-animate"
                  style={{ cursor: 'pointer' }}
                  onClick={() => setExpandedKey(expandedKey === client.api_key ? null : client.api_key)}
                >
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem' }}>
                    {client.api_key}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{client.total_requests}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', color: client.blocked > 0 ? 'var(--red)' : 'var(--text-secondary)' }}>
                    {client.blocked}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{client.block_rate}%</td>
                  <td>
                    <span className="badge badge-category">{client.top_category.replace(/_/g, ' ')}</span>
                  </td>
                  <td style={{ fontSize: '0.8rem' }}>{formatTime(client.last_seen)}</td>
                  <td>
                    <span className={`badge badge-status-${client.status}`}>
                      {client.status === 'high_risk' ? '⚠ High Risk' : '● Active'}
                    </span>
                  </td>
                </tr>
                {expandedKey === client.api_key && (
                  <ClientDetail key={`${client.api_key}-detail`} client={client} />
                )}
              </>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan="7" style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>
                  No clients found matching "{search}"
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
