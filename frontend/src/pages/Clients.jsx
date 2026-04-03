import React, { useState, useMemo } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { generateClients } from '../data/mockData';
import { showToast } from '../components/Toast';

function ClientModal({ client, onClose }) {
  if (!client) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="glass-panel modal-panel" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '2rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
            <div style={{
              width: '64px', height: '64px', borderRadius: 'var(--radius-lg)',
              background: 'linear-gradient(135deg, var(--primary-container), var(--secondary-container))',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: '1.5rem', fontWeight: 700, color: 'var(--on-primary)',
            }}>
              {client.name.charAt(0)}
            </div>
            <div>
              <h2 style={{ fontFamily: 'var(--font-headline)', fontSize: '2.5rem', color: 'var(--primary)', marginBottom: '0.25rem' }}>
                {client.name}
              </h2>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--outline)', background: 'rgba(40,42,44,0.6)', padding: '0.25rem 0.5rem', borderRadius: 'var(--radius-sm)' }}>
                {client.apiKey}
              </span>
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--outline)', fontSize: '24px' }}>
            <span className="material-symbols-outlined">close</span>
          </button>
        </div>

        {/* Stats Row */}
        <div className="stat-grid stat-grid-4" style={{ marginBottom: '2rem' }}>
          <div>
            <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.25rem' }}>Total Ingress</div>
            <div style={{ fontSize: '2rem', fontWeight: 300, color: 'var(--primary)' }}>{client.totalIngress}</div>
          </div>
          <div>
            <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.25rem' }}>Neutralized</div>
            <div style={{ fontSize: '2rem', fontWeight: 300, color: 'var(--error)' }}>{client.neutralized}</div>
          </div>
          <div>
            <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.25rem' }}>Block Rate</div>
            <div style={{ fontSize: '2rem', fontWeight: 300, color: 'var(--primary-container)' }}>{client.blockRate}</div>
          </div>
          <div>
            <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.25rem' }}>Latency</div>
            <div style={{ fontSize: '2rem', fontWeight: 300, color: 'var(--secondary-container)' }}>{client.latency}</div>
          </div>
        </div>

        {/* Historical Chart */}
        <div className="glass-card" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
          <h3 style={{ fontFamily: 'var(--font-headline)', fontSize: '1.125rem', color: 'var(--primary)', marginBottom: '1rem' }}>Historical Flow</h3>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={client.historicalData}>
              <defs>
                <linearGradient id="modalGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#00ff9d" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="#00ff9d" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#3b4a3f" strokeOpacity={0.3} />
              <XAxis dataKey="day" tick={{ fontSize: 10, fill: '#849587' }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 10, fill: '#849587' }} tickLine={false} axisLine={false} />
              <Tooltip
                contentStyle={{
                  background: 'rgba(26,28,30,0.9)',
                  border: '1px solid #3b4a3f',
                  borderRadius: '4px',
                  fontSize: '12px',
                  color: '#e2e2e5',
                }}
              />
              <Area type="monotone" dataKey="requests" stroke="#00ff9d" fill="url(#modalGrad)" strokeWidth={2} />
              <Area type="monotone" dataKey="blocked" stroke="#ffb4ab" fill="none" strokeWidth={1.5} strokeDasharray="4 4" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Dominant Anomalies */}
        <div style={{ marginBottom: '1.5rem' }}>
          <h3 style={{ fontFamily: 'var(--font-headline)', fontSize: '1.125rem', color: 'var(--primary)', marginBottom: '1rem' }}>Dominant Anomalies</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {client.anomalies.map((a, i) => (
              <div key={i} className="glass-panel" style={{ padding: '0.75rem 1rem', borderLeft: '2px solid var(--primary-container)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '0.8125rem', color: 'var(--on-surface-variant)' }}>{a.type}</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', color: 'var(--primary-container)' }}>{a.count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Buttons */}
        <div style={{ display: 'flex', gap: '1rem' }}>
          <button className="btn btn-primary btn-shine" onClick={() => showToast(`Regenerating cryptographic key for ${client.name}...`)}>
            <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>autorenew</span>
            Regenerate Key
          </button>
          <button className="btn btn-outline" onClick={() => showToast(`Flushing audit logs for ${client.name}...`)}>
            <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>delete_sweep</span>
            Flush Logs
          </button>
        </div>

        {/* Contextual Info */}
        <div style={{ marginTop: '2rem', padding: '1.5rem', borderTop: '1px solid var(--outline-variant)' }}>
          <h4 style={{ fontFamily: 'var(--font-headline)', fontSize: '1rem', color: 'var(--primary)', marginBottom: '0.75rem' }}>Integrity Monitoring</h4>
          <p style={{ fontSize: '0.8125rem', color: 'var(--on-surface-variant)', lineHeight: '1.7', marginBottom: '1rem' }}>
            Continuous monitoring of this client's API surface has been active for {Math.floor(Math.random() * 90) + 30} consecutive days. 
            All cryptographic handshake protocols are verified and within operational parameters.
          </p>
          <h4 style={{ fontFamily: 'var(--font-headline)', fontSize: '1rem', color: 'var(--primary)', marginBottom: '0.75rem' }}>Latest Audit Log</h4>
          {client.auditLog.map((log, i) => (
            <div key={i} style={{ display: 'flex', gap: '1rem', marginBottom: '0.5rem', fontSize: '0.8125rem' }}>
              <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--outline)', fontSize: '0.75rem', whiteSpace: 'nowrap' }}>{log.time}</span>
              <span style={{ color: 'var(--on-surface-variant)' }}>{log.action}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function Clients() {
  const clients = useMemo(() => generateClients(), []);
  const [search, setSearch] = useState('');
  const [sortBy, setSortBy] = useState('throughput');
  const [selectedClient, setSelectedClient] = useState(null);

  const filtered = clients.filter((c) =>
    c.name.toLowerCase().includes(search.toLowerCase()) ||
    c.apiKey.toLowerCase().includes(search.toLowerCase())
  ).sort((a, b) => {
    if (sortBy === 'throughput') {
      return parseFloat(b.totalIngress) - parseFloat(a.totalIngress);
    }
    if (sortBy === 'block rate') {
      return parseFloat(b.blockRate) - parseFloat(a.blockRate);
    }
    if (sortBy === 'latency') {
      // Sort latency ascending (lower is better, or maybe higher is worse so descending? Let's do ascending)
      return parseFloat(a.latency) - parseFloat(b.latency);
    }
    return 0;
  });

  const statusBadge = (status) => {
    const map = {
      Operational: 'badge-success',
      'Traffic Spike': 'badge-high',
      Hibernation: 'badge-low',
    };
    return <span className={`badge ${map[status] || 'badge-low'}`}>{status}</span>;
  };

  return (
    <div className="fade-in-up">
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
        <div>
          <h1 style={{ fontFamily: 'var(--font-headline)', fontSize: '2.75rem', color: 'var(--primary-container)', marginBottom: '0.5rem' }}>
            Client Infrastructure Registry
          </h1>
          <div className="label" style={{ color: 'var(--secondary-container)' }}>
            System Manifest & Cryptographic Protocols
          </div>
        </div>
        <button className="btn btn-primary btn-shine" style={{ transition: 'transform 0.2s' }}
          onMouseEnter={(e) => e.currentTarget.style.transform = 'scale(1.02)'}
          onMouseLeave={(e) => e.currentTarget.style.transform = 'scale(1)'}
          onClick={() => showToast('Opening new client provisioning wizard...')}
        >
          <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>add_link</span>
          Provision New Client
        </button>
      </div>

      {/* Stats Bento */}
      <div className="stat-grid stat-grid-4" style={{ margin: '2rem 0' }}>
        {[
          { label: 'API Keys', value: '1,248', delta: '+12', deltaColor: 'var(--primary-container)' },
          { label: 'Active Handshakes', value: '847', extra: 'live' },
          { label: 'Global Latency', value: '14.2ms', color: 'var(--secondary-container)' },
          { label: 'Threat Mitigation', value: '99.9%', color: 'var(--primary-container)' },
        ].map((s, i) => (
          <div key={i} className="glass-card light-cap" style={{ padding: '1.25rem' }}>
            <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.5rem' }}>{s.label}</div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.5rem' }}>
              <span style={{ fontSize: '2rem', fontWeight: 300, color: s.color || 'var(--primary)' }}>{s.value}</span>
              {s.delta && <span style={{ fontSize: '0.75rem', color: s.deltaColor }}>{s.delta}</span>}
              {s.extra === 'live' && (
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.375rem' }}>
                  <div className="pulse-dot-sm" />
                  <span className="label" style={{ color: 'var(--primary-container)' }}>Live</span>
                </span>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Search & Sort */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem', gap: '1rem' }}>
        <div style={{ position: 'relative', flex: 1, maxWidth: '400px' }}>
          <span className="material-symbols-outlined" style={{ position: 'absolute', left: '0', top: '50%', transform: 'translateY(-50%)', fontSize: '18px', color: 'var(--outline)' }}>search</span>
          <input
            type="text"
            className="input-underline"
            placeholder="QUERY INFRASTRUCTURE..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="filter-group">
          {['throughput', 'block rate', 'latency'].map((f) => (
            <button
              key={f}
              className={`filter-btn${sortBy === f ? ' active' : ''}`}
              onClick={() => setSortBy(f)}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Registry Table */}
      <div className="glass-card emerald-glow" style={{ overflow: 'hidden' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Client Identity</th>
              <th>Cryptographic Key</th>
              <th>Usage Trend</th>
              <th>Integrity Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((client) => (
              <tr key={client.id} onClick={() => setSelectedClient(client)} style={{ cursor: 'none' }} data-cursor="pointer">
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <div style={{
                      width: '36px', height: '36px', borderRadius: 'var(--radius-sm)',
                      background: 'linear-gradient(135deg, rgba(0,255,157,0.2), rgba(0,227,253,0.2))',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: '0.875rem', fontWeight: 600, color: 'var(--primary-container)',
                    }}>
                      {client.name.charAt(0)}
                    </div>
                    <div>
                      <div style={{ fontWeight: 500, color: 'var(--on-surface)', fontSize: '0.875rem' }}>{client.name}</div>
                      <div className="label" style={{ color: 'var(--outline)', fontSize: '9px' }}>{client.country} • {client.tier}</div>
                    </div>
                  </div>
                </td>
                <td>
                  <span style={{
                    fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--outline)',
                    background: 'rgba(40,42,44,0.6)', padding: '0.25rem 0.5rem', borderRadius: 'var(--radius-sm)',
                  }}>
                    {client.apiKey}
                  </span>
                </td>
                <td>
                  <div style={{ display: 'flex', gap: '2px', alignItems: 'flex-end', height: '24px' }}>
                    {client.trend.map((v, i) => (
                      <div key={i} style={{
                        width: '6px',
                        height: `${v * 0.24}px`,
                        background: 'var(--primary-container)',
                        borderRadius: '1px',
                        opacity: 0.4 + (i * 0.15),
                      }} />
                    ))}
                  </div>
                </td>
                <td>{statusBadge(client.status)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="deco-footer">
        GRID_COORD: 51.5074° N, 0.1278° W // REGISTRY_v3.2.0
      </div>

      {/* Detail Modal */}
      {selectedClient && (
        <ClientModal client={selectedClient} onClose={() => setSelectedClient(null)} />
      )}
    </div>
  );
}
