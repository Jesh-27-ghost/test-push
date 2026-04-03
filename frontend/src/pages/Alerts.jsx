import React, { useState, useEffect } from 'react';
import { generateAlerts } from '../data/mockData';
import { showToast } from '../components/Toast';

function CodeViewer({ code }) {
  const lines = code.split('\n');
  return (
    <div className="code-block">
      {lines.map((line, i) => {
        let coloredLine = line
          .replace(/"([^"]+)":/g, '<key>"$1"</key>:')
          .replace(/: "([^"]+)"/g, ': <val>"$1"</val>')
          .replace(/: ([0-9.]+)/g, ': <num>$1</num>');

        return (
          <div key={i} style={{ display: 'flex' }}>
            <span className="code-line-number">{i + 1}</span>
            <span dangerouslySetInnerHTML={{
              __html: coloredLine
                .replace(/<key>/g, '<span style="color:#00ff9d">')
                .replace(/<\/key>/g, '</span>')
                .replace(/<val>/g, '<span style="color:#ffb4ab">')
                .replace(/<\/val>/g, '</span>')
                .replace(/<num>/g, '<span style="color:#00e3fd">')
                .replace(/<\/num>/g, '</span>')
            }} />
          </div>
        );
      })}
    </div>
  );
}

export default function Alerts() {
  const [alerts, setAlerts] = useState(() => generateAlerts(15));
  const [filter, setFilter] = useState('all');
  const [selectedAlert, setSelectedAlert] = useState(null);

  // Add new alert every 12s
  useEffect(() => {
    const iv = setInterval(() => {
      const newAlerts = generateAlerts(1);
      setAlerts((prev) => [newAlerts[0], ...prev.slice(0, 24)]);
    }, 12000);
    return () => clearInterval(iv);
  }, []);

  const filtered = filter === 'all' ? alerts : alerts.filter((a) => a.severity === filter);

  const severityColor = (sev) => {
    const map = { critical: 'var(--error)', high: 'var(--tertiary-fixed)', medium: 'var(--secondary-container)', low: 'var(--outline)' };
    return map[sev] || 'var(--outline)';
  };

  const severityBadgeClass = (sev) => {
    const map = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low' };
    return map[sev] || 'badge-low';
  };

  return (
    <div className="fade-in-up" style={{ display: 'flex', gap: '1.5rem', minHeight: 'calc(100vh - 120px)' }}>
      {/* Main Feed */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ marginBottom: '1.5rem' }}>
          <h1 style={{ fontFamily: 'var(--font-headline)', fontSize: '2.25rem', color: 'var(--primary)', marginBottom: '0.5rem' }}>
            System Intercepts
          </h1>
          <p style={{ color: 'var(--outline)', fontSize: '0.875rem' }}>
            Real-time threat interception feed with forensic analysis capabilities.
          </p>
        </div>

        {/* Filters */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
          <div className="filter-group">
            {['all', 'critical', 'high', 'medium', 'low'].map((f) => (
              <button key={f} className={`filter-btn${filter === f ? ' active' : ''}`} onClick={() => setFilter(f)}>
                {f}
              </button>
            ))}
          </div>
          <button className="btn btn-outline" style={{ padding: '0.5rem 1rem' }} onClick={() => showToast('Exporting encrypted logs...')}>
            <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>download</span>
            Export Logs
          </button>
        </div>

        {/* Intercept Cards */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {filtered.map((alert) => (
            <div
              key={alert.id}
              className={`glass-panel${selectedAlert?.id === alert.id ? '' : ''}`}
              style={{
                display: 'flex',
                alignItems: 'stretch',
                overflow: 'hidden',
                transition: 'all 0.2s',
                border: selectedAlert?.id === alert.id ? '1px solid rgba(0, 255, 157, 0.1)' : undefined,
              }}
              onClick={() => setSelectedAlert(alert)}
              data-cursor="pointer"
            >
              {/* Severity Bar */}
              <div style={{ width: '3px', background: severityColor(alert.severity), flexShrink: 0 }} />

              <div style={{ flex: 1, padding: '1rem 1.25rem', display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
                {/* Score */}
                <div style={{ textAlign: 'center', minWidth: '56px' }}>
                  <div style={{ fontSize: '1.5rem', fontWeight: 600, color: severityColor(alert.severity) }}>{alert.confidence}</div>
                  <div className="label" style={{ color: severityColor(alert.severity), fontSize: '8px' }}>Score</div>
                </div>

                {/* Content */}
                <div style={{ flex: 1 }}>
                  <div style={{ fontFamily: 'var(--font-headline)', fontSize: '1rem', color: 'var(--primary-container)', marginBottom: '0.25rem' }}>
                    {alert.title}
                  </div>
                  <div className="label" style={{ color: 'var(--outline)', fontSize: '9px' }}>
                    Intercepted: {alert.timestamp} • PID: {alert.pid}
                  </div>
                </div>

                {/* Badge & Button */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                  <span className={`badge ${severityBadgeClass(alert.severity)}`}>{alert.severity}</span>
                  <button className="btn btn-outline-cyan" style={{ padding: '0.375rem 0.75rem', fontSize: '9px' }} onClick={(e) => { e.stopPropagation(); showToast(`Decrypting forensic data for ${alert.id}...`); }}>
                    View Decrypt
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Right Investigation Panel */}
      <div style={{
        width: '420px',
        flexShrink: 0,
        background: 'rgba(2, 6, 23, 0.4)',
        backdropFilter: 'blur(24px)',
        borderLeft: '1px solid rgba(0, 255, 157, 0.1)',
        padding: '1.5rem',
        overflowY: 'auto',
        maxHeight: 'calc(100vh - 120px)',
        position: 'sticky',
        top: '88px',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
          <h3 style={{ fontFamily: 'var(--font-headline)', fontSize: '1.25rem', color: 'var(--primary)' }}>Investigation</h3>
          {selectedAlert && (
            <button onClick={() => setSelectedAlert(null)} style={{ background: 'none', border: 'none', color: 'var(--outline)' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>close</span>
            </button>
          )}
        </div>

        {selectedAlert ? (
          <div className="fade-in-up">
            {/* Status */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.5rem' }}>
              <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--error)', boxShadow: '0 0 6px var(--error)' }} />
              <span className="label" style={{ color: 'var(--error)' }}>Live Forensics Active</span>
            </div>

            {/* Metadata */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
              <div>
                <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.25rem' }}>Vector</div>
                <div style={{ fontSize: '0.875rem', color: 'var(--on-surface)' }}>{selectedAlert.category}</div>
              </div>
              <div>
                <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.25rem' }}>Latency</div>
                <div style={{ fontSize: '0.875rem', color: 'var(--secondary-container)' }}>{selectedAlert.latency}</div>
              </div>
            </div>

            {/* Code View */}
            <div style={{ marginBottom: '1.5rem' }}>
              <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.75rem' }}>Blocked Source Fragment</div>
              <CodeViewer code={selectedAlert.codeFragment} />
            </div>

            {/* Threat Verdict */}
            <div style={{
              background: 'rgba(255, 180, 171, 0.05)',
              border: '1px solid rgba(255, 180, 171, 0.15)',
              borderRadius: 'var(--radius-md)',
              padding: '1rem',
              marginBottom: '1.5rem',
            }}>
              <div className="label" style={{ color: 'var(--error)', marginBottom: '0.5rem' }}>Threat Verdict</div>
              <p style={{ fontSize: '0.8125rem', color: 'var(--on-surface-variant)', lineHeight: '1.6', marginBottom: '1rem' }}>
                {selectedAlert.description}
              </p>
              <div style={{ display: 'flex', gap: '0.75rem' }}>
                <button className="btn btn-danger" style={{ padding: '0.5rem 1rem', fontSize: '9px' }} onClick={() => showToast(`Successfully hard purged threat record ${selectedAlert.id}.`)}>
                  <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>delete_forever</span>
                  Hard Purge
                </button>
                <button className="btn btn-outline" style={{ padding: '0.5rem 1rem', fontSize: '9px' }} onClick={() => showToast(`Tracing IP origin... Target identified near Region Sector 7.`)}>
                  <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>travel_explore</span>
                  Trace IP
                </button>
              </div>
            </div>

            {/* Deco */}
            <div style={{ marginTop: '2rem' }}>
              <div style={{ fontSize: '9px', letterSpacing: '0.2em', color: 'rgba(0,255,157,0.12)' }}>
                LAT: 47.3769° N // LNG: 8.5417° E
              </div>
              <div style={{ display: 'flex', gap: '2px', marginTop: '0.5rem' }}>
                {Array.from({ length: 12 }, (_, i) => (
                  <div key={i} style={{
                    width: '4px',
                    height: `${8 + Math.random() * 16}px`,
                    background: 'rgba(0,255,157,0.1)',
                    borderRadius: '1px',
                  }} />
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div style={{ textAlign: 'center', padding: '3rem 1rem' }}>
            <span className="material-symbols-outlined" style={{ fontSize: '48px', color: 'var(--outline-variant)', marginBottom: '1rem', display: 'block' }}>
              policy
            </span>
            <p style={{ color: 'var(--outline)', fontSize: '0.875rem' }}>
              Select an intercept to begin forensic analysis
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
