import { useState, useEffect, useRef } from 'react';
import { api } from '../api.js';
import ThreatBadge from './ThreatBadge.jsx';

function ConfidenceBar({ value }) {
  const pct = Math.round(value * 100);
  let colorClass = 'progress-cyan';
  if (value < 0.5) colorClass = 'progress-red';
  else if (value < 0.8) colorClass = 'progress-amber';

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 120 }}>
      <div className="progress-bar-container" style={{ flex: 1 }}>
        <div className={`progress-bar-fill ${colorClass}`} style={{ width: `${pct}%` }} />
      </div>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
        {pct}%
      </span>
    </div>
  );
}

function timeAgo(ts) {
  const diff = Date.now() / 1000 - ts;
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

export default function LiveFeed() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const prevIdsRef = useRef(new Set());

  useEffect(() => {
    let active = true;

    const fetchLogs = async () => {
      try {
        const data = await api.logs(20);
        if (active) {
          setLogs(data);
          setLoading(false);
        }
      } catch {
        // keep existing data
        setLoading(false);
      }
    };

    fetchLogs();
    const interval = setInterval(fetchLogs, 3000);
    return () => { active = false; clearInterval(interval); };
  }, []);

  if (loading) {
    return (
      <div className="glass-card" style={{ padding: 24 }}>
        <h3 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 16, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
          Live Threat Feed
        </h3>
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="skeleton skeleton-line" style={{ marginBottom: 12, height: 20 }} />
        ))}
      </div>
    );
  }

  return (
    <div className="glass-card" style={{ padding: 24, overflow: 'auto' }}>
      <h3 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 16, textTransform: 'uppercase', letterSpacing: '0.04em', display: 'flex', alignItems: 'center', gap: 8 }}>
        <span className="live-dot" />
        Live Threat Feed
      </h3>
      <table className="data-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Prompt Snippet</th>
            <th>Category</th>
            <th>Confidence</th>
            <th>Verdict</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((entry) => (
            <tr key={entry.id} className="row-animate">
              <td style={{ whiteSpace: 'nowrap', fontSize: '0.78rem' }}>
                {timeAgo(entry.timestamp)}
              </td>
              <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {entry.prompt_snippet}
              </td>
              <td>
                <span className="badge badge-category">
                  {entry.category.replace(/_/g, ' ')}
                </span>
              </td>
              <td>
                <ConfidenceBar value={entry.confidence} />
              </td>
              <td>
                <ThreatBadge verdict={entry.verdict} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
