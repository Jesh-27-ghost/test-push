import { useState, useEffect } from 'react';
import { api } from '../api.js';
import StatCard from '../components/StatCard.jsx';
import LiveFeed from '../components/LiveFeed.jsx';

export default function Overview() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [offline, setOffline] = useState(false);
  const [cachedStats, setCachedStats] = useState(null);

  useEffect(() => {
    let active = true;

    const fetchStats = async () => {
      try {
        const data = await api.stats();
        if (active) {
          setStats(data);
          setCachedStats(data);
          setLoading(false);
          setOffline(false);
        }
      } catch {
        if (active) {
          setOffline(true);
          setLoading(false);
          if (cachedStats) setStats(cachedStats);
        }
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => { active = false; clearInterval(interval); };
  }, []);

  return (
    <div>
      <div className="page-header">
        <h1>Threat Overview</h1>
        <span className="live-dot" />
      </div>

      {offline && (
        <div className="offline-banner">
          ⚠️ Backend Offline — Showing Cached Data
        </div>
      )}

      <div className="stats-grid">
        <StatCard
          title="Total Requests"
          value={stats ? stats.total_requests.toLocaleString() : '—'}
          change={stats ? 12.3 : null}
          icon="📨"
          glowColor="rgba(0, 212, 255, 0.12)"
          loading={loading}
        />
        <StatCard
          title="Blocked"
          value={stats ? stats.total_blocked.toLocaleString() : '—'}
          change={stats ? -4.2 : null}
          icon="🚫"
          glowColor="rgba(255, 61, 90, 0.12)"
          loading={loading}
        />
        <StatCard
          title="Avg Latency"
          value={stats ? `${stats.avg_latency_ms}ms` : '—'}
          change={stats ? -8.1 : null}
          icon="⚡"
          glowColor="rgba(124, 58, 237, 0.12)"
          loading={loading}
        />
        <StatCard
          title="Block Rate"
          value={stats ? `${stats.block_rate}%` : '—'}
          change={stats ? 2.5 : null}
          icon="🛡️"
          glowColor="rgba(245, 158, 11, 0.12)"
          loading={loading}
        />
      </div>

      <LiveFeed />
    </div>
  );
}
