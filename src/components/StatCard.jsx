export default function StatCard({ title, value, change, icon, glowColor, loading }) {
  if (loading) {
    return (
      <div className="glass-card stat-card">
        <div className="skeleton skeleton-line short" style={{ height: 14 }}></div>
        <div className="skeleton skeleton-line" style={{ height: 36, width: '50%', marginTop: 8 }}></div>
        <div className="skeleton skeleton-line short" style={{ height: 12, marginTop: 12 }}></div>
        <style>{statStyles}</style>
      </div>
    );
  }

  const isPositive = change >= 0;
  const glowShadow = glowColor ? `0 4px 20px ${glowColor}` : 'none';

  return (
    <div className="glass-card stat-card" style={{ boxShadow: glowShadow }}>
      <div className="stat-header">
        <span className="stat-title">{title}</span>
        <div
          className="stat-icon-circle"
          style={{ background: glowColor || 'rgba(255,255,255,0.06)' }}
        >
          {icon}
        </div>
      </div>
      <div className="stat-value">{value}</div>
      {change !== undefined && change !== null && (
        <div className={`stat-change ${isPositive ? 'up' : 'down'}`}>
          <span>{isPositive ? '↑' : '↓'}</span>
          <span>{Math.abs(change).toFixed(1)}%</span>
          <span className="change-label">vs last hour</span>
        </div>
      )}
      <style>{statStyles}</style>
    </div>
  );
}

const statStyles = `
  .stat-card {
    padding: 20px;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .stat-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
  }

  .stat-title {
    font-size: 0.78rem;
    font-weight: 500;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .stat-icon-circle {
    width: 36px;
    height: 36px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.1rem;
  }

  .stat-value {
    font-family: var(--font-mono);
    font-size: 2rem;
    font-weight: 700;
    color: var(--text-primary);
    letter-spacing: -0.02em;
    margin-top: 4px;
  }

  .stat-change {
    display: flex;
    align-items: center;
    gap: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    margin-top: 4px;
  }

  .stat-change.up { color: var(--green); }
  .stat-change.down { color: var(--red); }

  .change-label {
    color: var(--text-muted);
    font-weight: 400;
    margin-left: 4px;
  }
`;
