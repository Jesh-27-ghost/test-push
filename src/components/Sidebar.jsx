import { useState } from 'react';

const NAV_ITEMS = [
  { id: 'overview', label: 'Overview', icon: '📊' },
  { id: 'analytics', label: 'Analytics', icon: '📈' },
  { id: 'simulator', label: 'Simulator', icon: '⚡' },
  { id: 'clients', label: 'Clients', icon: '👥' },
];

export default function Sidebar({ activePage, setPage }) {
  return (
    <>
      {/* Desktop sidebar */}
      <aside className="sidebar-desktop">
        <div className="sidebar-logo">
          <div className="shield-icon">🛡️</div>
          <span className="logo-text">ShieldProxy</span>
        </div>

        <nav className="sidebar-nav">
          {NAV_ITEMS.map((item) => (
            <button
              key={item.id}
              id={`nav-${item.id}`}
              className={`nav-link ${activePage === item.id ? 'active' : ''}`}
              onClick={() => setPage(item.id)}
            >
              <span className="nav-icon">{item.icon}</span>
              <span className="nav-label">{item.label}</span>
            </button>
          ))}
        </nav>

        <div className="sidebar-status">
          <span className="status-dot"></span>
          <span className="status-text">System Online</span>
        </div>
      </aside>

      {/* Mobile bottom nav */}
      <nav className="mobile-nav">
        {NAV_ITEMS.map((item) => (
          <button
            key={item.id}
            className={`mobile-nav-link ${activePage === item.id ? 'active' : ''}`}
            onClick={() => setPage(item.id)}
          >
            <span className="mobile-nav-icon">{item.icon}</span>
            <span className="mobile-nav-label">{item.label}</span>
          </button>
        ))}
      </nav>

      <style>{`
        .sidebar-desktop {
          position: fixed;
          left: 0;
          top: 0;
          bottom: 0;
          width: 240px;
          background: rgba(10, 10, 15, 0.95);
          border-right: 1px solid var(--glass-border);
          display: flex;
          flex-direction: column;
          padding: 24px 16px;
          z-index: 100;
          backdrop-filter: blur(20px);
        }

        .sidebar-logo {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 0 8px;
          margin-bottom: 36px;
        }

        .shield-icon {
          font-size: 1.6rem;
          filter: drop-shadow(0 0 8px var(--cyan-glow));
        }

        .logo-text {
          font-size: 1.15rem;
          font-weight: 700;
          color: var(--cyan);
          letter-spacing: -0.01em;
        }

        .sidebar-nav {
          display: flex;
          flex-direction: column;
          gap: 4px;
          flex: 1;
        }

        .nav-link {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 10px 14px;
          border: none;
          border-radius: 10px;
          background: transparent;
          color: var(--text-secondary);
          font-family: inherit;
          font-size: 0.88rem;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.15s ease;
          text-align: left;
        }

        .nav-link:hover {
          background: rgba(255, 255, 255, 0.05);
          color: var(--text-primary);
        }

        .nav-link.active {
          background: rgba(0, 212, 255, 0.1);
          color: var(--cyan);
          font-weight: 600;
        }

        .nav-icon { font-size: 1.05rem; }

        .sidebar-status {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 12px 14px;
          border-top: 1px solid var(--glass-border);
          margin-top: 8px;
        }

        .status-dot {
          width: 8px;
          height: 8px;
          background: var(--green);
          border-radius: 50%;
          box-shadow: 0 0 6px var(--green-glow);
          animation: pulse-dot 2s ease-in-out infinite;
        }

        .status-text {
          font-size: 0.78rem;
          color: var(--text-muted);
          font-weight: 500;
        }

        /* Mobile bottom nav */
        .mobile-nav {
          display: none;
          position: fixed;
          bottom: 0;
          left: 0;
          right: 0;
          background: rgba(10, 10, 15, 0.98);
          border-top: 1px solid var(--glass-border);
          backdrop-filter: blur(20px);
          z-index: 100;
          padding: 8px 0;
        }

        @media (max-width: 768px) {
          .sidebar-desktop { display: none; }
          .mobile-nav {
            display: flex;
            justify-content: space-around;
          }
        }

        .mobile-nav-link {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 3px;
          padding: 6px 12px;
          border: none;
          background: none;
          color: var(--text-muted);
          font-family: inherit;
          cursor: pointer;
          transition: color 0.15s ease;
        }

        .mobile-nav-link.active {
          color: var(--cyan);
        }

        .mobile-nav-icon { font-size: 1.2rem; }

        .mobile-nav-label {
          font-size: 0.65rem;
          font-weight: 600;
          text-transform: uppercase;
          letter-spacing: 0.04em;
        }
      `}</style>
    </>
  );
}
