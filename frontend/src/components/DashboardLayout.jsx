import React, { useState } from 'react';
import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import LogoIcon from './LogoIcon';
import { showToast } from './Toast';
import ProfileModal from './ProfileModal';
const NAV_ITEMS = [
  { to: '/overview', icon: 'dashboard', label: 'Overview' },
  { to: '/clients', icon: 'group', label: 'Clients' },
  { to: '/alerts', icon: 'notifications_active', label: 'Alerts' },
  { to: '/analytics', icon: 'insights', label: 'Analytics' },
  { to: '/simulator', icon: 'swords', label: 'Attack Simulator' },
];

export default function DashboardLayout() {
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [isProfileModalOpen, setIsProfileModalOpen] = useState(false);
  const navigate = useNavigate();

  return (
    <div className="page-container">
      {/* Sidebar */}
      <aside className="sidebar">
        <div style={{ marginBottom: '0.5rem' }}>
          <div className="sidebar-logo">
            <LogoIcon size={36} color="#00ff9d" />
            <span className="sidebar-logo-text">ShieldProxy</span>
          </div>
          <div className="label" style={{ color: 'var(--outline)', marginTop: '0.25rem', marginLeft: '0.25rem' }}>
            Vanguard Level
          </div>
        </div>

        <nav className="sidebar-nav">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => `sidebar-link${isActive ? ' active' : ''}`}
            >
              <span className="material-symbols-outlined" style={{ fontSize: '20px' }}>
                {item.icon}
              </span>
              {item.label}
            </NavLink>
          ))}
        </nav>

        <button
          className="btn btn-primary btn-shine"
          style={{ width: '100%', marginTop: '1rem' }}
          onClick={() => showToast('Deploying new Sentry node to the edge...')}
        >
          <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>rocket_launch</span>
          Deploy Sentry
        </button>
      </aside>

      {/* Top Bar */}
      <header className="topbar">
        <div className="topbar-left">
          <div className="pulse-dot-sm" />
          <span className="label" style={{ color: 'var(--primary-container)' }}>Secure Orbit</span>
          <span className="label" style={{ color: 'var(--outline)' }}>System Status:</span>
          <span className="label" style={{ color: 'var(--primary-container)' }}>Online</span>
        </div>

        <div className="topbar-center">
          <input
            type="text"
            className="topbar-search"
            placeholder="QUERY NETWORK..."
            onKeyDown={(e) => { if (e.key === 'Enter') showToast(`Searching network for: ${e.target.value}`) }}
          />
        </div>

        <div className="topbar-right">
          <button className="topbar-icon-btn" onClick={() => showToast('No new notifications.')}>
            <span className="material-symbols-outlined">notifications</span>
            <span className="notification-badge" />
          </button>
          <button className="topbar-icon-btn" onClick={() => showToast('Settings console opened.')}>
            <span className="material-symbols-outlined">settings</span>
          </button>

          <div className="topbar-user">
            <button
              className="topbar-avatar"
              onClick={() => setDropdownOpen(!dropdownOpen)}
              style={{ border: 'none', cursor: 'none' }}
            >
              OP
            </button>
            <div className="topbar-user-info">
              <span className="topbar-user-name">Operator_01</span>
              <span className="topbar-user-level">SECURE_LEVEL_7</span>
            </div>

            {dropdownOpen && (
              <div className="user-dropdown">
                <button className="dropdown-item" onClick={() => { setDropdownOpen(false); setIsProfileModalOpen(true); }}>
                  <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>person</span>
                  Profile Setup
                </button>
                <button
                  className="dropdown-item danger"
                  onClick={() => {
                    setDropdownOpen(false);
                    showToast('Terminating Vault Session.');
                    navigate('/');
                  }}
                >
                  <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>logout</span>
                  Terminate Session
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Content */}
      <main className="dashboard-content fade-in-up">
        <Outlet />
      </main>

      {/* Profile Modal */}
      {isProfileModalOpen && (
        <ProfileModal onClose={() => setIsProfileModalOpen(false)} />
      )}
    </div>
  );
}
