import React, { useState, useEffect } from 'react';

export default function Toast() {
  const [toasts, setToasts] = useState([]);

  useEffect(() => {
    const handleToast = (e) => {
      const id = Date.now();
      setToasts((prev) => [...prev, { id, message: e.detail.message }]);
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
      }, 3000);
    };

    window.addEventListener('show-toast', handleToast);
    return () => window.removeEventListener('show-toast', handleToast);
  }, []);

  return (
    <div style={{ position: 'fixed', bottom: '2rem', right: '50%', transform: 'translateX(50%)', zIndex: 9999, display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
      {toasts.map((t) => (
        <div key={t.id} className="glass-panel fade-in-up emerald-glow" style={{ padding: '0.75rem 1.25rem', borderTop: '1px solid rgba(0, 255, 157, 0.4)', background: 'rgba(2, 6, 23, 0.9)', color: 'var(--primary-container)', fontSize: '0.875rem', minWidth: '300px', textAlign: 'center' }}>
          <span className="material-symbols-outlined" style={{ fontSize: '16px', verticalAlign: 'middle', marginRight: '8px' }}>info</span>
          {t.message}
        </div>
      ))}
    </div>
  );
}

export const showToast = (message) => {
  window.dispatchEvent(new CustomEvent('show-toast', { detail: { message } }));
};
