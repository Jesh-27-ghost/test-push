import React, { useState } from 'react';
import { showToast } from './Toast';

export default function ProfileModal({ onClose }) {
  const [operatorId, setOperatorId] = useState('Operator_01');
  const [callsign, setCallsign] = useState('GHOST-ACTUAL');
  const [clearance, setClearance] = useState('SECURE_LEVEL_7');
  const [mfaEnabled, setMfaEnabled] = useState(true);

  const handleSave = (e) => {
    e.preventDefault();
    if (!operatorId || !callsign) {
      showToast('Error: Identity fields cannot be blank.');
      return;
    }
    showToast('Vault Profile settings updated successfully.');
    onClose();
  };

  return (
    <div className="modal-overlay fade-in-up" onClick={onClose} style={{
      position: 'fixed', top: 0, left: 0, width: '100%', height: '100%',
      background: 'rgba(2, 6, 23, 0.8)', backdropFilter: 'blur(12px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
    }}>
      <div className="glass-panel modal-panel emerald-glow-strong" onClick={e => e.stopPropagation()} style={{
        width: '100%', maxWidth: '480px', padding: '2rem', position: 'relative'
      }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <span className="material-symbols-outlined" style={{ fontSize: '24px', color: 'var(--primary-container)' }}>badge</span>
            <h2 style={{ fontFamily: 'var(--font-headline)', fontSize: '1.5rem', color: 'var(--primary)' }}>
              Operator Profile
            </h2>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--outline)', cursor: 'none' }}>
            <span className="material-symbols-outlined">close</span>
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSave}>
          <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.5rem' }}>Identity Matrix</div>
          
          <div style={{ position: 'relative', marginBottom: '1.25rem' }}>
            <span className="material-symbols-outlined" style={{ position: 'absolute', left: '0', top: '50%', transform: 'translateY(-50%)', fontSize: '18px', color: 'var(--outline)' }}>person</span>
            <input 
              type="text" 
              className="input-underline" 
              placeholder="Operator ID" 
              value={operatorId} 
              onChange={e => setOperatorId(e.target.value)} 
            />
          </div>

          <div style={{ position: 'relative', marginBottom: '2rem' }}>
            <span className="material-symbols-outlined" style={{ position: 'absolute', left: '0', top: '50%', transform: 'translateY(-50%)', fontSize: '18px', color: 'var(--outline)' }}>headset_mic</span>
            <input 
              type="text" 
              className="input-underline" 
              placeholder="Tactical Callsign" 
              value={callsign} 
              onChange={e => setCallsign(e.target.value)} 
            />
          </div>

          <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.5rem' }}>Security Protocol</div>
          
          <div style={{ position: 'relative', marginBottom: '1.25rem' }}>
            <span className="material-symbols-outlined" style={{ position: 'absolute', left: '0', top: '50%', transform: 'translateY(-50%)', fontSize: '18px', color: 'var(--primary-container)' }}>policy</span>
            <select 
              className="input-underline" 
              style={{ appearance: 'none' }}
              value={clearance}
              onChange={e => setClearance(e.target.value)}
            >
              <option value="SECURE_LEVEL_3" style={{ background: '#121416', color: '#e2e2e5' }}>Level 3 (Analyst)</option>
              <option value="SECURE_LEVEL_5" style={{ background: '#121416', color: '#e2e2e5' }}>Level 5 (Sentinel)</option>
              <option value="SECURE_LEVEL_7" style={{ background: '#121416', color: '#e2e2e5' }}>Level 7 (Vanguard)</option>
              <option value="SECURE_LEVEL_9" style={{ background: '#121416', color: '#e2e2e5' }}>Level 9 (Overlord)</option>
            </select>
            <span className="material-symbols-outlined" style={{ position: 'absolute', right: '0', top: '50%', transform: 'translateY(-50%)', color: 'var(--outline)', pointerEvents: 'none' }}>expand_more</span>
          </div>

          <label className="custom-checkbox" style={{ marginBottom: '2.5rem' }}>
            <input type="checkbox" checked={mfaEnabled} onChange={() => setMfaEnabled(!mfaEnabled)} />
            <span className="checkbox-mark">
              <span className="material-symbols-outlined">check</span>
            </span>
            <span style={{ fontSize: '0.8125rem', color: mfaEnabled ? 'var(--primary-container)' : 'var(--outline)' }}>
              Require Quantum MFA for terminal access
            </span>
          </label>

          <div style={{ display: 'flex', gap: '1rem', justifyContent: 'flex-end' }}>
            <button type="button" className="btn btn-outline" onClick={onClose}>
              Abort
            </button>
            <button type="submit" className="btn btn-primary btn-shine">
              Initialize Updates
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
