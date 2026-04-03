import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import LogoIcon from '../components/LogoIcon';
import { showToast } from '../components/Toast';

export default function Login() {
  const [isRegister, setIsRegister] = useState(false);
  const [remember, setRemember] = useState(false);
  const [callsign, setCallsign] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const navigate = useNavigate();

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!username || !password) {
      showToast('Please provide your credentials.');
      return;
    }
    if (isRegister) {
      if (!callsign) {
        showToast('Operator Callsign is required.');
        return;
      }
      if (password !== confirmPassword) {
        showToast('Access keys do not match.');
        return;
      }
      showToast('Registration successful. Access granted.');
    } else {
      showToast('Vault Entry successful.');
    }
    navigate('/overview');
  };

  return (
    <div className="login-page fade-in-up">
      {/* Corner Accent */}
      <div className="corner-accent">
        <div className="label" style={{ color: 'var(--secondary-container)', letterSpacing: '0.3em', fontSize: '9px' }}>
          SECURE TERMINAL V4.2.0
        </div>
        <div className="label" style={{ color: 'var(--secondary-container)', letterSpacing: '0.3em', fontSize: '9px', marginTop: '2px' }}>
          LOC: BENGALURU_HUB
        </div>
      </div>

      {/* Left Side */}
      <div className="login-left">
        <div style={{ maxWidth: '640px' }}>
          {/* Logo */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '3rem' }}>
            <LogoIcon size={44} color="#00ff9d" />
            <span style={{ fontFamily: 'var(--font-headline)', fontSize: '1.875rem', color: 'var(--primary-container)' }}>
              ShieldProxy
            </span>
          </div>

          {/* Hero */}
          <h1 className="login-hero-title">
            Every Indian startup is building AI chatbots. None of them are secure.
          </h1>
          <p className="login-hero-subtitle">
            ShieldProxy is the missing security layer — a high-performance reverse proxy that intercepts, analyzes, and neutralizes prompt injection attacks before they reach your LLM.
          </p>

          {/* Value Cards */}
          <div className="value-grid">
            <div className="glass-panel value-card value-card-border-red">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                <span className="material-symbols-outlined" style={{ fontSize: '18px', color: 'var(--error)' }}>warning</span>
                <span className="label" style={{ color: 'var(--error)' }}>Problem</span>
              </div>
              <p style={{ fontSize: '0.8125rem', color: 'var(--on-surface-variant)', lineHeight: '1.5' }}>
                Modern LLMs are inherently vulnerable to adversarial prompts that bypass safety guidelines and extract sensitive data.
              </p>
            </div>

            <div className="glass-panel value-card value-card-border-green">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                <span className="material-symbols-outlined" style={{ fontSize: '18px', color: 'var(--primary-container)' }}>verified_user</span>
                <span className="label" style={{ color: 'var(--primary-container)' }}>Solution</span>
              </div>
              <p style={{ fontSize: '0.8125rem', color: 'var(--on-surface-variant)', lineHeight: '1.5' }}>
                A high-performance reverse proxy with layered heuristic scanning that intercepts threats in real-time.
              </p>
            </div>

            <div className="glass-panel value-card value-card-border-gold">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                <span className="material-symbols-outlined" style={{ fontSize: '18px', color: 'var(--tertiary-fixed-dim)' }}>star</span>
                <span className="label" style={{ color: 'var(--tertiary-fixed-dim)' }}>USP</span>
              </div>
              <p style={{ fontSize: '0.8125rem', color: 'var(--on-surface-variant)', lineHeight: '1.5' }}>
                &lt;100ms latency coupled with proprietary Hinglish detection — built for the Indian AI ecosystem.
              </p>
            </div>

            <div className="glass-panel value-card value-card-border-cyan">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                <span className="material-symbols-outlined" style={{ fontSize: '18px', color: 'var(--secondary-container)' }}>bolt</span>
                <span className="label" style={{ color: 'var(--secondary-container)' }}>Impact</span>
              </div>
              <p style={{ fontSize: '0.8125rem', color: 'var(--on-surface-variant)', lineHeight: '1.5' }}>
                99.9% reduction in prompt injection exploits with zero degradation to response quality.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Right Side — Login Form */}
      <div className="login-right">
        <div className="glass-panel login-card light-cap emerald-glow-strong">
          {/* Status Badge */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '2rem' }}>
            <div className="pulse-dot-sm" />
            <span className="label" style={{ color: 'var(--primary-container)' }}>Vault Connection Active</span>
          </div>

          {/* Title */}
          <h2 style={{ fontFamily: 'var(--font-headline)', fontSize: '1.875rem', color: 'var(--primary)', marginBottom: '0.25rem' }}>
            {isRegister ? 'Request Access' : 'Vault Entry'}
          </h2>
          <p className="label" style={{ color: 'var(--outline)', marginBottom: '2rem' }}>
            {isRegister ? 'New Operator Registration' : 'Authorized Personnel Only'}
          </p>

          <form onSubmit={handleSubmit}>
            {isRegister && (
              <div style={{ position: 'relative', marginBottom: '1.5rem' }}>
                <span className="material-symbols-outlined" style={{ position: 'absolute', left: '0', top: '50%', transform: 'translateY(-50%)', fontSize: '18px', color: 'var(--outline)' }}>badge</span>
                <input type="text" className="input-underline" placeholder="Operator Callsign" value={callsign} onChange={e => setCallsign(e.target.value)} />
              </div>
            )}

            <div style={{ position: 'relative', marginBottom: '1.5rem' }}>
              <span className="material-symbols-outlined" style={{ position: 'absolute', left: '0', top: '50%', transform: 'translateY(-50%)', fontSize: '18px', color: 'var(--outline)' }}>person</span>
              <input type="text" className="input-underline" placeholder="Credential ID / Username" value={username} onChange={e => setUsername(e.target.value)} />
            </div>

            <div style={{ position: 'relative', marginBottom: '1.5rem' }}>
              <span className="material-symbols-outlined" style={{ position: 'absolute', left: '0', top: '50%', transform: 'translateY(-50%)', fontSize: '18px', color: 'var(--outline)' }}>vpn_key</span>
              <input type="password" className="input-underline" placeholder="Access Key" value={password} onChange={e => setPassword(e.target.value)} />
            </div>

            {isRegister && (
              <div style={{ position: 'relative', marginBottom: '1.5rem' }}>
                <span className="material-symbols-outlined" style={{ position: 'absolute', left: '0', top: '50%', transform: 'translateY(-50%)', fontSize: '18px', color: 'var(--outline)' }}>vpn_key</span>
                <input type="password" className="input-underline" placeholder="Confirm Access Key" value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)} />
              </div>
            )}

            {!isRegister && (
              <label className="custom-checkbox" style={{ marginBottom: '2rem' }}>
                <input type="checkbox" checked={remember} onChange={() => setRemember(!remember)} />
                <span className="checkbox-mark">
                  <span className="material-symbols-outlined">check</span>
                </span>
                <span style={{ fontSize: '0.75rem', color: 'var(--outline)' }}>Maintain vault session</span>
              </label>
            )}

            <button
              type="submit"
              className="btn btn-primary btn-shine"
              style={{
                width: '100%',
                padding: '1rem',
                fontSize: '11px',
                marginTop: '0.5rem',
              }}
            >
              {isRegister ? 'REQUEST CLEARANCE' : 'INITIALIZE DEPLOYMENT'}
            </button>
          </form>

          {/* Toggle */}
          <div style={{ textAlign: 'center', marginTop: '1.5rem' }}>
            <button
              onClick={() => setIsRegister(!isRegister)}
              style={{
                background: 'none',
                border: 'none',
                color: 'var(--primary-container)',
                fontSize: '10px',
                textTransform: 'uppercase',
                letterSpacing: '0.15em',
              }}
            >
              {isRegister ? '← Return to Vault Entry' : 'Request Access / Register →'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
