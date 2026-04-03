import React, { useState, useEffect, useRef } from 'react';
import { ATTACK_PRESETS, simulateAttack } from '../data/mockData';

function FlowVisualization({ stage, blocked }) {
  const nodeClass = (node) => {
    if (node === 'user' && stage >= 1) return 'flow-node active-user';
    if (node === 'shield' && stage >= 2) return blocked ? 'flow-node blocked' : 'flow-node active-shield';
    if (node === 'llm' && stage >= 3 && !blocked) return 'flow-node active-llm';
    return 'flow-node';
  };

  const lineClass = (idx) => {
    if (idx === 1 && stage >= 2) return blocked && stage >= 2 ? 'flow-line blocked' : 'flow-line active';
    if (idx === 2 && stage >= 3 && !blocked) return 'flow-line active';
    return 'flow-line';
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '2rem 0' }}>
      {/* User Node */}
      <div className={nodeClass('user')}>
        <span className="material-symbols-outlined" style={{ fontSize: '24px' }}>person</span>
      </div>
      <div className="label" style={{ color: stage >= 1 ? 'var(--secondary-container)' : 'var(--outline)', margin: '0.25rem 0', fontSize: '8px' }}>
        User Input
      </div>

      {/* Line 1 */}
      <div className={lineClass(1)} />

      {/* Shield Node */}
      <div className={nodeClass('shield')}>
        <span className="material-symbols-outlined" style={{ fontSize: '24px' }}>security</span>
      </div>
      <div className="label" style={{
        color: stage >= 2 ? (blocked ? 'var(--error)' : 'var(--primary-container)') : 'var(--outline)',
        margin: '0.25rem 0', fontSize: '8px',
      }}>
        {stage >= 2 ? (blocked ? 'BLOCKED' : 'Analyzing...') : 'ShieldProxy'}
      </div>

      {/* Line 2 */}
      <div className={lineClass(2)} />

      {/* LLM Node */}
      <div className={nodeClass('llm')}>
        <span className="material-symbols-outlined" style={{ fontSize: '24px' }}>smart_toy</span>
      </div>
      <div className="label" style={{
        color: stage >= 3 && !blocked ? 'var(--on-surface)' : 'var(--outline)',
        margin: '0.25rem 0', fontSize: '8px',
      }}>
        {stage >= 3 && !blocked ? 'Received' : 'LLM Endpoint'}
      </div>
    </div>
  );
}

function CodeViewer({ data }) {
  if (!data) return null;
  const json = JSON.stringify(data, null, 2);
  const lines = json.split('\n');

  return (
    <div className="code-block" style={{ maxHeight: '240px', overflowY: 'auto' }}>
      {lines.map((line, i) => {
        let colored = line
          .replace(/"([^"]+)"(?=:)/g, '<span style="color:#00ff9d">"$1"</span>')
          .replace(/: "([^"]+)"/g, ': <span style="color:#ffb4ab">"$1"</span>')
          .replace(/: ([0-9.]+)/g, ': <span style="color:#00e3fd">$1</span>');

        return (
          <div key={i} style={{ display: 'flex' }}>
            <span className="code-line-number">{i + 1}</span>
            <span dangerouslySetInnerHTML={{ __html: colored }} />
          </div>
        );
      })}
    </div>
  );
}

export default function Simulator() {
  const [shieldActive, setShieldActive] = useState(true);
  const [category, setCategory] = useState('Prompt Injection');
  const [payload, setPayload] = useState('');
  const [targetModel, setTargetModel] = useState('GPT-4');
  const [simState, setSimState] = useState('idle'); // idle | simulating | done
  const [result, setResult] = useState(null);
  const [stage, setStage] = useState(0);
  const [showPresets, setShowPresets] = useState(false);
  const timerRef = useRef(null);

  const categories = ['Prompt Injection', 'Jailbreak', 'System Prompt Leak', 'Social Engineering', 'Business Logic Bypass'];
  const aiModels = ['GPT-4', 'Gemini 1.5 Pro', 'Claude 3.5 Sonnet', 'Llama 3 (Local)'];

  const presets = ATTACK_PRESETS.filter((p) =>
    category === 'Jailbreak' ? p.category === 'Prompt Injection' : p.category === category
  );

  const runSimulation = () => {
    if (!payload.trim()) return;

    setSimState('simulating');
    setResult(null);
    setStage(0);

    // Step 1: User sends
    setTimeout(() => setStage(1), 0);

    // Step 2: Shield analyzes
    setTimeout(() => setStage(2), 400);

    // Step 3: Result
    setTimeout(() => {
      const res = simulateAttack(payload, shieldActive, targetModel);
      setResult(res);
      setStage(res.blocked ? 2 : 3);
      setSimState('done');
    }, 1200);
  };

  const clearAll = () => {
    setPayload('');
    setSimState('idle');
    setResult(null);
    setStage(0);
  };

  return (
    <div className="fade-in-up">
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '2rem' }}>
        <div>
          <h1 style={{ fontFamily: 'var(--font-headline)', fontSize: '2.25rem', color: 'var(--primary)', marginBottom: '0.5rem' }}>
            Attack Simulation Engine
          </h1>
          <div className="label" style={{ color: 'var(--secondary-container)' }}>
            Red-Team Testing & Threat Vector Injection
          </div>
        </div>

        {/* Shield Toggle */}
        <div className="glass-panel" style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.5rem 1rem', borderRadius: '2rem' }}>
          <span className="label" style={{ color: shieldActive ? 'var(--outline)' : 'var(--on-surface)' }}>Standard</span>
          <button
            className={`toggle-switch${shieldActive ? ' active' : ''}`}
            onClick={() => setShieldActive(!shieldActive)}
          />
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
            <span className="material-symbols-outlined" style={{
              fontSize: '18px',
              color: shieldActive ? 'var(--primary-container)' : 'var(--outline)',
              fontVariationSettings: shieldActive ? "'FILL' 1, 'wght' 400, 'GRAD' 0, 'opsz' 24" : undefined,
            }}>
              security
            </span>
            <span className="label" style={{ color: shieldActive ? 'var(--primary-container)' : 'var(--outline)' }}>
              ShieldProxy {shieldActive ? 'Active' : 'Inactive'}
            </span>
          </div>
        </div>
      </div>

      {/* Three Column Layout */}
      <div style={{ display: 'grid', gridTemplateColumns: '5fr 2fr 5fr', gap: '1.5rem' }}>
        {/* Left — Payload Editor */}
        <div className="glass-card" style={{ padding: '1.5rem', borderTop: '1px solid rgba(0, 255, 157, 0.2)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.25rem' }}>
            <span className="material-symbols-outlined" style={{ fontSize: '20px', color: 'var(--primary-container)' }}>terminal</span>
            <span style={{ fontFamily: 'var(--font-headline)', fontSize: '1.125rem', color: 'var(--primary)' }}>Payload Editor</span>
          </div>

          {/* AI Model Dropdown */}
          <div style={{ marginBottom: '1.25rem' }}>
            <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.5rem' }}>Target AI Model</div>
            <div style={{ position: 'relative' }}>
              <select 
                className="input-underline" 
                style={{ width: '100%', appearance: 'none', cursor: 'none' }}
                value={targetModel}
                onChange={(e) => setTargetModel(e.target.value)}
              >
                {aiModels.map(m => <option key={m} value={m} style={{ background: '#121416', color: '#e2e2e5' }}>{m}</option>)}
              </select>
              <span className="material-symbols-outlined" style={{ position: 'absolute', right: '0', top: '50%', transform: 'translateY(-50%)', color: 'var(--outline)', pointerEvents: 'none' }}>expand_more</span>
            </div>
          </div>

          {/* Category Pills */}
          <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.5rem' }}>Attack Vector</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.375rem', marginBottom: '1rem' }}>
            {categories.map((cat) => (
              <button
                key={cat}
                className={`filter-btn${category === cat ? ' active' : ''}`}
                style={{ borderRadius: 'var(--radius-xl)', border: '1px solid var(--outline-variant)', fontSize: '9px', padding: '0.375rem 0.75rem' }}
                onClick={() => setCategory(cat)}
              >
                {cat}
              </button>
            ))}
          </div>

          {/* Pre-built Exploits */}
          <div style={{ marginBottom: '1rem' }}>
            <button
              className="btn btn-outline"
              style={{ width: '100%', justifyContent: 'space-between', padding: '0.5rem 0.75rem' }}
              onClick={() => setShowPresets(!showPresets)}
            >
              <span style={{ fontSize: '10px' }}>Pre-built Exploits</span>
              <span className="material-symbols-outlined" style={{ fontSize: '16px', transform: showPresets ? 'rotate(180deg)' : '', transition: 'transform 0.2s' }}>
                expand_more
              </span>
            </button>
            {showPresets && (
              <div className="fade-in-up" style={{ marginTop: '0.5rem', display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
                {presets.map((preset, i) => (
                  <button
                    key={i}
                    className="glass-panel"
                    style={{
                      padding: '0.625rem 0.75rem',
                      textAlign: 'left',
                      border: '1px solid var(--outline-variant)',
                      background: 'rgba(26,28,30,0.4)',
                      color: 'var(--on-surface-variant)',
                      fontSize: '0.75rem',
                      lineHeight: '1.4',
                      transition: 'background 0.2s',
                    }}
                    onClick={() => { setPayload(preset.payload); setShowPresets(false); }}
                    onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.05)'}
                    onMouseLeave={(e) => e.currentTarget.style.background = 'rgba(26,28,30,0.4)'}
                  >
                    <div className="label" style={{ color: 'var(--primary-container)', marginBottom: '0.25rem', fontSize: '9px' }}>{preset.label}</div>
                    {preset.payload.slice(0, 80)}...
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Textarea */}
          <div style={{ position: 'relative', marginBottom: '1rem' }}>
            <textarea
              className="simulator-textarea"
              placeholder="PROMPT INPUT VECTOR..."
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              rows={8}
            />
            <div style={{ position: 'absolute', bottom: '0.5rem', right: '0.75rem' }}>
              <span className="label" style={{ color: 'rgba(0,255,157,0.2)', fontSize: '8px' }}>UTF-8 SURVEILLANCE</span>
            </div>
          </div>

          {/* Buttons */}
          <div style={{ display: 'flex', gap: '0.75rem' }}>
            <button className="btn btn-outline" onClick={clearAll}>
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>backspace</span>
              Clear
            </button>
            <button
              className="btn btn-primary btn-shine"
              style={{ flex: 1 }}
              onClick={runSimulation}
              disabled={simState === 'simulating'}
            >
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>play_arrow</span>
              {simState === 'simulating' ? 'Executing...' : 'Execute Attack'}
            </button>
          </div>
        </div>

        {/* Center — Flow Visualization */}
        <div className="glass-card" style={{ padding: '1rem', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
          <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.5rem' }}>Flow Analysis</div>
          <FlowVisualization stage={stage} blocked={result?.blocked} />
        </div>

        {/* Right — Evaluation Result */}
        <div className="glass-card" style={{ padding: '1.5rem', borderTop: '1px solid rgba(0, 227, 253, 0.2)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.25rem' }}>
            <span className="material-symbols-outlined" style={{ fontSize: '20px', color: 'var(--secondary-container)' }}>analytics</span>
            <span style={{ fontFamily: 'var(--font-headline)', fontSize: '1.125rem', color: 'var(--primary)' }}>Evaluation Result</span>
          </div>

          {simState === 'idle' && (
            <div style={{ textAlign: 'center', padding: '3rem 1rem' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '48px', color: 'var(--outline-variant)', display: 'block', marginBottom: '1rem' }}>hourglass_empty</span>
              <p style={{ color: 'var(--outline)', fontSize: '0.875rem' }}>Awaiting prompt input...</p>
            </div>
          )}

          {simState === 'simulating' && (
            <div style={{ textAlign: 'center', padding: '3rem 1rem' }}>
              <div style={{
                width: '40px', height: '40px', border: '3px solid var(--outline-variant)',
                borderTop: '3px solid var(--primary-container)', borderRadius: '50%',
                margin: '0 auto 1rem', animation: 'spin 1s linear infinite',
              }} />
              <p style={{ color: 'var(--primary-container)', fontSize: '0.875rem' }}>Layered heuristic scanning active...</p>
            </div>
          )}

          {simState === 'done' && result && (
            <div className="fade-in-up">
              {/* Verdict Banner */}
              <div className={result.blocked ? 'verdict-blocked' : 'verdict-passed'} style={{
                padding: '1.25rem',
                display: 'flex',
                alignItems: 'center',
                gap: '1rem',
                marginBottom: '1.5rem',
              }}>
                <span className="material-symbols-outlined" style={{
                  fontSize: '32px',
                  color: result.blocked ? 'var(--error)' : 'var(--primary-container)',
                }}>
                  {result.blocked ? 'gpp_bad' : 'check_circle'}
                </span>
                <div>
                  <div style={{
                    fontSize: '1.25rem',
                    fontWeight: 600,
                    color: result.blocked ? 'var(--error)' : 'var(--primary-container)',
                    letterSpacing: '0.1em',
                  }}>
                    REQUEST {result.blocked ? 'BLOCKED' : 'PASSED'}
                  </div>
                  <div className="label" style={{ color: 'var(--outline)', fontSize: '9px' }}>
                    Shield: {shieldActive ? 'Active' : 'Inactive'}
                  </div>
                </div>
              </div>

              {/* Stats Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
                <div>
                  <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.25rem' }}>Confidence</div>
                  <div style={{ fontSize: '1.5rem', fontWeight: 300, color: result.blocked ? 'var(--error)' : 'var(--primary-container)' }}>{result.confidence}%</div>
                  <div className="progress-bar" style={{ marginTop: '0.375rem' }}>
                    <div className="progress-bar-fill" style={{
                      width: `${result.confidence}%`,
                      background: result.blocked ? 'var(--error)' : 'var(--primary-container)',
                      boxShadow: result.blocked ? '0 0 8px rgba(255,180,171,0.4)' : undefined,
                    }} />
                  </div>
                </div>
                <div>
                  <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.25rem' }}>Latency</div>
                  <div style={{ fontSize: '1.5rem', fontWeight: 300, color: 'var(--secondary-container)' }}>{result.latency}ms</div>
                </div>
              </div>

              {/* Category */}
              <div style={{ marginBottom: '1.5rem' }}>
                <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.5rem' }}>Detected Category</div>
                <span className="badge badge-critical">{result.category}</span>
              </div>

              {/* Raw JSON */}
              <div>
                <div className="label" style={{ color: 'var(--outline)', marginBottom: '0.5rem' }}>Raw Response</div>
                <CodeViewer data={result.raw} />
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="deco-footer">
        SANDCASTLE_ENGINE_v5.0.1 // ACTIVE CONTAINMENT
      </div>
    </div>
  );
}
