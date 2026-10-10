import React, { useState } from 'react';
import { Defense } from '../types';
import { api } from '../api';
import { Shield, ShieldAlert, CheckCircle2, AlertTriangle, ToggleLeft, ToggleRight, Info } from 'lucide-react';

interface Props {
  assessmentId: string;
  defenses: Defense[];
  onDefensesUpdated: (defenses: Defense[]) => void;
}

export const DefensesView: React.FC<Props> = ({
  assessmentId,
  defenses,
  onDefensesUpdated,
}) => {
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleToggle = async (d: Defense) => {
    if (d.is_stub) {
      setError(`Defense '${d.name}' is currently a development stub and cannot be actively enforced.`);
      return;
    }

    setTogglingId(d.id);
    setError(null);
    try {
      const updated = await api.toggleDefense(assessmentId, d.id);
      const newDefenses = defenses.map((item) => (item.id === updated.id ? updated : item));
      onDefensesUpdated(newDefenses);
    } catch (err: any) {
      setError(err.message || 'Failed to toggle defense');
    } finally {
      setTogglingId(null);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h2 className="page-title">
            <Shield size={18} color="#00e5ff" /> Active Defense Guards & Interceptors
          </h2>
          <p className="page-desc">
            Configure runtime security guardrails. Stubs are explicitly labeled and not misrepresented as active protection.
          </p>
        </div>
      </div>

      {error && <div className="alert-banner alert-warning">{error}</div>}

      <div className="panel">
        <div className="panel-header">
          <div>
            <h3 className="panel-title">Defense Control Matrix</h3>
            <p className="panel-subtitle">Inspected live from assessment configuration</p>
          </div>
          <span className="mono" style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
            3 Configured Controls
          </span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          {defenses.map((d) => {
            const isEnforced = d.status === 'enforced';
            const isStub = d.is_stub || d.status === 'stub';

            return (
              <div
                key={d.id}
                style={{
                  padding: '1rem',
                  borderRadius: '5px',
                  backgroundColor: 'var(--bg-app)',
                  border: isStub
                    ? '1px solid var(--amber-border)'
                    : isEnforced
                    ? '1px solid var(--emerald-border)'
                    : '1px solid var(--border-subtle)',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.4rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', marginBottom: '0.2rem' }}>
                      <strong style={{ fontSize: '0.92rem', color: '#fff' }}>{d.name}</strong>
                      {isStub ? (
                        <span className="chip chip-stub">Development Stub</span>
                      ) : isEnforced ? (
                        <span className="chip chip-enforced">Active / Enforced</span>
                      ) : (
                        <span className="chip chip-disabled">Disabled</span>
                      )}
                    </div>
                    <div style={{ display: 'flex', gap: '0.75rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      <span>Interception Point: <strong style={{ color: '#00e5ff' }}>{d.target_component}</strong></span>
                      <span>•</span>
                      <span>Mitigates: <code className="mono" style={{ color: '#cbd5e1' }}>{d.mitigation_rule}</code></span>
                    </div>
                  </div>

                  {!isStub ? (
                    <button
                      className={`btn ${isEnforced ? 'btn-secondary' : 'btn-primary'} btn-sm`}
                      disabled={togglingId === d.id}
                      onClick={() => handleToggle(d)}
                      style={{ minWidth: '110px' }}
                    >
                      {togglingId === d.id ? 'Updating...' : isEnforced ? 'Disable Guard' : 'Enable Guard'}
                    </button>
                  ) : (
                    <span className="chip chip-seed" style={{ fontSize: '0.7rem', color: 'var(--text-subtle)' }}>
                      Pending P3 Module
                    </span>
                  )}
                </div>

                <p style={{ fontSize: '0.8rem', color: '#cbd5e1', marginBottom: '0.5rem', lineHeight: '1.45' }}>
                  {d.description}
                </p>

                {d.denial_message && (
                  <div style={{ padding: '0.45rem 0.65rem', background: 'var(--bg-surface-elevated)', borderRadius: '3px', border: '1px solid var(--border-subtle)', fontSize: '0.76rem' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Interception Message: </span>
                    <span className="mono" style={{ color: '#fca5a5' }}>"{d.denial_message}"</span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Honest Boundary Notice */}
      <div className="panel" style={{ borderLeft: '3px solid #f59e0b' }}>
        <h4 style={{ fontSize: '0.85rem', fontWeight: 600, color: '#fde68a', marginBottom: '0.35rem' }}>
          Crucial Architectural Boundary: Tool Guards vs. Reply Leaks
        </h4>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', lineHeight: '1.5' }}>
          <strong>D1</strong> and <strong>D2</strong> inspect outgoing function call payloads (<code className="mono">tool_call</code>).
          However, if an attacker prompts the agent to output confidential canary tokens directly in its delivered conversation reply (<code className="mono">final_reply</code>),
          no tool call is executed. Therefore, tool-call policies alone cannot intercept response leaks.
          Output filter <strong>D3</strong> is currently a development stub, leaving final reply secrets unmitigated until P3 integration.
        </p>
      </div>
    </div>
  );
};
