import React, { useState } from 'react';
import { Defense } from '../types';
import { api } from '../api';
import { ShieldCheck, ShieldAlert, AlertCircle, CheckCircle2 } from 'lucide-react';

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
      setError(`'${d.name}' is a development stub and cannot be toggled.`);
      return;
    }

    setTogglingId(d.id);
    setError(null);
    try {
      const updated = await api.toggleDefense(assessmentId, d.id);
      const newDefenses = defenses.map((item) => (item.id === updated.id ? updated : item));
      onDefensesUpdated(newDefenses);
    } catch (err: any) {
      setError(err.message || 'Failed to update protection status');
    } finally {
      setTogglingId(null);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Protection</h1>
          <p className="page-desc">
            Guardrails that intercept unauthorized tool calls and protect your agent against adversarial exploits.
          </p>
        </div>
      </div>

      {error && <div className="alert-banner alert-warning">{error}</div>}

      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Configured Guardrails</h2>
            <p className="card-subtitle">Active and planned security guards for the tested agent</p>
          </div>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            {defenses.length} guardrail(s) configured
          </span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {defenses.map((d) => {
            const isEnforced = d.status === 'enforced';
            const isStub = d.is_stub || d.status === 'stub';

            return (
              <div
                key={d.id}
                style={{
                  padding: '1.25rem',
                  borderRadius: 'var(--radius-md)',
                  backgroundColor: 'var(--bg-surface)',
                  border: isStub
                    ? '1px solid var(--warning-border)'
                    : isEnforced
                    ? '1px solid var(--success-border)'
                    : '1px solid var(--border-default)',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '0.65rem' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                      <strong style={{ fontSize: '0.98rem', color: 'var(--text-primary)' }}>
                        {d.name}
                      </strong>
                      {isStub ? (
                        <span className="badge badge-warning">Development Stub</span>
                      ) : isEnforced ? (
                        <span className="badge badge-success">
                          <CheckCircle2 size={12} /> Active / Enforced
                        </span>
                      ) : (
                        <span className="badge badge-neutral">Disabled</span>
                      )}
                    </div>
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      Interception Target: <strong style={{ color: 'var(--text-secondary)' }}>{d.target_component}</strong>
                      {' • '}
                      Mitigates Rule: <code className="mono">{d.mitigation_rule}</code>
                    </div>
                  </div>

                  {!isStub ? (
                    <button
                      className={`btn ${isEnforced ? 'btn-secondary' : 'btn-primary'} btn-sm`}
                      disabled={togglingId === d.id}
                      onClick={() => handleToggle(d)}
                      style={{ minWidth: '120px' }}
                    >
                      {togglingId === d.id ? 'Updating...' : isEnforced ? 'Disable Guard' : 'Enable Guard'}
                    </button>
                  ) : (
                    <span className="badge badge-neutral" style={{ fontSize: '0.74rem' }}>
                      Planned in Roadmap
                    </span>
                  )}
                </div>

                <p style={{ fontSize: '0.86rem', color: 'var(--text-secondary)', lineHeight: '1.45', marginBottom: d.denial_message ? '0.65rem' : '0' }}>
                  {d.description}
                </p>

                {d.denial_message && (
                  <div
                    style={{
                      padding: '0.5rem 0.75rem',
                      backgroundColor: 'var(--bg-surface-subtle)',
                      borderRadius: 'var(--radius-sm)',
                      border: '1px solid var(--border-light)',
                      fontSize: '0.8rem',
                    }}
                  >
                    <span style={{ color: 'var(--text-muted)' }}>Denial Message: </span>
                    <span className="mono" style={{ color: 'var(--danger)', fontWeight: 500 }}>
                      "{d.denial_message}"
                    </span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Boundary & Limitation Explanation */}
      <div className="card" style={{ backgroundColor: 'var(--bg-surface-subtle)' }}>
        <h3 style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.35rem' }}>
          Important Boundary: Tool Call Guards vs. Conversational Responses
        </h3>
        <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
          <strong>D1</strong> and <strong>D2</strong> inspect external tool call parameters before execution.
          They successfully block unauthorized email recipients or untrusted memory writes.
          However, if an attacker prompts the agent to recite confidential data directly in its conversation response (without invoking a tool),
          tool guards cannot intercept it. A conversational response filter (D3) is needed to mitigate direct speech disclosures.
        </p>
      </div>
    </div>
  );
};
