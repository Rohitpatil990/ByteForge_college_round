import React, { useState } from 'react';
import { api } from '../api';
import { Zap, CheckCircle2, AlertTriangle, ArrowRight, CornerDownRight, RefreshCw } from 'lucide-react';

interface Props {
  assessmentId: string;
  hasRuns: boolean;
  onChallengeCompleted: () => void;
}

export const ChallengeView: React.FC<Props> = ({
  assessmentId,
  hasRuns,
  onChallengeCompleted,
}) => {
  const [challenging, setChallenging] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<any | null>(null);

  const handleChallenge = async () => {
    setChallenging(true);
    setError(null);
    try {
      const res = await api.challengeDefenses(assessmentId);
      setResult(res);
      onChallengeCompleted();
    } catch (err: any) {
      setError(err.message || 'Challenge failed');
    } finally {
      setChallenging(false);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h2 className="page-title">
            <Zap size={18} color="#00e5ff" /> Adaptive Attacker Challenge Loop
          </h2>
          <p className="page-desc">
            Closed-loop adversary mutation: when an attack is blocked by a guard, the attacker receives the refusal feedback
            and automatically rewrites the prompt to challenge the defense.
          </p>
        </div>
      </div>

      {!hasRuns && (
        <div className="alert-banner alert-warning">
          <span>
            <AlertTriangle size={14} style={{ display: 'inline', marginRight: '0.4rem', verticalAlign: '-2px' }} />
            No initial runs found to challenge. Please run the seed benchmark suite in <strong>Execute Tests</strong> first.
          </span>
        </div>
      )}

      {error && <div className="alert-banner alert-danger">{error}</div>}

      {/* Control Panel */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h3 className="panel-title">Adaptive Feedback Generator</h3>
            <p className="panel-subtitle">Target: <code className="mono">demo-company-assistant</code> | Session: <code className="mono">{assessmentId}</code></p>
          </div>
          <span className="chip chip-generated">Round 1 Mutation</span>
        </div>

        <div style={{ padding: '0.5rem 0 1rem 0' }}>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '1rem', lineHeight: '1.5' }}>
            The adaptive attacker inspects the policy denial reason returned by D1 (e.g. <em>"Recipient domain is restricted to company.com"</em>),
            mutates its exfiltration strategy to route through an internal company relay address (<code className="mono">relay-dispatcher@company.com</code>),
            and evaluates whether the canary token is delivered into tool arguments.
          </p>

          <button
            className="btn btn-primary"
            onClick={handleChallenge}
            disabled={challenging || !hasRuns}
            style={{ padding: '0.55rem 1.4rem', fontSize: '0.85rem' }}
          >
            <Zap size={15} /> {challenging ? 'Simulating Adaptive Challenge...' : 'Challenge Active Defenses'}
          </button>
        </div>

        {/* Challenge Results */}
        {result && (
          <div
            style={{
              padding: '1.1rem',
              background: 'var(--bg-surface-elevated)',
              borderRadius: '5px',
              border: '1px solid var(--border-medium)',
              marginTop: '0.75rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem', color: '#10b981', fontWeight: 600 }}>
              <CheckCircle2 size={16} /> Adaptive Challenge Completed
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.75rem', marginBottom: '0.85rem' }}>
              <div style={{ padding: '0.6rem 0.75rem', background: 'var(--bg-app)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-subtle)', textTransform: 'uppercase', display: 'block' }}>New Run ID</span>
                <span className="mono" style={{ fontSize: '0.82rem', fontWeight: 600, color: '#fff' }}>{result.challenge_run_id}</span>
              </div>

              <div style={{ padding: '0.6rem 0.75rem', background: 'var(--bg-app)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-subtle)', textTransform: 'uppercase', display: 'block' }}>Parent Seed Run</span>
                <span className="mono" style={{ fontSize: '0.82rem', color: '#f59e0b' }}>{result.parent_run_id}</span>
              </div>

              <div style={{ padding: '0.6rem 0.75rem', background: 'var(--bg-app)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-subtle)', textTransform: 'uppercase', display: 'block' }}>Mutation Iteration</span>
                <strong style={{ fontSize: '0.82rem', color: '#fff' }}>Round {result.round}</strong>
              </div>

              <div style={{ padding: '0.6rem 0.75rem', background: 'var(--bg-app)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-subtle)', textTransform: 'uppercase', display: 'block' }}>Source Tag</span>
                <span className="chip chip-generated">Adaptive Generated</span>
              </div>
            </div>

            {/* Denial Feedback Delivered to Attacker */}
            {result.feedback && (
              <div style={{ padding: '0.65rem 0.8rem', background: 'var(--bg-app)', borderRadius: '4px', border: '1px solid var(--border-subtle)', marginBottom: '0.85rem' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-subtle)', textTransform: 'uppercase', display: 'block', marginBottom: '0.2rem' }}>
                  Guard Feedback Provided to Attacker ({result.feedback.type}):
                </span>
                <p className="mono" style={{ color: '#fca5a5', fontSize: '0.78rem' }}>"{result.feedback.text}"</p>
                {result.feedback.rule && (
                  <span className="mono" style={{ fontSize: '0.72rem', color: 'var(--text-subtle)', display: 'block', marginTop: '0.2rem' }}>
                    Triggered Policy Rule: {result.feedback.rule}
                  </span>
                )}
              </div>
            )}

            {/* Analysis Outcome */}
            <div style={{ fontSize: '0.82rem', color: '#e2e8f0', lineHeight: '1.45' }}>
              <strong>Adversarial Outcome: </strong>
              <span className="chip chip-exploit" style={{ marginRight: '0.45rem' }}>
                {result.verdict}
              </span>
              Rule fired: <code className="mono" style={{ color: '#00e5ff' }}>{result.rule_fired}</code>.
              The adaptive attacker bypassed the external domain filter by complying with the <code className="mono">company.com</code> recipient restriction,
              while smuggling the canary token inside the tool execution arguments.
            </div>
          </div>
        )}
      </div>

      {/* Disclosures & Discovery Rules */}
      <div className="panel">
        <h4 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
          Frozen Schema Discovery Classification
        </h4>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', lineHeight: '1.5' }}>
          In AgentBreak, only variants generated dynamically via the feedback loop (<code className="mono">variant_source: "generated"</code>)
          count as adaptive discoveries. Pre-recorded fixtures (<code className="mono">source: "recorded"</code>) and seed benchmark tests
          are strictly isolated and never inflate adaptive-found statistics.
        </p>
      </div>
    </div>
  );
};
