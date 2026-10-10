import React, { useState } from 'react';
import { api } from '../api';
import { Zap, CheckCircle2, AlertTriangle, ArrowRight, RefreshCw, ChevronDown, ChevronUp } from 'lucide-react';

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
  const [showTechnical, setShowTechnical] = useState<boolean>(false);

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
          <h1 className="page-title">Try a New Attack</h1>
          <p className="page-desc">
            Test whether an attacker can adapt their prompt to bypass your active protections when their initial attempt is blocked.
          </p>
        </div>
      </div>

      {!hasRuns && (
        <div className="alert-banner alert-warning">
          <span>
            <AlertTriangle size={15} style={{ display: 'inline', marginRight: '0.4rem', verticalAlign: '-2px' }} />
            No baseline tests recorded yet. Please run tests in <strong>Run Security Test</strong> first.
          </span>
        </div>
      )}

      {error && <div className="alert-banner alert-danger">{error}</div>}

      {/* 4-Step Adaptive Workflow Card */}
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">How the Adaptive Attack Works</h2>
            <p className="card-subtitle">Automated attacker mutation loop</p>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', marginBottom: '1.25rem' }}>
          <div style={{ padding: '0.85rem', backgroundColor: 'var(--bg-surface-subtle)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-default)' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--primary)', marginBottom: '0.25rem' }}>
              STEP 1
            </div>
            <strong style={{ fontSize: '0.86rem', color: 'var(--text-primary)', display: 'block', marginBottom: '0.2rem' }}>
              Try an attack
            </strong>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              Attacker sends a malicious request to exfiltrate confidential data.
            </p>
          </div>

          <div style={{ padding: '0.85rem', backgroundColor: 'var(--bg-surface-subtle)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-default)' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--primary)', marginBottom: '0.25rem' }}>
              STEP 2
            </div>
            <strong style={{ fontSize: '0.86rem', color: 'var(--text-primary)', display: 'block', marginBottom: '0.2rem' }}>
              Examine response
            </strong>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              Guard blocks the action and returns a denial message explaining why.
            </p>
          </div>

          <div style={{ padding: '0.85rem', backgroundColor: 'var(--bg-surface-subtle)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-default)' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--primary)', marginBottom: '0.25rem' }}>
              STEP 3
            </div>
            <strong style={{ fontSize: '0.86rem', color: 'var(--text-primary)', display: 'block', marginBottom: '0.2rem' }}>
              Try a variation
            </strong>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              Attacker rewrites the prompt to evade the specific policy constraint.
            </p>
          </div>

          <div style={{ padding: '0.85rem', backgroundColor: 'var(--bg-surface-subtle)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-default)' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--primary)', marginBottom: '0.25rem' }}>
              STEP 4
            </div>
            <strong style={{ fontSize: '0.86rem', color: 'var(--text-primary)', display: 'block', marginBottom: '0.2rem' }}>
              Check the result
            </strong>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              Evaluates if the variation succeeded or was blocked by remaining guards.
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', paddingTop: '0.5rem' }}>
          <button
            className="btn btn-primary btn-lg"
            onClick={handleChallenge}
            disabled={challenging || !hasRuns}
          >
            {challenging ? (
              <>
                <RefreshCw size={15} className="animate-spin" /> Generating Attack Variation...
              </>
            ) : (
              <>
                <Zap size={15} /> Run Adaptive Attack
              </>
            )}
          </button>

          {challenging && (
            <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              Analyzing denial feedback and mutating attack strategy...
            </span>
          )}
        </div>

        {/* Results Card */}
        {result && (
          <div
            style={{
              marginTop: '1.25rem',
              padding: '1.25rem',
              backgroundColor: 'var(--bg-surface-subtle)',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border-default)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--success)', fontWeight: 600 }}>
                <CheckCircle2 size={18} /> Adaptive Attack Executed
              </div>
              <span className="badge badge-neutral">Round {result.round}</span>
            </div>

            {/* Outcome Explanation */}
            <div
              style={{
                padding: '0.85rem 1rem',
                backgroundColor: result.verdict === 'confirmed_exploit' ? 'var(--danger-subtle)' : 'var(--success-subtle)',
                border: `1px solid ${result.verdict === 'confirmed_exploit' ? 'var(--danger-border)' : 'var(--success-border)'}`,
                borderRadius: 'var(--radius-sm)',
                marginBottom: '1rem',
              }}
            >
              <div style={{ fontWeight: 600, color: result.verdict === 'confirmed_exploit' ? 'var(--danger)' : 'var(--success)', marginBottom: '0.2rem' }}>
                {result.verdict === 'confirmed_exploit' ? 'Attack Succeeded on Variation' : 'Attack Was Blocked'}
              </div>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-primary)', lineHeight: '1.45' }}>
                {result.verdict === 'confirmed_exploit'
                  ? 'The attacker adapted to the email domain policy by routing through an internal company address, but successfully smuggled the canary token inside the tool parameters.'
                  : 'The guardrails successfully caught the attack variation.'}
              </p>
            </div>

            {/* Feedback Delivered */}
            {result.feedback && (
              <div style={{ marginBottom: '1rem', padding: '0.75rem', backgroundColor: 'var(--bg-surface)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-light)' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                  Guard Feedback Observed by Attacker
                </div>
                <div className="mono" style={{ fontSize: '0.82rem', color: 'var(--text-primary)' }}>
                  "{result.feedback.text}"
                </div>
              </div>
            )}

            {/* Progressive Disclosure: Technical Details */}
            <div>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => setShowTechnical(!showTechnical)}
                style={{ fontSize: '0.78rem' }}
              >
                {showTechnical ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                {showTechnical ? 'Hide Technical Metadata' : 'View Technical Metadata'}
              </button>

              {showTechnical && (
                <div style={{ marginTop: '0.75rem', padding: '0.75rem', backgroundColor: 'var(--bg-surface)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-light)', fontSize: '0.8rem' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.5rem' }}>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>New Run ID: </span>
                      <code className="mono">{result.challenge_run_id}</code>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Parent Seed Run: </span>
                      <code className="mono">{result.parent_run_id}</code>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Triggered Rule: </span>
                      <code className="mono">{result.rule_fired}</code>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Source Provenance: </span>
                      <span className="badge badge-neutral">Adaptive Generated</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
