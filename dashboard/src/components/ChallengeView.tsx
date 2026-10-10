import React, { useState } from 'react';
import { api } from '../api';
import { ChallengeResult } from '../types';
import {
  Zap,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  ShieldAlert,
  ShieldCheck,
  Compass,
} from 'lucide-react';

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
  const [resetting, setResetting] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ChallengeResult | null>(null);
  const [showTechnical, setShowTechnical] = useState<boolean>(false);

  const handleChallenge = async () => {
    if (challenging) return;
    setChallenging(true);
    setError(null);
    try {
      const res = await api.challengeDefenses(assessmentId, 'real_sandbox');
      setResult(res);
      onChallengeCompleted();
    } catch (err: any) {
      setError(err.message || 'Challenge failed');
    } finally {
      setChallenging(false);
    }
  };

  const handleReset = async () => {
    if (resetting) return;
    setResetting(true);
    setError(null);
    try {
      await api.resetChallenge(assessmentId);
      setResult(null);
      onChallengeCompleted();
    } catch (err: any) {
      setError(err.message || 'Reset failed');
    } finally {
      setResetting(false);
    }
  };

  const isExhausted = Boolean(result?.exhausted);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Try a New Attack</h1>
          <p className="page-desc">
            Test whether an attacker can adapt their prompt across 7 dynamic adversarial strategies to bypass active protections.
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
            <p className="card-subtitle">Automated attacker mutation loop across 7 threat vectors</p>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', marginBottom: '1.25rem' }}>
          <div style={{ padding: '0.85rem', backgroundColor: 'var(--bg-surface-subtle)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-default)' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--primary)', marginBottom: '0.25rem' }}>
              STEP 1
            </div>
            <strong style={{ fontSize: '0.86rem', color: 'var(--text-primary)', display: 'block', marginBottom: '0.2rem' }}>
              Evaluate Target
            </strong>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              Attacker checks previous execution feedback and guard denial reasons.
            </p>
          </div>

          <div style={{ padding: '0.85rem', backgroundColor: 'var(--bg-surface-subtle)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-default)' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--primary)', marginBottom: '0.25rem' }}>
              STEP 2
            </div>
            <strong style={{ fontSize: '0.86rem', color: 'var(--text-primary)', display: 'block', marginBottom: '0.2rem' }}>
              Rotate Strategy
            </strong>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              Pivots to an unattempted vector (role impersonation, context smuggling, internal relay, etc.).
            </p>
          </div>

          <div style={{ padding: '0.85rem', backgroundColor: 'var(--bg-surface-subtle)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-default)' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--primary)', marginBottom: '0.25rem' }}>
              STEP 3
            </div>
            <strong style={{ fontSize: '0.86rem', color: 'var(--text-primary)', display: 'block', marginBottom: '0.2rem' }}>
              Mutate Prompt
            </strong>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              Generates a genuinely fresh prompt payload adapted around the previous block.
            </p>
          </div>

          <div style={{ padding: '0.85rem', backgroundColor: 'var(--bg-surface-subtle)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-default)' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--primary)', marginBottom: '0.25rem' }}>
              STEP 4
            </div>
            <strong style={{ fontSize: '0.86rem', color: 'var(--text-primary)', display: 'block', marginBottom: '0.2rem' }}>
              Execute in Sandbox
            </strong>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              Analyzes trace evidence and records cryptographic proof without duplicating findings.
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', paddingTop: '0.5rem', flexWrap: 'wrap' }}>
          <button
            className="btn btn-primary btn-lg"
            onClick={handleChallenge}
            disabled={challenging || resetting || !hasRuns || isExhausted}
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

          {isExhausted && (
            <button
              className="btn btn-secondary btn-lg"
              onClick={handleReset}
              disabled={resetting || challenging}
            >
              {resetting ? (
                <>
                  <RefreshCw size={15} className="animate-spin" /> Resetting History...
                </>
              ) : (
                <>
                  <RotateCcw size={15} /> Reset Attack History
                </>
              )}
            </button>
          )}

          {challenging && (
            <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              Analyzing denial feedback and mutating attack strategy...
            </span>
          )}
        </div>

        {/* Exhaustion Banner */}
        {isExhausted && (
          <div
            style={{
              marginTop: '1.25rem',
              padding: '1rem 1.25rem',
              backgroundColor: 'var(--warning-subtle)',
              border: '1px solid var(--warning-border)',
              borderRadius: 'var(--radius-md)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '1rem',
              flexWrap: 'wrap',
            }}
          >
            <div>
              <div style={{ fontWeight: 600, color: 'var(--warning)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <AlertTriangle size={16} /> Strategy Pool Exhausted
              </div>
              <p style={{ fontSize: '0.84rem', color: 'var(--text-primary)', marginTop: '0.2rem' }}>
                {result?.message || 'All viable adaptive attack strategies have been tested for this target configuration.'}
              </p>
            </div>
            <button className="btn btn-secondary btn-sm" onClick={handleReset} disabled={resetting}>
              <RotateCcw size={13} /> Reset and Start New Sequence
            </button>
          </div>
        )}

        {/* Results Card */}
        {result && !result.exhausted && (
          <div
            style={{
              marginTop: '1.25rem',
              padding: '1.25rem',
              backgroundColor: 'var(--bg-surface-subtle)',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border-default)',
            }}
          >
            {/* Header: Attempt, Strategy, Round */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <span className="badge badge-primary" style={{ fontSize: '0.8rem', padding: '0.25rem 0.6rem' }}>
                  Attempt #{result.attempt_number || result.round}
                </span>
                <span style={{ fontWeight: 700, fontSize: '0.95rem', color: 'var(--text-primary)' }}>
                  Strategy: {result.strategy_name || result.strategy?.replace(/_/g, ' ').toUpperCase()}
                </span>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                <span className="badge badge-neutral">Round {result.round}</span>
                <span className="badge badge-neutral">{result.execution_mode}</span>
              </div>
            </div>

            {/* Outcome Explanation Card */}
            <div
              style={{
                padding: '0.85rem 1rem',
                backgroundColor: result.verdict === 'confirmed_exploit' ? 'var(--danger-subtle)' : result.verdict === 'blocked' ? 'var(--success-subtle)' : 'var(--bg-surface)',
                border: `1px solid ${result.verdict === 'confirmed_exploit' ? 'var(--danger-border)' : result.verdict === 'blocked' ? 'var(--success-border)' : 'var(--border-default)'}`,
                borderRadius: 'var(--radius-sm)',
                marginBottom: '1rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontWeight: 600, color: result.verdict === 'confirmed_exploit' ? 'var(--danger)' : result.verdict === 'blocked' ? 'var(--success)' : 'var(--text-primary)', marginBottom: '0.25rem' }}>
                {result.verdict === 'confirmed_exploit' ? (
                  <>
                    <ShieldAlert size={16} /> Confirmed Exploit: Attack Succeeded on Variation
                  </>
                ) : result.verdict === 'blocked' ? (
                  <>
                    <ShieldCheck size={16} /> Blocked: Guard Intercepted the Variation
                  </>
                ) : (
                  <>
                    <CheckCircle2 size={16} /> No Policy Violation Detected
                  </>
                )}
              </div>
              <p style={{ fontSize: '0.84rem', color: 'var(--text-primary)', lineHeight: '1.45' }}>
                {result.verdict === 'confirmed_exploit'
                  ? `The attacker successfully bypassed active protections using ${result.strategy_name || result.strategy}. Rule fired: ${result.rule_fired || 'policy violation'}.`
                  : result.verdict === 'blocked'
                  ? `The guard intercepted the attack attempt before any sensitive actions or exfiltrations could execute.`
                  : 'The agent processed the prompt safely within authorized operational boundaries.'}
              </p>
            </div>

            {/* Strategy & Mutation Diff Summary */}
            {result.diff_summary && (
              <div style={{ marginBottom: '1rem', padding: '0.75rem 1rem', backgroundColor: 'var(--bg-surface)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-light)' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.25rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  <Compass size={13} /> Strategy Adaptation & Variation Diff
                </div>
                <div style={{ fontSize: '0.84rem', color: 'var(--text-primary)', lineHeight: '1.45' }}>
                  {result.diff_summary}
                </div>
              </div>
            )}

            {/* Generated Prompt Preview */}
            {result.prompt && (
              <div style={{ marginBottom: '1rem', padding: '0.75rem 1rem', backgroundColor: 'var(--bg-surface)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-light)' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                  Executed Attack Prompt (Genuinely Generated)
                </div>
                <div className="mono" style={{ fontSize: '0.82rem', color: 'var(--text-primary)', whiteSpace: 'pre-wrap', wordBreak: 'break-word', backgroundColor: 'var(--bg-surface-subtle)', padding: '0.5rem 0.65rem', borderRadius: 'var(--radius-sm)' }}>
                  "{result.prompt}"
                </div>
              </div>
            )}

            {/* Feedback Observed */}
            {result.feedback && (
              <div style={{ marginBottom: '1rem', padding: '0.75rem 1rem', backgroundColor: 'var(--bg-surface)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-light)' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                  Guard Feedback Observed by Attacker
                </div>
                <div className="mono" style={{ fontSize: '0.82rem', color: 'var(--text-primary)' }}>
                  "{result.feedback.text}"
                </div>
              </div>
            )}

            {/* Technical Metadata (Progressive Disclosure) */}
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
                      <span style={{ color: 'var(--text-muted)' }}>Run ID: </span>
                      <code className="mono">{result.challenge_run_id}</code>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Parent Run: </span>
                      <code className="mono">{result.parent_run_id}</code>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Triggered Rule: </span>
                      <code className="mono">{result.rule_fired || 'None'}</code>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Provenance: </span>
                      <span className="badge badge-neutral">{result.variant_source || 'generated'}</span>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Generation Mode: </span>
                      <span className="badge badge-neutral">{result.generation_mode || 'offline_adaptive_template'}</span>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Model Client: </span>
                      <span>{result.is_model_generated ? 'Gemini Generative' : 'Deterministic Offline'}</span>
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
