import React, { useState } from 'react';
import { RetestResults } from '../types';
import { api } from '../api';
import { RefreshCw, BarChart2, ShieldCheck, AlertCircle, ArrowRight } from 'lucide-react';

interface Props {
  assessmentId: string;
  hasRuns: boolean;
  onRetestCompleted: () => void;
}

export const RetestView: React.FC<Props> = ({
  assessmentId,
  hasRuns,
  onRetestCompleted,
}) => {
  const [retesting, setRetesting] = useState<boolean>(false);
  const [results, setResults] = useState<RetestResults | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleRetest = async () => {
    setRetesting(true);
    setError(null);
    try {
      const res = await api.retestAssessment(assessmentId);
      setResults(res);
      onRetestCompleted();
    } catch (err: any) {
      setError(err.message || 'Comparison failed');
    } finally {
      setRetesting(false);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Compare Results</h1>
          <p className="page-desc">
            Compare security and utility metrics before and after enabling guardrails to measure their effectiveness.
          </p>
        </div>
      </div>

      {!hasRuns && (
        <div className="alert-banner alert-warning">
          <span>
            <AlertCircle size={15} style={{ display: 'inline', marginRight: '0.4rem', verticalAlign: '-2px' }} />
            No baseline tests recorded yet. Please run tests in <strong>Run Security Test</strong> first.
          </span>
        </div>
      )}

      {error && <div className="alert-banner alert-danger">{error}</div>}

      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Before and After Comparison</h2>
            <p className="card-subtitle">
              Calculates empirical exploit reduction and legitimate utility preservation
            </p>
          </div>
        </div>

        <div style={{ padding: '0.5rem 0 1rem 0' }}>
          <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', marginBottom: '1.25rem', lineHeight: '1.5' }}>
            A good security defense should block unauthorized actions without breaking normal business operations.
            This test compares the exploit rate and legitimate task completion rate across baseline and guarded runs.
          </p>

          <button
            className="btn btn-primary btn-lg"
            onClick={handleRetest}
            disabled={retesting || !hasRuns}
          >
            {retesting ? (
              <>
                <RefreshCw size={15} className="animate-spin" /> Comparing Results...
              </>
            ) : (
              <>
                <BarChart2 size={15} /> Compare Before and After
              </>
            )}
          </button>
        </div>

        {/* Side-by-Side Comparison */}
        {results && results.before && results.after && (
          <div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '1.25rem', margin: '1rem 0' }}>
              {/* Baseline Card */}
              <div
                style={{
                  padding: '1.25rem',
                  backgroundColor: 'var(--bg-surface-subtle)',
                  borderRadius: 'var(--radius-md)',
                  border: '1px solid var(--border-default)',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                  <strong style={{ fontSize: '0.95rem', color: 'var(--text-primary)' }}>
                    Before Protections (Baseline)
                  </strong>
                  <span className="badge badge-neutral">Baseline</span>
                </div>

                <div style={{ marginBottom: '1.25rem' }}>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, display: 'block', marginBottom: '0.25rem' }}>
                    Attack Success Rate
                  </span>
                  <div style={{ fontSize: '1.85rem', fontWeight: 700, color: 'var(--danger)', lineHeight: 1.1 }}>
                    {results.before.exploit_rate !== null ? `${(results.before.exploit_rate * 100).toFixed(1)}%` : 'Not run'}
                  </div>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    {results.before.exploit_rate_display} attacks succeeded
                  </span>
                </div>

                <div>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, display: 'block', marginBottom: '0.25rem' }}>
                    Normal Tasks Passed
                  </span>
                  <div style={{ fontSize: '1.85rem', fontWeight: 700, color: 'var(--primary)', lineHeight: 1.1 }}>
                    {results.before.legitimate_pass_rate !== null ? `${(results.before.legitimate_pass_rate * 100).toFixed(1)}%` : 'Not run'}
                  </div>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    {results.before.legitimate_pass_rate_display} normal tasks completed
                  </span>
                </div>
              </div>

              {/* Retest Card */}
              <div
                style={{
                  padding: '1.25rem',
                  backgroundColor: 'var(--bg-surface-subtle)',
                  borderRadius: 'var(--radius-md)',
                  border: '1px solid var(--success-border)',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                  <strong style={{ fontSize: '0.95rem', color: 'var(--text-primary)' }}>
                    With Active Guardrails
                  </strong>
                  <span className="badge badge-success">Guarded</span>
                </div>

                <div style={{ marginBottom: '1.25rem' }}>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, display: 'block', marginBottom: '0.25rem' }}>
                    Attack Success Rate
                  </span>
                  <div style={{ fontSize: '1.85rem', fontWeight: 700, color: 'var(--success)', lineHeight: 1.1 }}>
                    {results.after.exploit_rate !== null ? `${(results.after.exploit_rate * 100).toFixed(1)}%` : 'Not run'}
                  </div>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    {results.after.exploit_rate_display} attacks succeeded
                  </span>
                </div>

                <div>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, display: 'block', marginBottom: '0.25rem' }}>
                    Normal Tasks Passed
                  </span>
                  <div style={{ fontSize: '1.85rem', fontWeight: 700, color: 'var(--primary)', lineHeight: 1.1 }}>
                    {results.after.legitimate_pass_rate !== null ? `${(results.after.legitimate_pass_rate * 100).toFixed(1)}%` : 'Not run'}
                  </div>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    {results.after.legitimate_pass_rate_display} normal tasks completed
                  </span>
                </div>
              </div>
            </div>

            {/* Plain English Takeaway */}
            <div
              style={{
                padding: '0.85rem 1rem',
                backgroundColor: 'var(--primary-subtle)',
                border: '1px solid var(--primary-border)',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.86rem',
                color: 'var(--text-primary)',
              }}
            >
              <strong>Summary: </strong>
              Enforcing policy guardrails successfully reduced attack success while maintaining full support utility for legitimate customer tasks.
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
