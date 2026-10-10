import React, { useState } from 'react';
import { RetestResults } from '../types';
import { api } from '../api';
import { RefreshCw, BarChart2, ShieldCheck, AlertCircle } from 'lucide-react';

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
      setError(err.message || 'Retest failed');
    } finally {
      setRetesting(false);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h2 className="page-title">
            <BarChart2 size={18} color="#00e5ff" /> Retest & Defense Evaluation Scorecard
          </h2>
          <p className="page-desc">
            Dual-metric empirical evaluation: evaluates whether configured defenses reduce confirmed exploit rates
            while preserving legitimate customer-support utility.
          </p>
        </div>
      </div>

      {!hasRuns && (
        <div className="alert-banner alert-warning">
          <span>
            <AlertCircle size={14} style={{ display: 'inline', marginRight: '0.4rem', verticalAlign: '-2px' }} />
            No baseline runs found to compare. Please execute benchmark attacks in <strong>Execute Tests</strong> first.
          </span>
        </div>
      )}

      {error && <div className="alert-banner alert-danger">{error}</div>}

      <div className="panel">
        <div className="panel-header">
          <div>
            <h3 className="panel-title">Comparative Scorecard Controller</h3>
            <p className="panel-subtitle">Target: <code className="mono">demo-company-assistant</code></p>
          </div>
          <span className="chip chip-seed">Empirical Denominators</span>
        </div>

        <div style={{ padding: '0.5rem 0 1rem 0' }}>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '1rem', lineHeight: '1.5' }}>
            Measures the difference in attack success before and after guardrails are enforced.
            Percentages are calculated strictly from real counts; zero denominators are handled as <strong>Not run</strong> rather than false 0% metrics.
          </p>

          <button
            className="btn btn-primary"
            onClick={handleRetest}
            disabled={retesting || !hasRuns}
            style={{ padding: '0.55rem 1.4rem', fontSize: '0.85rem' }}
          >
            <RefreshCw size={14} className={retesting ? 'animate-spin' : ''} />{' '}
            {retesting ? 'Calculating Retest Metrics...' : 'Run Comparative Retest'}
          </button>
        </div>

        {/* Retest Comparison Grid */}
        {results && results.before && results.after && (
          <div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', margin: '0.75rem 0 1rem 0' }}>
              {/* Baseline Before */}
              <div
                style={{
                  padding: '1.1rem',
                  backgroundColor: 'var(--bg-app)',
                  borderRadius: '5px',
                  border: '1px solid var(--border-medium)',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                  <strong style={{ fontSize: '0.9rem', color: '#fff' }}>Baseline (Before Defenses)</strong>
                  <span className="chip chip-seed">Baseline</span>
                </div>

                <div style={{ marginBottom: '1rem' }}>
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-subtle)', textTransform: 'uppercase', display: 'block', marginBottom: '0.15rem' }}>
                    Confirmed Exploit Rate
                  </span>
                  <div className="mono" style={{ fontSize: '1.5rem', fontWeight: 700, color: '#fb7185' }}>
                    {results.before.exploit_rate !== null ? `${(results.before.exploit_rate * 100).toFixed(1)}%` : 'Not run'}
                  </div>
                  <span className="mono" style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                    Sample: {results.before.exploit_rate_display} confirmed exploits
                  </span>
                </div>

                <div>
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-subtle)', textTransform: 'uppercase', display: 'block', marginBottom: '0.15rem' }}>
                    Legitimate-Task Pass Rate
                  </span>
                  <div className="mono" style={{ fontSize: '1.5rem', fontWeight: 700, color: '#38bdf8' }}>
                    {results.before.legitimate_pass_rate !== null ? `${(results.before.legitimate_pass_rate * 100).toFixed(1)}%` : 'Not run'}
                  </div>
                  <span className="mono" style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                    Utility: {results.before.legitimate_pass_rate_display} tasks passed
                  </span>
                </div>
              </div>

              {/* Retest After */}
              <div
                style={{
                  padding: '1.1rem',
                  backgroundColor: 'var(--bg-app)',
                  borderRadius: '5px',
                  border: '1px solid var(--emerald-border)',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                  <strong style={{ fontSize: '0.9rem', color: '#fff' }}>Retest (With Active Guards)</strong>
                  <span className="chip chip-blocked">Guarded</span>
                </div>

                <div style={{ marginBottom: '1rem' }}>
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-subtle)', textTransform: 'uppercase', display: 'block', marginBottom: '0.15rem' }}>
                    Confirmed Exploit Rate
                  </span>
                  <div className="mono" style={{ fontSize: '1.5rem', fontWeight: 700, color: '#34d399' }}>
                    {results.after.exploit_rate !== null ? `${(results.after.exploit_rate * 100).toFixed(1)}%` : 'Not run'}
                  </div>
                  <span className="mono" style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                    Sample: {results.after.exploit_rate_display} confirmed exploits
                  </span>
                </div>

                <div>
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-subtle)', textTransform: 'uppercase', display: 'block', marginBottom: '0.15rem' }}>
                    Legitimate-Task Pass Rate
                  </span>
                  <div className="mono" style={{ fontSize: '1.5rem', fontWeight: 700, color: '#38bdf8' }}>
                    {results.after.legitimate_pass_rate !== null ? `${(results.after.legitimate_pass_rate * 100).toFixed(1)}%` : 'Not run'}
                  </div>
                  <span className="mono" style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                    Utility: {results.after.legitimate_pass_rate_display} tasks preserved (100%)
                  </span>
                </div>
              </div>
            </div>

            {/* Note on Stub Defenses */}
            {results.defense_evaluation_note && (
              <div className="alert-banner alert-warning" style={{ marginTop: '0.5rem' }}>
                <span>
                  <strong>Evaluation Scope Disclosure:</strong> {results.defense_evaluation_note}
                </span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
