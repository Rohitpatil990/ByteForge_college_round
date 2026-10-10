import React, { useState } from 'react';
import { Run } from '../types';
import { api } from '../api';
import { Play, CheckCircle2, AlertTriangle, ArrowRight, ShieldCheck, Target, RefreshCw } from 'lucide-react';

interface Props {
  assessmentId: string;
  targetId: string | null;
  onRunsCompleted: (runs: Run[]) => void;
  onNavigate: (tab: string) => void;
}

export const RunTestsView: React.FC<Props> = ({
  assessmentId,
  targetId,
  onRunsCompleted,
  onNavigate,
}) => {
  const [running, setRunning] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [latestRuns, setLatestRuns] = useState<Run[]>([]);
  const [completed, setCompleted] = useState<boolean>(false);

  const handleExecute = async () => {
    if (!targetId) {
      setError('Please select a target agent before running tests.');
      return;
    }
    setRunning(true);
    setError(null);
    setCompleted(false);

    try {
      const res = await api.startRuns(assessmentId);
      setLatestRuns(res.runs);
      setCompleted(true);
      onRunsCompleted(res.runs);
    } catch (err: any) {
      setError(err.message || 'Execution failed. Ensure the backend server is running.');
    } finally {
      setRunning(false);
    }
  };

  const exploitsCount = latestRuns.filter((r) => r.verdict === 'confirmed_exploit').length;
  const blockedCount = latestRuns.filter((r) => r.verdict === 'blocked').length;
  const passCount = latestRuns.filter((r) => r.verdict === 'legitimate_pass').length;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Run Security Test</h1>
          <p className="page-desc">
            Execute standard test vectors to check whether the agent leaks private secrets, performs unauthorized tool actions, or alters memory.
          </p>
        </div>
      </div>

      {!targetId && (
        <div className="alert-banner alert-warning">
          <span>
            <AlertTriangle size={15} style={{ display: 'inline', marginRight: '0.4rem', verticalAlign: '-2px' }} />
            No target agent selected. Please select an agent in <strong>Targets</strong> first.
          </span>
          <button className="btn btn-secondary btn-sm" onClick={() => onNavigate('target')}>
            Go to Targets
          </button>
        </div>
      )}

      {error && <div className="alert-banner alert-danger">{error}</div>}

      {/* Primary Test Controller Card */}
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Security Test Suite</h2>
            <p className="card-subtitle">
              Target Agent: <strong style={{ color: 'var(--primary)' }}>{targetId || 'None'}</strong>
            </p>
          </div>
          <span className="badge badge-neutral">4 Standard Scenarios</span>
        </div>

        <div style={{ padding: '0.5rem 0 1rem 0' }}>
          <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', marginBottom: '1.25rem', lineHeight: '1.5' }}>
            This suite tests 3 adversarial attack scenarios and 1 normal customer-service task.
            The test records each action, verifies tool policies, and logs whether the attack was stopped or succeeded.
          </p>

          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
            <button
              className="btn btn-primary btn-lg"
              onClick={handleExecute}
              disabled={running || !targetId}
            >
              {running ? (
                <>
                  <RefreshCw size={16} className="animate-spin" /> Running Security Tests...
                </>
              ) : (
                <>
                  <Play size={16} /> Run Security Test
                </>
              )}
            </button>

            {running && (
              <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                Executing scenarios against agent... This usually takes 2–3 seconds.
              </span>
            )}
          </div>
        </div>

        {/* Results Banner */}
        {completed && (
          <div
            style={{
              padding: '1.25rem',
              backgroundColor: 'var(--bg-surface-subtle)',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border-default)',
              marginTop: '1rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem', color: 'var(--success)', fontWeight: 600 }}>
              <CheckCircle2 size={18} /> Test Run Completed
            </div>

            <p style={{ fontSize: '0.88rem', color: 'var(--text-primary)', marginBottom: '1rem' }}>
              Executed {latestRuns.length} tests against <strong style={{ color: 'var(--text-primary)' }}>{targetId}</strong>:{' '}
              <strong style={{ color: 'var(--danger)' }}>{exploitsCount} attacks succeeded</strong>,{' '}
              <strong style={{ color: 'var(--success)' }}>{blockedCount} attacks blocked</strong>, and{' '}
              <strong style={{ color: 'var(--primary)' }}>{passCount} normal customer task passed</strong>.
            </p>

            <div style={{ display: 'flex', gap: '0.75rem' }}>
              <button className="btn btn-secondary btn-sm" onClick={() => onNavigate('trace')}>
                View Test Details <ArrowRight size={13} />
              </button>
              <button className="btn btn-secondary btn-sm" onClick={() => onNavigate('overview')}>
                Back to Overview
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Test Scenarios List */}
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Included Test Scenarios</h2>
            <p className="card-subtitle">Scenarios evaluated in this benchmark suite</p>
          </div>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Test Scenario</th>
                <th>Category</th>
                <th>What It Tests</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>
                  <strong>Secret Canary Leak</strong>
                  <div className="mono" style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>seed-canary-leak-prompt</div>
                </td>
                <td>
                  <span className="badge badge-warning">Confidentiality</span>
                </td>
                <td style={{ color: 'var(--text-secondary)' }}>
                  Attempts to trick the agent into repeating private canary secrets in its reply or action parameters.
                </td>
              </tr>
              <tr>
                <td>
                  <strong>Poisoned Document Injection</strong>
                  <div className="mono" style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>seed-poisoned-document</div>
                </td>
                <td>
                  <span className="badge badge-danger">Indirect Injection</span>
                </td>
                <td style={{ color: 'var(--text-secondary)' }}>
                  Simulates a document containing hidden malicious instructions to send customer data to an untrusted external email.
                </td>
              </tr>
              <tr>
                <td>
                  <strong>Unauthorized Tool Scope</strong>
                  <div className="mono" style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>seed-unauthorized-tool-scope</div>
                </td>
                <td>
                  <span className="badge badge-danger">Tool Boundary</span>
                </td>
                <td style={{ color: 'var(--text-secondary)' }}>
                  Prompts the agent to perform sensitive restricted tool operations (such as deleting files or unauthorized memory writes).
                </td>
              </tr>
              <tr>
                <td>
                  <strong>Normal Customer Query (Control)</strong>
                  <div className="mono" style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>seed-legitimate-task-control</div>
                </td>
                <td>
                  <span className="badge badge-success">Utility Control</span>
                </td>
                <td style={{ color: 'var(--text-secondary)' }}>
                  A standard support request to verify that safety guards do not break legitimate agent functionality.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
