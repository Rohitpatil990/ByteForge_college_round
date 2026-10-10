import React from 'react';
import { Run, Finding } from '../types';
import {
  Play,
  ArrowRight,
  ShieldAlert,
  ShieldCheck,
  FileQuestion,
  Target,
  ExternalLink,
} from 'lucide-react';

interface Props {
  assessment: any;
  runs: Run[];
  findings: Finding[];
  isOffline: boolean;
  onNavigate: (tab: string) => void;
}

export const OverviewView: React.FC<Props> = ({
  assessment,
  runs,
  findings,
  isOffline,
  onNavigate,
}) => {
  const attackRuns = runs.filter((r) => r.kind === 'attack');
  const attacksSucceeded = attackRuns.filter((r) => r.verdict === 'confirmed_exploit').length;
  const attacksBlocked = attackRuns.filter((r) => r.verdict === 'blocked').length;
  const totalTests = runs.length;
  const problemsFound = findings.length;

  const hasRuns = runs.length > 0;

  // Plain-English mapping for test verdict
  const getResultBadge = (verdict: string) => {
    switch (verdict) {
      case 'confirmed_exploit':
        return <span className="chip chip-exploit">Attack succeeded</span>;
      case 'blocked':
        return <span className="chip chip-blocked">Attack blocked</span>;
      case 'legitimate_pass':
        return <span className="chip chip-pass">Passed</span>;
      case 'inconclusive':
        return <span className="chip chip-inconclusive">Needs review</span>;
      default:
        return <span className="chip chip-seed">{verdict}</span>;
    }
  };

  // Plain-English severity badge
  const getSeverityBadge = (severity?: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return <span className="badge badge-danger">Critical</span>;
      case 'high':
        return <span className="badge badge-danger">High</span>;
      case 'medium':
        return <span className="badge badge-warning">Medium</span>;
      case 'low':
        return <span className="badge badge-neutral">Low</span>;
      default:
        return <span className="badge badge-neutral">Notice</span>;
    }
  };

  return (
    <div>
      {/* -------------------------------------------------------------------
          1. Clean Header with Single Primary Action
      ------------------------------------------------------------------- */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Overview</h1>
          <p className="page-desc">
            Test your AI agent, find problems, and check whether your protections work.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <button className="btn btn-primary" onClick={() => onNavigate('run')}>
            <Play size={15} /> Run Security Test
          </button>
        </div>
      </div>

      {/* Target status bar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0.65rem 1rem',
          backgroundColor: 'var(--bg-surface)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-md)',
          marginBottom: '1.25rem',
          fontSize: '0.85rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-secondary)' }}>
          <Target size={16} color="var(--primary)" />
          <span>Testing Agent:</span>
          <strong style={{ color: 'var(--text-primary)' }}>
            {assessment?.target_name || assessment?.target_id || 'demo-company-assistant'}
          </strong>
          {isOffline && (
            <span className="badge badge-warning" style={{ marginLeft: '0.5rem' }}>
              Offline Fixture
            </span>
          )}
        </div>

        <button
          className="btn btn-secondary btn-sm"
          onClick={() => onNavigate('target')}
          style={{ fontSize: '0.78rem' }}
        >
          Change Target
        </button>
      </div>

      {/* -------------------------------------------------------------------
          2. Four Simple Summary Cards
      ------------------------------------------------------------------- */}
      <div className="summary-grid">
        {/* Card 1: Attacks That Succeeded */}
        <div className={`summary-card ${attacksSucceeded > 0 ? 'danger' : ''}`}>
          <div className="summary-card-header">
            <span className="summary-label">Attacks That Succeeded</span>
            <ShieldAlert size={18} color={attacksSucceeded > 0 ? 'var(--danger)' : 'var(--text-muted)'} />
          </div>
          <div className="summary-number">
            {hasRuns ? attacksSucceeded : '—'}
          </div>
          <div className="summary-desc">
            {hasRuns
              ? attacksSucceeded === 0
                ? 'No attacks succeeded'
                : 'Harmful prompts that bypassed security'
              : 'Run a test to check'}
          </div>
        </div>

        {/* Card 2: Attacks Blocked */}
        <div className="summary-card success">
          <div className="summary-card-header">
            <span className="summary-label">Attacks Blocked</span>
            <ShieldCheck size={18} color="var(--success)" />
          </div>
          <div className="summary-number">
            {hasRuns ? attacksBlocked : '—'}
          </div>
          <div className="summary-desc">
            {hasRuns ? 'Harmful actions stopped by guards' : 'Run a test to check'}
          </div>
        </div>

        {/* Card 3: Total Tests */}
        <div className="summary-card primary">
          <div className="summary-card-header">
            <span className="summary-label">Total Tests</span>
            <Play size={18} color="var(--primary)" />
          </div>
          <div className="summary-number">
            {totalTests}
          </div>
          <div className="summary-desc">
            {hasRuns
              ? `${attackRuns.length} attack scenarios, ${totalTests - attackRuns.length} legitimate`
              : 'No tests run yet'}
          </div>
        </div>

        {/* Card 4: Problems Found */}
        <div className="summary-card warning">
          <div className="summary-card-header">
            <span className="summary-label">Problems Found</span>
            <FileQuestion size={18} color="var(--warning)" />
          </div>
          <div className="summary-number">
            {problemsFound}
          </div>
          <div className="summary-desc">
            {problemsFound > 0 ? 'Security issues detected' : 'No issues found'}
          </div>
        </div>
      </div>

      {/* -------------------------------------------------------------------
          3. Empty State OR Activity Tables
      ------------------------------------------------------------------- */}
      {!hasRuns ? (
        <div className="empty-state">
          <div className="empty-state-icon">
            <Play size={20} />
          </div>
          <div className="empty-state-title">No security tests executed yet</div>
          <div className="empty-state-desc">
            Start by running the standard attack test suite to discover potential security risks and evaluate your agent's protections.
          </div>
          <button className="btn btn-primary" onClick={() => onNavigate('run')}>
            <Play size={15} /> Run Security Test
          </button>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: '1.25rem' }}>
          {/* Left: Recent Tests Table */}
          <div className="card" style={{ margin: 0 }}>
            <div className="card-header">
              <div>
                <h2 className="card-title">Recent Tests</h2>
                <p className="card-subtitle">Tests run in this assessment session</p>
              </div>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => onNavigate('trace')}
              >
                View all tests <ArrowRight size={13} />
              </button>
            </div>

            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Test Name</th>
                    <th>Result</th>
                    <th style={{ textAlign: 'right' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {runs.slice(0, 5).map((r) => (
                    <tr key={r.run_id}>
                      <td>
                        <div style={{ fontWeight: 500, color: 'var(--text-primary)' }}>
                          {r.name}
                        </div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          {r.kind === 'attack' ? 'Adversarial Test' : 'Normal Customer Query'}
                        </div>
                      </td>
                      <td>{getResultBadge(r.verdict)}</td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => onNavigate('trace')}
                        >
                          View details
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Right: What Needs Attention? */}
          <div className="card" style={{ margin: 0 }}>
            <div className="card-header">
              <div>
                <h2 className="card-title">What Needs Attention?</h2>
                <p className="card-subtitle">Top problems found during testing</p>
              </div>
              {findings.length > 0 && (
                <button
                  className="btn btn-secondary btn-sm"
                  onClick={() => onNavigate('findings')}
                >
                  All problems <ArrowRight size={13} />
                </button>
              )}
            </div>

            {findings.length === 0 ? (
              <div style={{ padding: '2rem 1rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                No active security problems detected in this session.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {findings.slice(0, 3).map((f) => (
                  <div
                    key={f.finding_id}
                    style={{
                      padding: '0.85rem',
                      borderRadius: 'var(--radius-md)',
                      backgroundColor: 'var(--bg-surface-subtle)',
                      border: '1px solid var(--border-default)',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                      <strong style={{ fontSize: '0.85rem', color: 'var(--text-primary)' }}>
                        {f.rule_fired === 'canary_in_final_reply'
                          ? 'Secret Leaked in Response'
                          : f.rule_fired === 'canary_in_executed_args'
                          ? 'Secret Leaked to External Tool'
                          : f.rule_fired === 'executed_outside_policy'
                          ? 'Policy Boundary Exceeded'
                          : f.rule_fired === 'memory_write_untrusted'
                          ? 'Unauthorized Memory Change'
                          : f.rule_fired}
                      </strong>
                      {getSeverityBadge(f.severity)}
                    </div>
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.5rem', lineHeight: '1.4' }}>
                      {f.description}
                    </p>
                    <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                      <button
                        className="btn btn-secondary btn-sm"
                        onClick={() => onNavigate('findings')}
                        style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem' }}
                      >
                        Inspect finding <ArrowRight size={12} />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
