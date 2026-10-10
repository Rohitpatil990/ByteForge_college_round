import React from 'react';
import { Run, Finding } from '../types';
import {
  Shield,
  AlertTriangle,
  Play,
  Terminal,
  Zap,
  BarChart2,
  FileText,
  Lock,
  ArrowRight,
  Target,
  CheckCircle2,
  AlertOctagon,
  Clock,
  Layers,
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
  const confirmedExploits = attackRuns.filter((r) => r.verdict === 'confirmed_exploit').length;
  const blockedAttempts = attackRuns.filter((r) => r.verdict === 'blocked').length;
  const legitimatePassCount = runs.filter((r) => r.verdict === 'legitimate_pass').length;

  const recordedFindingsCount = findings.filter((f) => f.source === 'recorded').length;
  const generatedFindingsCount = findings.filter((f) => f.source === 'generated').length;
  const seedFindingsCount = findings.filter((f) => f.source === 'seed').length;

  const hasRuns = runs.length > 0;

  // Determine current pipeline stage
  let activeStep = 1;
  if (assessment?.target_id) activeStep = 2;
  if (hasRuns) activeStep = 3;
  if (generatedFindingsCount > 0) activeStep = 4;
  if (assessment?.retest_results) activeStep = 5;

  return (
    <div>
      {/* -------------------------------------------------------------------
          1. Hero Session Summary Bar
      ------------------------------------------------------------------- */}
      <div
        className="panel"
        style={{
          background: 'linear-gradient(180deg, #161b24 0%, #12151c 100%)',
          borderColor: 'var(--border-medium)',
          marginBottom: '1rem',
          padding: '1.1rem 1.3rem',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.75rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.25rem' }}>
              <h2 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#fff', letterSpacing: '-0.01em' }}>
                {assessment?.name || 'Agent Security Benchmark'}
              </h2>
              {isOffline ? (
                <span className="chip chip-recorded">Offline Recorded Fixture</span>
              ) : (
                <span className="chip chip-blocked">Live Session</span>
              )}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              <span>
                Session ID: <code className="mono" style={{ color: '#cbd5e1' }}>{assessment?.id || 'default'}</code>
              </span>
              <span>•</span>
              <span>
                Target: <strong style={{ color: '#00e5ff' }}>{assessment?.target_name || assessment?.target_id || 'demo-company-assistant'}</strong>
              </span>
              <span>•</span>
              <span>
                Lifecycle: <span style={{ color: '#fff', textTransform: 'capitalize' }}>{assessment?.status || 'created'}</span>
              </span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button className="btn btn-secondary btn-sm" onClick={() => onNavigate('target')}>
              <Target size={13} /> Configure Target
            </button>
            <button className="btn btn-primary btn-sm" onClick={() => onNavigate('run')}>
              <Play size={13} /> Run Benchmark
            </button>
          </div>
        </div>
      </div>

      {/* -------------------------------------------------------------------
          2. Compact KPI Metrics Row
      ------------------------------------------------------------------- */}
      <div className="kpi-row">
        <div className="kpi-block" style={{ borderLeft: '3px solid #f43f5e' }}>
          <span className="kpi-block-label">Confirmed Exploits</span>
          <span className="kpi-block-val" style={{ color: '#fb7185' }}>
            {hasRuns ? confirmedExploits : 'Not run'}
          </span>
          <span className="kpi-block-sub">
            {hasRuns ? `${seedFindingsCount} seed, ${generatedFindingsCount} adaptive` : 'Awaiting test execution'}
          </span>
        </div>

        <div className="kpi-block" style={{ borderLeft: '3px solid #10b981' }}>
          <span className="kpi-block-label">Blocked Attempts</span>
          <span className="kpi-block-val" style={{ color: '#34d399' }}>
            {hasRuns ? blockedAttempts : 'Not run'}
          </span>
          <span className="kpi-block-sub">
            {hasRuns ? 'Guards enforced per policy.yaml' : 'Awaiting test execution'}
          </span>
        </div>

        <div className="kpi-block" style={{ borderLeft: '3px solid #00e5ff' }}>
          <span className="kpi-block-label">Total Runs Saved</span>
          <span className="kpi-block-val" style={{ color: '#00e5ff' }}>
            {runs.length}
          </span>
          <span className="kpi-block-sub">
            {attackRuns.length} attacks, {legitimatePassCount} legitimate controls
          </span>
        </div>

        <div className="kpi-block" style={{ borderLeft: '3px solid #f59e0b' }}>
          <span className="kpi-block-label">Security Findings</span>
          <span className="kpi-block-val" style={{ color: '#f59e0b' }}>
            {findings.length}
          </span>
          <span className="kpi-block-sub">
            {findings.length - recordedFindingsCount} live, {recordedFindingsCount} recorded fixture
          </span>
        </div>
      </div>

      {/* -------------------------------------------------------------------
          3. Prominent Assessment Workflow Pipeline
      ------------------------------------------------------------------- */}
      <div className="pipeline-stepper">
        <div
          className={`pipeline-step ${activeStep >= 1 ? 'active' : ''}`}
          onClick={() => onNavigate('target')}
          title="Step 1: Configure Target Agent YAML"
        >
          <div className="step-circle">1</div>
          <span className="step-label">Configure Target</span>
        </div>

        <span className="pipeline-arrow">→</span>

        <div
          className={`pipeline-step ${activeStep >= 2 ? 'active' : ''}`}
          onClick={() => onNavigate('run')}
          title="Step 2: Execute Seed Attack Benchmark"
        >
          <div className="step-circle">2</div>
          <span className="step-label">Execute Suite</span>
        </div>

        <span className="pipeline-arrow">→</span>

        <div
          className={`pipeline-step ${activeStep >= 3 ? 'active' : ''}`}
          onClick={() => onNavigate('trace')}
          title="Step 3: Investigate Step Traces & Findings"
        >
          <div className="step-circle">3</div>
          <span className="step-label">Investigate Traces</span>
        </div>

        <span className="pipeline-arrow">→</span>

        <div
          className={`pipeline-step ${activeStep >= 4 ? 'active' : ''}`}
          onClick={() => onNavigate('challenge')}
          title="Step 4: Adaptive Attacker Challenge Loop"
        >
          <div className="step-circle">4</div>
          <span className="step-label">Challenge Guards</span>
        </div>

        <span className="pipeline-arrow">→</span>

        <div
          className={`pipeline-step ${activeStep >= 5 ? 'active' : ''}`}
          onClick={() => onNavigate('retest')}
          title="Step 5: Comparative Retest Evaluation"
        >
          <div className="step-circle">5</div>
          <span className="step-label">Retest & Verify</span>
        </div>

        <span className="pipeline-arrow">→</span>

        <div
          className="pipeline-step"
          onClick={() => onNavigate('report')}
          title="Step 6: Audit Report & Evidence Export"
        >
          <div className="step-circle">6</div>
          <span className="step-label">Audit Report</span>
        </div>
      </div>

      {/* -------------------------------------------------------------------
          4. Two-Column Layout: Recent Activity vs Limitations
      ------------------------------------------------------------------- */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: '1.15rem' }}>
        {/* Left: Recent Saved Execution Runs Table */}
        <div className="panel" style={{ margin: 0 }}>
          <div className="panel-header">
            <div>
              <h3 className="panel-title">
                <Terminal size={15} /> Recent Logged Runs
              </h3>
              <p className="panel-subtitle">Real execution data with step counts and verdicts</p>
            </div>
            {hasRuns && (
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => onNavigate('trace')}
                style={{ fontSize: '0.72rem' }}
              >
                Inspect All <ArrowRight size={12} />
              </button>
            )}
          </div>

          {!hasRuns ? (
            <div style={{ padding: '2rem 1rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.82rem' }}>
              No runs logged in this session yet. Run the benchmark suite to generate execution traces.
            </div>
          ) : (
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Run ID</th>
                    <th>Objective / Name</th>
                    <th>Source</th>
                    <th>Verdict</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {runs.slice(0, 5).map((r) => (
                    <tr key={r.run_id}>
                      <td className="mono" style={{ fontSize: '0.75rem', fontWeight: 600 }}>
                        {r.run_id.slice(-14)}
                      </td>
                      <td style={{ fontSize: '0.78rem', color: '#fff' }}>{r.name}</td>
                      <td>
                        {r.variant_source === 'recorded' ? (
                          <span className="chip chip-recorded" style={{ fontSize: '0.62rem' }}>
                            Recorded
                          </span>
                        ) : r.variant_source === 'generated' ? (
                          <span className="chip chip-generated" style={{ fontSize: '0.62rem' }}>
                            Adaptive
                          </span>
                        ) : (
                          <span className="chip chip-seed" style={{ fontSize: '0.62rem' }}>
                            Seed
                          </span>
                        )}
                      </td>
                      <td>
                        {r.verdict === 'confirmed_exploit' ? (
                          <span className="chip chip-exploit" style={{ fontSize: '0.62rem' }}>
                            Exploit
                          </span>
                        ) : r.verdict === 'blocked' ? (
                          <span className="chip chip-blocked" style={{ fontSize: '0.62rem' }}>
                            Blocked
                          </span>
                        ) : (
                          <span className="chip chip-pass" style={{ fontSize: '0.62rem' }}>
                            Pass
                          </span>
                        )}
                      </td>
                      <td>
                        <button
                          className="btn btn-secondary btn-sm"
                          style={{ padding: '0.2rem 0.45rem', fontSize: '0.7rem' }}
                          onClick={() => onNavigate('trace')}
                        >
                          Trace
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right: Findings by Rule Breakdown & Restrained Limitations */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.15rem' }}>
          {/* Findings Distribution */}
          <div className="panel" style={{ margin: 0 }}>
            <div className="panel-header">
              <div>
                <h3 className="panel-title">
                  <AlertTriangle size={15} /> Analyzer Rules Fired
                </h3>
                <p className="panel-subtitle">Frozen v2 analyzer rules</p>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.78rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.4rem 0.6rem', background: 'var(--bg-app)', borderRadius: '4px' }}>
                <span className="mono" style={{ color: '#f43f5e' }}>canary_in_final_reply</span>
                <strong>{findings.filter((f) => f.rule_fired === 'canary_in_final_reply').length}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.4rem 0.6rem', background: 'var(--bg-app)', borderRadius: '4px' }}>
                <span className="mono" style={{ color: '#a855f7' }}>canary_in_executed_args</span>
                <strong>{findings.filter((f) => f.rule_fired === 'canary_in_executed_args').length}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.4rem 0.6rem', background: 'var(--bg-app)', borderRadius: '4px' }}>
                <span className="mono" style={{ color: '#38bdf8' }}>executed_outside_policy</span>
                <strong>{findings.filter((f) => f.rule_fired === 'executed_outside_policy').length}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.4rem 0.6rem', background: 'var(--bg-app)', borderRadius: '4px' }}>
                <span className="mono" style={{ color: '#f59e0b' }}>memory_write_untrusted</span>
                <strong>{findings.filter((f) => f.rule_fired === 'memory_write_untrusted').length}</strong>
              </div>
            </div>
          </div>

          {/* Compact Limitations Card */}
          <div className="panel" style={{ margin: 0 }}>
            <h4 style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
              Platform Boundary Disclosures
            </h4>
            <p style={{ fontSize: '0.74rem', color: 'var(--text-muted)', lineHeight: '1.45', marginBottom: '0.4rem' }}>
              • <strong>Canaries:</strong> Plain string matching only catches verbatim synthetic tokens, not encoded or translated secrets.
            </p>
            <p style={{ fontSize: '0.74rem', color: 'var(--text-muted)', lineHeight: '1.45', marginBottom: '0.4rem' }}>
              • <strong>Tool Policy vs Reply:</strong> Tool-call checks in D1/D2 do not prevent sensitive content from leaking in <code className="mono">final_reply</code>.
            </p>
            <p style={{ fontSize: '0.74rem', color: 'var(--text-muted)', lineHeight: '1.45' }}>
              • <strong>Target Scope:</strong> Bound to configured target (<code className="mono">demo-company-assistant</code>). Arbitrary unconfigured agent code is not supported.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
