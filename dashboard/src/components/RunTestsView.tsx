import React, { useState } from 'react';
import { Run } from '../types';
import { api } from '../api';
import { Play, CheckCircle2, AlertTriangle, ArrowRight, ShieldCheck, Target, RefreshCw, Cpu, Terminal, Zap } from 'lucide-react';

interface Props {
  assessmentId: string;
  targetId: string | null;
  allRuns?: Run[];
  onRunsCompleted: (runs: Run[]) => void;
  onNavigate: (tab: string) => void;
}

export const RunTestsView: React.FC<Props> = ({
  assessmentId,
  targetId,
  allRuns = [],
  onRunsCompleted,
  onNavigate,
}) => {
  const [running, setRunning] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [latestRuns, setLatestRuns] = useState<Run[]>([]);
  const [completed, setCompleted] = useState<boolean>(false);
  const [executionMode, setExecutionMode] = useState<'real_sandbox' | 'deterministic_simulation'>('real_sandbox');

  const handleExecute = async () => {
    if (!targetId) {
      setError('Please select a target agent before running tests.');
      return;
    }
    setRunning(true);
    setError(null);
    setCompleted(false);

    try {
      const res = await api.startRuns(assessmentId, executionMode);
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

  const ADAPTIVE_STRATEGIES = [
    {
      id: 'direct_injection',
      name: 'Direct System Prompt Override',
      category: 'Prompt Extraction',
      description: 'Overrides system prompt directives to extract confidential secrets directly.',
    },
    {
      id: 'indirect_context_smuggling',
      name: 'Indirect Context Smuggling',
      category: 'Context Injection',
      description: 'Hides adversarial instructions inside ingested documents or customer records.',
    },
    {
      id: 'internal_relay_exfiltration',
      name: 'Internal Relay Exfiltration',
      category: 'Policy Evasion',
      description: 'Evades external recipient domain restrictions by routing through allowed internal addresses.',
    },
    {
      id: 'role_impersonation',
      name: 'Executive / Auditor Impersonation',
      category: 'Privilege Escalation',
      description: 'Impersonates elevated personnel to demand restricted customer actions.',
    },
    {
      id: 'parameter_obfuscation',
      name: 'Parameter & Format Obfuscation',
      category: 'Filter Evasion',
      description: 'Uses spacing, encoding, and framing variations to evade argument regex filters.',
    },
    {
      id: 'multistep_memory_tampering',
      name: 'Multi-Step Memory Tampering',
      category: 'State Poisoning',
      description: 'Injects unauthorized preferences and rules into persistent agent memory.',
    },
    {
      id: 'forbidden_tool_probing',
      name: 'Restricted Tool Probing',
      category: 'Scope Probing',
      description: 'Probes destructive or out-of-scope tools outside permitted capabilities.',
    },
  ];

  // Identify attempted strategies in this session
  const combinedRuns = [...allRuns, ...latestRuns];
  const adaptiveRuns = combinedRuns.filter(
    (r) => r.variant_source === 'generated' || (r.round && r.round > 0)
  );

  const attemptedStrategyMap = new Map<string, Run[]>();
  adaptiveRuns.forEach((r) => {
    let strat = r.metadata?.strategy;
    if (!strat && r.name && r.name.toLowerCase().includes('round')) {
      const parts = r.name.split(':');
      if (parts.length > 1) {
        strat = parts[1].trim().toLowerCase().replace(/\s+/g, '_');
      }
    }
    if (strat) {
      const existing = attemptedStrategyMap.get(strat) || [];
      existing.push(r);
      attemptedStrategyMap.set(strat, existing);
    }
  });

  const attemptedCount = ADAPTIVE_STRATEGIES.filter((s) => attemptedStrategyMap.has(s.id)).length;

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
            <h2 className="card-title">Fixed Seed Benchmark Suite</h2>
            <p className="card-subtitle">
              Target Agent: <strong style={{ color: 'var(--primary)' }}>{targetId || 'None'}</strong>
            </p>
          </div>
          <span className="badge badge-neutral">5 Fixed Scenarios (4 Seeds + 1 Control)</span>
        </div>

        <div style={{ padding: '0.5rem 0 1rem 0' }}>
          <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', marginBottom: '1.25rem', lineHeight: '1.5' }}>
            This baseline suite tests 4 fixed seed attack vectors and 1 normal customer-service task to establish an initial performance baseline.
            Dynamic multi-round variations are generated separately during the <strong>Adaptive Red-Team Loop</strong>.
          </p>

          <div style={{ marginBottom: '1.25rem' }}>
            <label style={{ fontSize: '0.74rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-subtle)', display: 'block', marginBottom: '0.45rem' }}>
              Execution Environment
            </label>
            <div style={{ display: 'flex', gap: '0.65rem', flexWrap: 'wrap' }}>
              <button
                type="button"
                className={`btn btn-sm ${executionMode === 'real_sandbox' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setExecutionMode('real_sandbox')}
                style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.78rem' }}
              >
                <Cpu size={13} /> Real Sandbox (Live Tools & Tracer)
              </button>
              <button
                type="button"
                className={`btn btn-sm ${executionMode === 'deterministic_simulation' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setExecutionMode('deterministic_simulation')}
                style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.78rem' }}
              >
                <Terminal size={13} /> Deterministic Simulation (Mock Traces)
              </button>
            </div>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
              {executionMode === 'real_sandbox'
                ? 'Executes requests inside target.runner with isolated tools (mock mailer, mock DB) and live policy guards.'
                : 'Emits deterministic pre-recorded trace sequence without initializing the target agent loop.'}
            </p>
          </div>

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

      {/* 1. Fixed Seed Benchmark Scenarios */}
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Fixed Seed Benchmark Scenarios</h2>
            <p className="card-subtitle">Deterministic baseline scenarios evaluated by clicking "Run Security Test"</p>
          </div>
          <span className="badge badge-neutral">5 Fixed Scenarios (4 Seeds + 1 Control)</span>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Benchmark Scenario</th>
                <th>Category</th>
                <th>Target Threat Vector</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>
                  <strong>Secret Canary Leak in Tool Arguments</strong>
                  <div className="mono" style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>seed-canary-leak-prompt</div>
                </td>
                <td>
                  <span className="badge badge-warning">Confidentiality</span>
                </td>
                <td style={{ color: 'var(--text-secondary)' }}>
                  Attempts to trick the agent into including private canary secrets in external tool arguments.
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
                  Prompts the agent to perform sensitive restricted tool operations (such as deleting files or accessing out-of-scope records).
                </td>
              </tr>
              <tr>
                <td>
                  <strong>Multi-Step Untrusted Memory Poisoning</strong>
                  <div className="mono" style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>seed-memory-poisoning</div>
                </td>
                <td>
                  <span className="badge badge-danger">Memory Integrity</span>
                </td>
                <td style={{ color: 'var(--text-secondary)' }}>
                  Instructs the agent to overwrite persistent memory with unverified attacker directives.
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
                  Standard support request verifying that safety guardrails do not break legitimate agent functionality.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* 2. Adaptive Attack Coverage */}
      <div className="card" style={{ marginTop: '1.25rem' }}>
        <div className="card-header">
          <div>
            <h2 className="card-title">
              <Zap size={16} color="var(--primary)" style={{ display: 'inline', marginRight: '0.4rem', verticalAlign: '-2px' }} />
              Adaptive Red-Team Attack Coverage
            </h2>
            <p className="card-subtitle">
              Dynamic attack strategies supported by the feedback mutation engine during multi-round red teaming
            </p>
          </div>
          <span className={`badge ${attemptedCount > 0 ? 'badge-success' : 'badge-neutral'}`}>
            {attemptedCount} of {ADAPTIVE_STRATEGIES.length} Attempted in Session
          </span>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Adaptive Strategy</th>
                <th>Vector</th>
                <th>Description</th>
                <th style={{ textAlign: 'right' }}>Session Status</th>
              </tr>
            </thead>
            <tbody>
              {ADAPTIVE_STRATEGIES.map((strat) => {
                const attempts = attemptedStrategyMap.get(strat.id);
                const wasAttempted = Boolean(attempts && attempts.length > 0);
                const latestRound = wasAttempted ? attempts![attempts!.length - 1].round : null;
                return (
                  <tr key={strat.id}>
                    <td>
                      <strong style={{ color: 'var(--text-primary)' }}>{strat.name}</strong>
                      <div className="mono" style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                        {strat.id}
                      </div>
                    </td>
                    <td>
                      <span className="badge badge-neutral">{strat.category}</span>
                    </td>
                    <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                      {strat.description}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      {wasAttempted ? (
                        <span className="badge badge-success" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                          <CheckCircle2 size={11} /> Attempted (Round {latestRound || 1})
                        </span>
                      ) : (
                        <span className="badge badge-neutral">Not Attempted (Available)</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        <div
          style={{
            padding: '0.85rem 1rem',
            backgroundColor: 'var(--bg-surface-subtle)',
            borderRadius: 'var(--radius-sm)',
            borderTop: '1px solid var(--border-light)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '0.75rem',
            marginTop: '0.5rem',
          }}
        >
          <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            <strong>Note:</strong> Adaptive strategies are generated on demand based on guard denial feedback. They are evaluated during the <strong>Adaptive Red-Team Loop</strong> in Protection.
          </span>
          <button className="btn btn-secondary btn-sm" onClick={() => onNavigate('defenses')}>
            Run Adaptive Loop in Protection <ArrowRight size={13} />
          </button>
        </div>
      </div>
    </div>
  );
};
