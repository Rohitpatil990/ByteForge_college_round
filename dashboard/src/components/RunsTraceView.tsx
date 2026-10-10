import React, { useState } from 'react';
import { Run, TraceStep } from '../types';
import { User, Cpu, Wrench, CheckCircle, MessageSquare, AlertTriangle, ShieldCheck, ShieldAlert, Terminal } from 'lucide-react';

interface Props {
  runs: Run[];
}

export const RunsTraceView: React.FC<Props> = ({ runs }) => {
  const [selectedRunId, setSelectedRunId] = useState<string | null>(
    runs.length > 0 ? runs[0].run_id : null
  );

  const activeRun = runs.find((r) => r.run_id === selectedRunId) || runs[0];

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

  const getSourceBadge = (source: string) => {
    switch (source) {
      case 'recorded':
        return <span className="badge badge-warning">Recorded Fixture</span>;
      case 'generated':
        return <span className="badge badge-neutral">Adaptive Variation</span>;
      default:
        return <span className="badge badge-neutral">Standard Test</span>;
    }
  };

  const getExecutionModeBadge = (mode?: string) => {
    if (mode === 'real_sandbox') {
      return (
        <span
          className="badge badge-success"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.35rem',
            fontWeight: 600,
          }}
        >
          <Cpu size={12} /> Real Sandbox
        </span>
      );
    }
    return (
      <span
        className="badge badge-neutral"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.35rem',
          fontWeight: 600,
        }}
      >
        <Terminal size={12} /> Deterministic Sim
      </span>
    );
  };

  const getStepIcon = (type: string) => {
    switch (type) {
      case 'user_input':
        return <User size={15} color="var(--primary)" />;
      case 'agent_thought':
        return <Cpu size={15} color="#7C3AED" />;
      case 'tool_call':
        return <Wrench size={15} color="var(--warning)" />;
      case 'tool_result':
        return <CheckCircle size={15} color="var(--success)" />;
      case 'final_reply':
        return <MessageSquare size={15} color="#DB2777" />;
      default:
        return <User size={15} color="var(--text-muted)" />;
    }
  };

  const getStepLabel = (type: string) => {
    switch (type) {
      case 'user_input':
        return 'User Message';
      case 'agent_thought':
        return 'Agent Reasoning';
      case 'tool_call':
        return 'Tool Invoked';
      case 'tool_result':
        return 'Tool Result';
      case 'final_reply':
        return 'Final Response Delivered';
      default:
        return type;
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Test Runs</h1>
          <p className="page-desc">
            Review detailed execution records for each test, including user prompts, agent reasoning, tool calls, and final responses.
          </p>
        </div>
        <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          {runs.length} test run(s) recorded
        </span>
      </div>

      {runs.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-title">No test runs recorded</div>
          <div className="empty-state-desc">
            Execute security tests in <strong>Run Security Test</strong> to see detailed step-by-step records.
          </div>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '1.25rem' }}>
          {/* Left: Test List */}
          <div className="card" style={{ margin: 0, padding: '1rem' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
              Select a Test to Inspect
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: '700px', overflowY: 'auto' }}>
              {runs.map((r) => {
                const isSelected = r.run_id === activeRun?.run_id;
                return (
                  <div
                    key={r.run_id}
                    onClick={() => setSelectedRunId(r.run_id)}
                    style={{
                      padding: '0.75rem 0.85rem',
                      borderRadius: 'var(--radius-md)',
                      backgroundColor: isSelected ? 'var(--primary-subtle)' : 'var(--bg-surface-subtle)',
                      border: isSelected ? '1px solid var(--primary-border)' : '1px solid var(--border-default)',
                      cursor: 'pointer',
                      transition: 'all 0.12s ease',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                      <span className="mono" style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                        {r.run_id.slice(-12)}
                      </span>
                      {getSourceBadge(r.variant_source)}
                    </div>

                    <div style={{ fontWeight: 600, fontSize: '0.86rem', color: 'var(--text-primary)', marginBottom: '0.45rem' }}>
                      {r.name}
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      {getResultBadge(r.verdict)}
                      <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
                        <span
                          className="badge"
                          style={{
                            fontSize: '0.65rem',
                            padding: '1px 5px',
                            backgroundColor: r.execution_mode === 'real_sandbox' ? 'var(--success-subtle)' : 'var(--neutral-subtle)',
                            color: r.execution_mode === 'real_sandbox' ? 'var(--success)' : 'var(--text-muted)',
                            border: `1px solid ${r.execution_mode === 'real_sandbox' ? 'var(--success-border)' : 'var(--neutral-border)'}`,
                          }}
                        >
                          {r.execution_mode === 'real_sandbox' ? 'Sandbox' : 'Sim'}
                        </span>
                        <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                          {r.trace?.steps?.length || 0} steps
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right: Step-by-Step Details */}
          {activeRun && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              {/* Test Header Card */}
              <div className="card" style={{ margin: 0, padding: '1.25rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '0.75rem' }}>
                  <div>
                    <h2 style={{ fontSize: '1.1rem', color: 'var(--text-primary)', fontWeight: 700, marginBottom: '0.25rem' }}>
                      {activeRun.name}
                    </h2>
                    <div style={{ display: 'flex', gap: '0.75rem', fontSize: '0.8rem', color: 'var(--text-muted)', flexWrap: 'wrap' }}>
                      <span>Run ID: <code className="mono">{activeRun.run_id}</code></span>
                      <span>•</span>
                      <span>Target: <strong style={{ color: 'var(--text-primary)' }}>{activeRun.target_id}</strong></span>
                      <span>•</span>
                      <span>Type: <span style={{ textTransform: 'capitalize' }}>{activeRun.kind}</span></span>
                      <span>•</span>
                      <span>Round: <strong>{activeRun.round}</strong></span>
                      {activeRun.parent_run_id && (
                        <>
                          <span>•</span>
                          <span>Parent: <span className="mono">{activeRun.parent_run_id}</span></span>
                        </>
                      )}
                      <span>•</span>
                      <span>
                        Mode:{' '}
                        <strong style={{ color: activeRun.execution_mode === 'real_sandbox' ? 'var(--success)' : 'var(--warning)' }}>
                          {activeRun.execution_mode === 'real_sandbox' ? 'Real Sandbox' : 'Deterministic Simulation'}
                        </strong>
                      </span>
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                    {getExecutionModeBadge(activeRun.execution_mode)}
                    {getResultBadge(activeRun.verdict)}
                  </div>
                </div>

                <div
                  style={{
                    padding: '0.65rem 0.85rem',
                    backgroundColor: activeRun.verdict === 'confirmed_exploit' ? 'var(--danger-subtle)' : activeRun.verdict === 'blocked' ? 'var(--success-subtle)' : 'var(--bg-surface-subtle)',
                    border: `1px solid ${activeRun.verdict === 'confirmed_exploit' ? 'var(--danger-border)' : activeRun.verdict === 'blocked' ? 'var(--success-border)' : 'var(--border-default)'}`,
                    borderRadius: 'var(--radius-sm)',
                    fontSize: '0.84rem',
                    color: activeRun.verdict === 'confirmed_exploit' ? 'var(--danger)' : activeRun.verdict === 'blocked' ? 'var(--success)' : 'var(--text-secondary)',
                  }}
                >
                  <strong>Result Explanation: </strong>
                  {activeRun.verdict === 'confirmed_exploit'
                    ? 'The attack succeeded. The agent performed an unauthorized tool action or leaked sensitive data.'
                    : activeRun.verdict === 'blocked'
                    ? 'The attack was blocked. Guardrails successfully intercepted the prohibited operation before it took effect.'
                    : activeRun.verdict === 'legitimate_pass'
                    ? 'The test passed. Normal support utility completed without issues.'
                    : 'The test completed and requires human inspection.'}
                </div>
              </div>

              {/* Execution Steps Timeline */}
              <div className="card" style={{ margin: 0, padding: '1.25rem' }}>
                <div className="card-header">
                  <div>
                    <h3 className="card-title">Execution Timeline</h3>
                    <p className="card-subtitle">Every step taken by the agent during this test</p>
                  </div>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    {activeRun.trace?.steps?.length || 0} event(s)
                  </span>
                </div>

                {(!activeRun.trace?.steps || activeRun.trace.steps.length === 0) ? (
                  <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No recorded steps in this run trace.
                  </div>
                ) : (
                  <div className="trace-timeline">
                    {activeRun.trace.steps.map((step, idx) => (
                      <div key={idx} className="trace-step-card">
                        <div className="trace-step-header">
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            {getStepIcon(step.step_type)}
                            <span className="trace-step-type">
                              Step {idx + 1}: {getStepLabel(step.step_type)}
                            </span>
                          </div>
                          {step.tool_name && (
                            <span className="badge badge-neutral mono" style={{ fontSize: '0.72rem' }}>
                              tool: {step.tool_name}
                            </span>
                          )}
                        </div>

                        {step.content && (
                          <div className="trace-step-content mono">
                            {step.content}
                          </div>
                        )}

                        {step.tool_args && (
                          <div style={{ marginTop: '0.45rem' }}>
                            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: '0.2rem' }}>
                              Arguments:
                            </div>
                            <pre
                              className="mono"
                              style={{
                                backgroundColor: 'var(--bg-surface-subtle)',
                                padding: '0.5rem 0.75rem',
                                borderRadius: 'var(--radius-sm)',
                                border: '1px solid var(--border-light)',
                                fontSize: '0.8rem',
                                color: 'var(--text-primary)',
                                overflowX: 'auto',
                              }}
                            >
                              {JSON.stringify(step.tool_args, null, 2)}
                            </pre>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
