import React, { useState } from 'react';
import { Run, TraceStep } from '../types';
import { Terminal, ArrowRight, CornerDownRight, CheckCircle, ShieldAlert, Cpu } from 'lucide-react';

interface Props {
  runs: Run[];
}

export const RunsTraceView: React.FC<Props> = ({ runs }) => {
  const [selectedRunId, setSelectedRunId] = useState<string | null>(
    runs.length > 0 ? runs[0].run_id : null
  );

  const activeRun = runs.find((r) => r.run_id === selectedRunId) || runs[0];

  const getVerdictChip = (verdict: string) => {
    switch (verdict) {
      case 'confirmed_exploit':
        return <span className="chip chip-exploit">Exploit Confirmed</span>;
      case 'blocked':
        return <span className="chip chip-blocked">Blocked by Guard</span>;
      case 'legitimate_pass':
        return <span className="chip chip-pass">Legitimate Pass</span>;
      case 'inconclusive':
        return <span className="chip chip-inconclusive">Inconclusive</span>;
      default:
        return <span className="chip chip-seed">{verdict}</span>;
    }
  };

  const getSourceChip = (source: string) => {
    switch (source) {
      case 'recorded':
        return <span className="chip chip-recorded">Recorded Fixture</span>;
      case 'generated':
        return <span className="chip chip-generated">Adaptive Generated</span>;
      default:
        return <span className="chip chip-seed">Seed Benchmark</span>;
    }
  };

  const getStepTypeBadge = (type: string) => {
    switch (type) {
      case 'user_input':
        return <span className="mono" style={{ color: '#00e5ff', fontWeight: 600 }}>user_input</span>;
      case 'agent_thought':
        return <span className="mono" style={{ color: '#a855f7', fontWeight: 600 }}>agent_thought</span>;
      case 'tool_call':
        return <span className="mono" style={{ color: '#f59e0b', fontWeight: 600 }}>tool_call</span>;
      case 'tool_result':
        return <span className="mono" style={{ color: '#10b981', fontWeight: 600 }}>tool_result</span>;
      case 'final_reply':
        return <span className="mono" style={{ color: '#ec4899', fontWeight: 700 }}>final_reply</span>;
      default:
        return <span className="mono" style={{ color: '#94a3b8' }}>{type}</span>;
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h2 className="page-title">
            <Terminal size={18} color="#00e5ff" /> Execution Runs & Step-by-Step Traces
          </h2>
          <p className="page-desc">
            Forensic trace inspection tracking agent thought processes, tool arguments, policy intercepts, and final response deliveries.
          </p>
        </div>
        <span className="mono" style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
          {runs.length} Saved Run(s)
        </span>
      </div>

      {runs.length === 0 ? (
        <div className="panel" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
          No runs recorded in current session. Execute benchmark tests in <strong>Execute Tests</strong> to inspect traces.
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(280px, 1fr) 2.2fr', gap: '1.15rem' }}>
          {/* Left: Compact Run Selector */}
          <div className="panel" style={{ margin: 0, padding: '0.85rem' }}>
            <div style={{ fontSize: '0.74rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-subtle)', marginBottom: '0.65rem' }}>
              Select Run to Investigate
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', maxHeight: '680px', overflowY: 'auto' }}>
              {runs.map((r) => {
                const isSelected = r.run_id === activeRun?.run_id;
                return (
                  <div
                    key={r.run_id}
                    onClick={() => setSelectedRunId(r.run_id)}
                    style={{
                      padding: '0.65rem 0.75rem',
                      borderRadius: '5px',
                      backgroundColor: isSelected ? 'var(--bg-surface-elevated)' : 'var(--bg-app)',
                      border: isSelected ? '1px solid var(--cyan-primary)' : '1px solid var(--border-subtle)',
                      cursor: 'pointer',
                      transition: 'all 0.12s ease',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.2rem' }}>
                      <span className="mono" style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                        {r.run_id.slice(-14)}
                      </span>
                      {getSourceChip(r.variant_source)}
                    </div>

                    <div style={{ fontWeight: 600, fontSize: '0.82rem', color: '#fff', marginBottom: '0.35rem' }}>
                      {r.name}
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      {getVerdictChip(r.verdict)}
                      <span className="mono" style={{ fontSize: '0.68rem', color: 'var(--text-subtle)' }}>
                        {r.trace?.steps?.length || 0} steps
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right: Forensic Trace & Attack Path Inspector */}
          {activeRun && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.15rem' }}>
              {/* Active Run Header */}
              <div className="panel" style={{ margin: 0, padding: '1rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
                  <div>
                    <h3 style={{ fontSize: '1rem', color: '#fff', fontWeight: 600, marginBottom: '0.2rem' }}>
                      {activeRun.name}
                    </h3>
                    <div style={{ display: 'flex', gap: '0.75rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      <span>Run ID: <code className="mono" style={{ color: '#cbd5e1' }}>{activeRun.run_id}</code></span>
                      <span>•</span>
                      <span>Target: <strong style={{ color: '#00e5ff' }}>{activeRun.target_id}</strong></span>
                      <span>•</span>
                      <span>Round: <strong>{activeRun.round}</strong></span>
                      <span>•</span>
                      <span>Parent: <span className="mono">{activeRun.parent_run_id || 'Root (Seed)'}</span></span>
                    </div>
                  </div>
                  {getVerdictChip(activeRun.verdict)}
                </div>
              </div>

              {/* Attack Path Flowchart Sequence (P1 Visualization) */}
              <div className="panel" style={{ margin: 0, padding: '1rem' }}>
                <div className="panel-header" style={{ marginBottom: '0.65rem' }}>
                  <h4 className="panel-title" style={{ fontSize: '0.84rem' }}>
                    <Cpu size={14} color="#00e5ff" /> Attack Path Flowchart (P1 Sequence View)
                  </h4>
                  <span className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                    {activeRun.trace?.steps?.length || 0} Trace Events
                  </span>
                </div>

                <div className="path-container">
                  {activeRun.trace?.steps?.map((step: TraceStep, index: number) => {
                    const isFinalReply = step.step_type === 'final_reply';
                    const isTool = step.step_type === 'tool_call';
                    const isBlocked = step.content?.includes('blocked') || step.content?.includes('Policy Guard');

                    return (
                      <div
                        key={index}
                        className="path-node"
                        style={{
                          borderColor: isFinalReply
                            ? 'rgba(236, 72, 153, 0.4)'
                            : isBlocked
                            ? 'rgba(16, 185, 129, 0.4)'
                            : undefined,
                          backgroundColor: isFinalReply
                            ? 'rgba(236, 72, 153, 0.04)'
                            : undefined,
                        }}
                      >
                        <span className="node-idx">{index + 1}</span>
                        <div className="node-body">
                          <div className="node-header">
                            {getStepTypeBadge(step.step_type)}
                            {step.tool_name && (
                              <span className="mono" style={{ fontSize: '0.74rem', color: '#f59e0b' }}>
                                invoke: {step.tool_name}()
                              </span>
                            )}
                          </div>
                          <div className="node-content">
                            {step.content || JSON.stringify(step.tool_args)}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Dense Step Trace Table */}
              <div className="panel" style={{ margin: 0, padding: '1rem' }}>
                <div className="panel-header" style={{ marginBottom: '0.65rem' }}>
                  <h4 className="panel-title" style={{ fontSize: '0.84rem' }}>
                    Raw Execution Trace Records
                  </h4>
                  <span className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                    Deterministic Chronological Order
                  </span>
                </div>

                <div className="table-container">
                  <table>
                    <thead>
                      <tr>
                        <th>#</th>
                        <th>Step Type</th>
                        <th>Action / Tool</th>
                        <th>Payload / Evidence Content</th>
                        <th>Timestamp</th>
                      </tr>
                    </thead>
                    <tbody>
                      {activeRun.trace?.steps?.map((step: TraceStep, idx: number) => {
                        const isFinalReply = step.step_type === 'final_reply';
                        return (
                          <tr
                            key={idx}
                            style={{
                              backgroundColor: isFinalReply ? 'rgba(236, 72, 153, 0.05)' : undefined,
                            }}
                          >
                            <td className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                              {idx + 1}
                            </td>
                            <td>{getStepTypeBadge(step.step_type)}</td>
                            <td className="mono" style={{ fontSize: '0.78rem', color: step.tool_name ? '#f59e0b' : 'var(--text-subtle)' }}>
                              {step.tool_name ? `${step.tool_name}()` : '-'}
                            </td>
                            <td style={{ fontSize: '0.78rem' }}>
                              {step.tool_args && (
                                <pre className="mono" style={{ fontSize: '0.74rem', color: '#fde68a', margin: '0 0 0.25rem 0', background: 'var(--bg-app)', padding: '0.3rem 0.5rem', borderRadius: '3px' }}>
                                  {JSON.stringify(step.tool_args, null, 2)}
                                </pre>
                              )}
                              {step.content && (
                                <span style={{ wordBreak: 'break-all', color: isFinalReply ? '#fbcfe8' : '#e2e8f0' }}>
                                  {step.content}
                                </span>
                              )}
                            </td>
                            <td className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-subtle)' }}>
                              {step.timestamp ? new Date(step.timestamp).toLocaleTimeString() : '-'}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
