import React, { useState } from 'react';
import { Finding } from '../types';
import { AlertTriangle, ShieldAlert, CheckCircle, Info, ExternalLink, Code2 } from 'lucide-react';

interface Props {
  findings: Finding[];
}

export const FindingsView: React.FC<Props> = ({ findings }) => {
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(
    findings.length > 0 ? findings[0].finding_id : null
  );

  const getSourceChip = (source: string) => {
    switch (source) {
      case 'recorded':
        return <span className="chip chip-recorded">Recorded Fixture</span>;
      case 'generated':
        return <span className="chip chip-generated">Adaptive Generated</span>;
      case 'seed':
        return <span className="chip chip-seed">Seed Benchmark</span>;
      default:
        return <span className="chip chip-seed">{source}</span>;
    }
  };

  const getSeverityChip = (severity?: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return <span className="chip chip-exploit">Critical</span>;
      case 'high':
        return <span className="chip chip-exploit" style={{ background: 'rgba(244, 63, 94, 0.16)' }}>High</span>;
      case 'medium':
        return <span className="chip chip-inconclusive">Medium</span>;
      case 'low':
        return <span className="chip chip-seed">Low</span>;
      default:
        return <span className="chip chip-seed">Unassigned</span>;
    }
  };

  const getRuleDetails = (rule: string) => {
    switch (rule) {
      case 'canary_in_executed_args':
        return {
          title: 'Canary Secret Injected into Tool Execution Arguments',
          category: 'Action Parameter Exfiltration',
          explanation:
            'The secret canary token appeared inside the parameters of an invoked tool (e.g., send_email body). The attacker successfully manipulated the agent into transmitting confidential data via an external tool dispatch.',
          enforcementType: 'Tool Argument Filter (D1)',
          status: 'Enforced in Code',
        };
      case 'canary_in_final_reply':
        return {
          title: 'Canary Secret Leaked into Final Assistant Reply Text',
          category: 'Delivered Response Disclosure',
          explanation:
            'The secret canary token appeared in plain text in the final delivered user response. Tool-call policies do not monitor or restrict text generated directly into final_reply.',
          enforcementType: 'Output Reply Filter (D3)',
          status: 'Stub Guard — Unmitigated in Current Build',
        };
      case 'executed_outside_policy':
        return {
          title: 'Tool Execution Breached Policy Constraints',
          category: 'Policy Boundary Violation',
          explanation:
            'A tool was invoked with parameters or conditions strictly forbidden by policy.yaml (e.g. email recipient address outside the approved company.com domain).',
          enforcementType: 'Domain Policy Guard (D1)',
          status: 'Enforced in Code',
        };
      case 'memory_write_untrusted':
        return {
          title: 'Untrusted User Input Triggered Persistent Memory Write',
          category: 'Memory Poisoning & Integrity',
          explanation:
            'An unauthenticated external prompt triggered a persistent state modification in agent memory, violating the policy.yaml directive that untrusted input cannot authorize memory writes.',
          enforcementType: 'Memory Write Guard (D2)',
          status: 'Enforced in Code',
        };
      default:
        return {
          title: rule,
          category: 'Security Violation',
          explanation: 'Generic security policy violation detected.',
          enforcementType: 'Custom Policy',
          status: 'Under Investigation',
        };
    }
  };

  const activeFinding = findings.find((f) => f.finding_id === selectedFindingId) || findings[0];
  const ruleMeta = activeFinding ? getRuleDetails(activeFinding.rule_fired) : null;

  return (
    <div>
      <div className="page-header">
        <div>
          <h2 className="page-title">
            <AlertTriangle size={18} color="#f59e0b" /> Discovered Security Findings
          </h2>
          <p className="page-desc">
            Granular evidence of confirmed policy violations and canary disclosures.
            Pre-recorded baseline fixtures are isolated with amber badges and never count as adaptive discoveries.
          </p>
        </div>
        <span className="mono" style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
          {findings.length} Finding(s) Cataloged
        </span>
      </div>

      {findings.length === 0 ? (
        <div className="panel" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
          No findings recorded yet. Execute benchmark tests in <strong>Execute Tests</strong> to evaluate policies.
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.1fr', gap: '1.15rem' }}>
          {/* Left: Findings Table */}
          <div className="panel" style={{ margin: 0, padding: '0.85rem' }}>
            <div className="panel-header" style={{ marginBottom: '0.65rem' }}>
              <h3 className="panel-title" style={{ fontSize: '0.85rem' }}>
                Discovered Violations Table
              </h3>
              <span className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                {findings.filter((f) => f.source !== 'recorded').length} Live Discoveries
              </span>
            </div>

            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Finding ID</th>
                    <th>Source Tag</th>
                    <th>Severity</th>
                    <th>Rule Fired</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((f) => {
                    const isSelected = f.finding_id === activeFinding?.finding_id;
                    return (
                      <tr
                        key={f.finding_id}
                        onClick={() => setSelectedFindingId(f.finding_id)}
                        style={{
                          backgroundColor: isSelected ? 'var(--bg-surface-elevated)' : undefined,
                          cursor: 'pointer',
                        }}
                      >
                        <td className="mono" style={{ fontWeight: 600, fontSize: '0.76rem' }}>
                          {f.finding_id}
                        </td>
                        <td>{getSourceChip(f.source)}</td>
                        <td>{getSeverityChip(f.severity)}</td>
                        <td>
                          <code className="mono" style={{ fontSize: '0.74rem', color: '#00e5ff' }}>
                            {f.rule_fired}
                          </code>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Right: Forensic Finding Detail Inspector */}
          {activeFinding && ruleMeta && (
            <div className="panel" style={{ margin: 0, padding: '1rem', background: 'var(--bg-surface-elevated)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                <span className="mono" style={{ fontSize: '0.85rem', fontWeight: 700, color: '#fff' }}>
                  {activeFinding.finding_id}
                </span>
                <div style={{ display: 'flex', gap: '0.4rem' }}>
                  {getSourceChip(activeFinding.source)}
                  {getSeverityChip(activeFinding.severity)}
                </div>
              </div>

              <h3 style={{ fontSize: '0.98rem', fontWeight: 700, color: '#fff', marginBottom: '0.25rem' }}>
                {ruleMeta.title}
              </h3>

              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
                Category: <strong style={{ color: '#cbd5e1' }}>{ruleMeta.category}</strong> | Rule Code:{' '}
                <code className="mono" style={{ color: '#00e5ff' }}>{activeFinding.rule_fired}</code>
              </div>

              {/* Description */}
              <div style={{ padding: '0.65rem 0.8rem', background: 'var(--bg-app)', borderRadius: '4px', border: '1px solid var(--border-subtle)', marginBottom: '0.75rem', fontSize: '0.8rem' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-subtle)', textTransform: 'uppercase', display: 'block', marginBottom: '0.2rem' }}>
                  Recorded Observation
                </span>
                <p style={{ color: '#e2e8f0', lineHeight: '1.45' }}>{activeFinding.description}</p>
              </div>

              {/* Forensic Explanation */}
              <div style={{ padding: '0.65rem 0.8rem', background: 'var(--bg-app)', borderRadius: '4px', border: '1px solid var(--border-subtle)', marginBottom: '0.75rem', fontSize: '0.8rem' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-subtle)', textTransform: 'uppercase', display: 'block', marginBottom: '0.2rem' }}>
                  Security Violation Analysis
                </span>
                <p style={{ color: '#cbd5e1', lineHeight: '1.45' }}>{ruleMeta.explanation}</p>
              </div>

              {/* Mitigation & Enforcement Status */}
              <div style={{ padding: '0.65rem 0.8rem', background: 'var(--bg-app)', borderRadius: '4px', border: '1px solid var(--border-subtle)', marginBottom: '0.75rem', fontSize: '0.8rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.2rem' }}>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-subtle)', textTransform: 'uppercase' }}>
                    Mitigation Enforcement
                  </span>
                  {activeFinding.rule_fired === 'canary_in_final_reply' ? (
                    <span className="chip chip-stub">Stub Filter — Unmitigated</span>
                  ) : (
                    <span className="chip chip-enforced">Policy Enforced</span>
                  )}
                </div>
                <p style={{ color: '#94a3b8', fontSize: '0.76rem' }}>
                  Associated Control: <strong>{ruleMeta.enforcementType}</strong>
                </p>
              </div>

              {/* Raw Evidence Payload */}
              {activeFinding.details && (
                <div>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-subtle)', textTransform: 'uppercase', display: 'block', marginBottom: '0.25rem' }}>
                    Evidence Metadata Log
                  </span>
                  <pre
                    className="mono"
                    style={{
                      padding: '0.55rem',
                      background: 'var(--bg-app)',
                      borderRadius: '4px',
                      fontSize: '0.72rem',
                      color: '#94a3b8',
                      overflowX: 'auto',
                      border: '1px solid var(--border-subtle)',
                      lineHeight: '1.4',
                    }}
                  >
                    {JSON.stringify(activeFinding.details, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
