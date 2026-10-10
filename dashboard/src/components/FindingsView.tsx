import React, { useState } from 'react';
import { Finding } from '../types';
import { AlertTriangle, ShieldCheck, ShieldAlert, FileText, CheckCircle2, History, Layers } from 'lucide-react';

interface Props {
  findings: Finding[];
}

export const FindingsView: React.FC<Props> = ({ findings }) => {
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(
    findings.length > 0 ? findings[0].finding_id : null
  );

  const totalOccurrences = findings.reduce(
    (sum, f) => sum + (f.details?.occurrences || 1),
    0
  );

  const getSourceBadge = (source: string) => {
    switch (source) {
      case 'recorded':
        return <span className="badge badge-warning">Recorded Fixture</span>;
      case 'generated':
        return <span className="badge badge-primary">Adaptive Discovery</span>;
      case 'seed':
        return <span className="badge badge-neutral">Seed Scenario</span>;
      default:
        return <span className="badge badge-neutral">{source}</span>;
    }
  };

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

  const getProblemDetails = (rule: string) => {
    switch (rule) {
      case 'canary_in_executed_args':
        return {
          title: 'Secret Leaked in External Tool Arguments',
          summary: 'The agent passed a confidential secret into the arguments of an external tool call.',
          explanation:
            'During testing, an adversarial prompt tricked the agent into including a protected secret inside a tool call (such as the recipient or body of an email). This allows exfiltration outside the agent system.',
          protection: 'Tool Domain Policy Guard (D1)',
          protectionStatus: 'Enforced',
        };
      case 'canary_in_final_reply':
        return {
          title: 'Secret Leaked in Conversation Response',
          summary: 'The agent repeated a confidential secret in its direct answer to the user.',
          explanation:
            'The agent included a sensitive canary secret in its final text response. Since tool-call policies only check function parameters, conversational output filters are required to prevent this disclosure.',
          protection: 'Response Content Filter (D3)',
          protectionStatus: 'Development Stub',
        };
      case 'executed_outside_policy':
        return {
          title: 'Unauthorized Action Exceeded Policy Boundary',
          summary: 'A tool was invoked with parameters strictly prohibited by company policy.',
          explanation:
            'The agent attempted to invoke a tool with unauthorized parameters (such as sending an email to an unapproved external domain). When defenses are active, Guard D1 intercepts this call.',
          protection: 'Tool Domain Policy Guard (D1)',
          protectionStatus: 'Enforced',
        };
      case 'memory_write_untrusted':
        return {
          title: 'Unauthorized Memory Modification from Untrusted Input',
          summary: 'Untrusted user input attempted to modify persistent agent memory.',
          explanation:
            'An unverified prompt instructed the agent to write or overwrite persistent memory data. Guard D2 rejects untrusted memory writes to prevent persistent agent manipulation.',
          protection: 'Untrusted Memory Write Guard (D2)',
          protectionStatus: 'Enforced',
        };
      default:
        return {
          title: rule.replace(/_/g, ' '),
          summary: 'Security policy violation detected during testing.',
          explanation: 'The agent executed an action that triggered an active security rule.',
          protection: 'Policy Guard',
          protectionStatus: 'Active',
        };
    }
  };

  const activeFinding = findings.find((f) => f.finding_id === selectedFindingId) || findings[0];
  const details = activeFinding ? getProblemDetails(activeFinding.rule_fired) : null;
  const activeOccurrences = activeFinding?.details?.occurrences || 1;
  const associatedRuns = activeFinding?.details?.associated_run_ids || (activeFinding?.trace_id ? [activeFinding.trace_id] : []);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Problems Found</h1>
          <p className="page-desc">
            Deduplicated catalog of unique vulnerabilities detected across testing and adaptive attacks.
          </p>
        </div>
        <div style={{ textAlign: 'right' }}>
          <span className="badge badge-primary" style={{ fontSize: '0.84rem', padding: '0.3rem 0.65rem' }}>
            {findings.length} Unique {findings.length === 1 ? 'Vulnerability' : 'Vulnerabilities'}
          </span>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
            {totalOccurrences} total violation attempt{totalOccurrences === 1 ? '' : 's'} across runs
          </div>
        </div>
      </div>

      {findings.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-title">No problems found</div>
          <div className="empty-state-desc">
            No security violations were detected. Run security tests in <strong>Run Security Test</strong> or <strong>Try a New Attack</strong> to evaluate your agent.
          </div>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '1.25rem' }}>
          {/* Left: Problems List */}
          <div className="card" style={{ margin: 0 }}>
            <div className="card-header">
              <div>
                <h2 className="card-title">Discovered Issues (Deduplicated)</h2>
                <p className="card-subtitle">Click an issue to view its details, occurrences, and run traces</p>
              </div>
            </div>

            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Issue</th>
                    <th>Occurrences</th>
                    <th>Severity</th>
                    <th>Source</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((f) => {
                    const isSelected = f.finding_id === activeFinding?.finding_id;
                    const meta = getProblemDetails(f.rule_fired);
                    const occ = f.details?.occurrences || 1;
                    return (
                      <tr
                        key={f.finding_id}
                        onClick={() => setSelectedFindingId(f.finding_id)}
                        style={{
                          backgroundColor: isSelected ? 'var(--primary-subtle)' : undefined,
                          cursor: 'pointer',
                        }}
                      >
                        <td>
                          <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                            {meta.title}
                          </div>
                          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                            {f.description}
                          </div>
                        </td>
                        <td>
                          <span
                            className={`badge ${occ > 1 ? 'badge-warning' : 'badge-neutral'}`}
                            style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}
                          >
                            <Layers size={11} />
                            {occ}x detected
                          </span>
                        </td>
                        <td>{getSeverityBadge(f.severity)}</td>
                        <td>{getSourceBadge(f.source)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Right: Selected Finding Evidence Card */}
          {activeFinding && details && (
            <div className="card" style={{ margin: 0, padding: '1.25rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem', borderBottom: '1px solid var(--border-light)', paddingBottom: '0.75rem' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                    <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                      {details.title}
                    </h3>
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    Finding ID: <code className="mono">{activeFinding.finding_id}</code>
                  </div>
                </div>
                {getSeverityBadge(activeFinding.severity)}
              </div>

              {/* Occurrences & Lineage Card */}
              <div
                style={{
                  marginBottom: '1.25rem',
                  padding: '0.85rem 1rem',
                  backgroundColor: 'var(--bg-surface-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border-default)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                  <span style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                    Violation Frequency
                  </span>
                  <span className={`badge ${activeOccurrences > 1 ? 'badge-warning' : 'badge-neutral'}`}>
                    {activeOccurrences} Execution Attempt{activeOccurrences === 1 ? '' : 's'}
                  </span>
                </div>
                <div style={{ fontSize: '0.84rem', color: 'var(--text-primary)', lineHeight: '1.45' }}>
                  This vulnerability was triggered <strong>{activeOccurrences} time{activeOccurrences === 1 ? '' : 's'}</strong> during testing.
                  Finding records are deduplicated by underlying vulnerability so each issue appears once.
                </div>
                {activeFinding.details?.last_seen_at && (
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.35rem' }}>
                    Last triggered: {activeFinding.details.last_seen_at}
                  </div>
                )}
              </div>

              {/* What Happened */}
              <div style={{ marginBottom: '1.25rem' }}>
                <h4 style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.35rem' }}>
                  What Happened
                </h4>
                <p style={{ fontSize: '0.88rem', color: 'var(--text-primary)', lineHeight: '1.5' }}>
                  {activeFinding.description}
                </p>
              </div>

              {/* Technical Rule Fired */}
              <div style={{ marginBottom: '1.25rem' }}>
                <h4 style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.35rem' }}>
                  Security Rule
                </h4>
                <div style={{ padding: '0.5rem 0.75rem', backgroundColor: 'var(--bg-surface-subtle)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-default)' }}>
                  <code className="mono" style={{ fontSize: '0.82rem', color: 'var(--text-primary)', fontWeight: 600 }}>
                    {activeFinding.rule_fired}
                  </code>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.35rem' }}>
                    {details.explanation}
                  </p>
                </div>
              </div>

              {/* Recommended Protection */}
              <div style={{ marginBottom: '1.25rem' }}>
                <h4 style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.35rem' }}>
                  Recommended Protection
                </h4>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.65rem 0.85rem', backgroundColor: 'var(--bg-surface-subtle)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-default)' }}>
                  <span style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--text-primary)' }}>
                    {details.protection}
                  </span>
                  <span className={`badge ${details.protectionStatus === 'Enforced' ? 'badge-success' : 'badge-warning'}`}>
                    {details.protectionStatus}
                  </span>
                </div>
              </div>

              {/* Associated Test Run Traces */}
              <div>
                <h4 style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  <History size={13} /> Associated Test Runs ({associatedRuns.length})
                </h4>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', marginTop: '0.25rem' }}>
                  {associatedRuns.map((rid, idx) => {
                    const isLatest = idx === associatedRuns.length - 1;
                    return (
                      <span
                        key={rid}
                        className="badge badge-neutral mono"
                        style={{
                          fontSize: '0.76rem',
                          backgroundColor: isLatest ? 'var(--primary-subtle)' : undefined,
                          borderColor: isLatest ? 'var(--primary)' : undefined,
                          color: isLatest ? 'var(--primary)' : undefined,
                        }}
                      >
                        {rid} {isLatest && '(Latest)'}
                      </span>
                    );
                  })}
                </div>
                <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
                  All {associatedRuns.length} execution traces and cryptographic chain blocks are preserved in <strong>Test Runs</strong>.
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
