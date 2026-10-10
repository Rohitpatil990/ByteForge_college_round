import React, { useEffect, useState } from 'react';
import { AssessmentReport, Finding } from '../types';
import { api } from '../api';
import { FileText, Download, ShieldCheck, AlertTriangle, Shield, CheckCircle2, Lock } from 'lucide-react';

interface Props {
  assessmentId: string;
}

export const ReportView: React.FC<Props> = ({ assessmentId }) => {
  const [report, setReport] = useState<AssessmentReport | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchReport = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getReport(assessmentId);
      setReport(data);
    } catch (err: any) {
      setError(err.message || 'Failed to generate assessment report');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReport();
  }, [assessmentId]);

  const handleExportJson = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `agentbreak-security-report-${assessmentId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Report</h1>
          <p className="page-desc">
            Formal assessment record summarizing security test results, problems found, and protective guardrails.
          </p>
        </div>
        {report && (
          <button className="btn btn-secondary btn-sm" onClick={handleExportJson}>
            <Download size={14} /> Download JSON Report
          </button>
        )}
      </div>

      {error && <div className="alert-banner alert-danger">{error}</div>}

      {loading ? (
        <div className="empty-state">
          <div className="empty-state-title">Compiling security report...</div>
          <div className="empty-state-desc">Aggregating test metrics and verified findings</div>
        </div>
      ) : !report ? (
        <div className="empty-state">
          <div className="empty-state-title">No report available</div>
          <div className="empty-state-desc">
            Run tests to generate an assessment report.
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {/* Executive Summary Card */}
          <div className="card" style={{ padding: '1.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem', borderBottom: '1px solid var(--border-light)', paddingBottom: '1rem', marginBottom: '1rem' }}>
              <div>
                <span style={{ fontSize: '0.74rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Assessment Summary
                </span>
                <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.15rem' }}>
                  {report.assessment_name}
                </h2>
                <div style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                  Target Agent: <strong style={{ color: 'var(--text-primary)' }}>{report.target_name} ({report.target_id})</strong>
                </div>
              </div>

              <div style={{ textAlign: 'right', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                <div>Generated: <span style={{ color: 'var(--text-primary)' }}>{new Date(report.generated_at).toLocaleString()}</span></div>
                <div style={{ marginTop: '0.2rem' }}>
                  Evidence Seal: <strong style={{ color: 'var(--success)' }}>{report.evidence_integrity.chain_length} Verified Blocks</strong>
                </div>
              </div>
            </div>

            {/* Finding statement */}
            <div
              style={{
                padding: '0.85rem 1rem',
                backgroundColor: 'var(--primary-subtle)',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--primary-border)',
                fontSize: '0.88rem',
                color: 'var(--text-primary)',
                lineHeight: '1.5',
              }}
            >
              <strong>Key Finding: </strong>
              {report.summary.exploit_breakdown_statement}
            </div>
          </div>

          {/* Test Outcomes Grid */}
          <div className="summary-grid">
            <div className="summary-card primary">
              <div className="summary-card-header">
                <span className="summary-label">Total Tests</span>
              </div>
              <div className="summary-number">{report.summary.total_runs}</div>
              <div className="summary-desc">{report.summary.attack_runs} attacks dispatched</div>
            </div>

            <div className="summary-card danger">
              <div className="summary-card-header">
                <span className="summary-label">Attacks Succeeded</span>
              </div>
              <div className="summary-number">{report.summary.confirmed_exploits}</div>
              <div className="summary-desc">
                {report.findings_metrics.seed_findings_count} seed, {report.findings_metrics.adaptive_generated_findings_count} adaptive
              </div>
            </div>

            <div className="summary-card success">
              <div className="summary-card-header">
                <span className="summary-label">Attacks Blocked</span>
              </div>
              <div className="summary-number">{report.summary.blocked_attempts}</div>
              <div className="summary-desc">Intercepted by active guardrails</div>
            </div>

            <div className="summary-card warning">
              <div className="summary-card-header">
                <span className="summary-label">Recorded Fixtures</span>
              </div>
              <div className="summary-number">{report.findings_metrics.recorded_findings_count}</div>
              <div className="summary-desc">Baseline cataloged fixtures</div>
            </div>
          </div>

          {/* Detailed Problems Found Table */}
          <div className="card">
            <div className="card-header">
              <div>
                <h3 className="card-title">Discovered Security Problems</h3>
                <p className="card-subtitle">Detailed inventory of detected violations</p>
              </div>
            </div>

            {(!report.findings_list || report.findings_list.length === 0) ? (
              <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                No security problems recorded in this assessment.
              </div>
            ) : (
              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>Rule ID</th>
                      <th>Severity</th>
                      <th>Source</th>
                      <th>Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.findings_list.map((f: Finding) => (
                      <tr key={f.finding_id}>
                        <td className="mono" style={{ fontWeight: 600, fontSize: '0.8rem' }}>
                          {f.rule_fired}
                        </td>
                        <td>
                          <span className={`badge ${f.severity === 'high' || f.severity === 'critical' ? 'badge-danger' : 'badge-warning'}`}>
                            {f.severity}
                          </span>
                        </td>
                        <td>
                          <span className="badge badge-neutral">
                            {f.source}
                          </span>
                        </td>
                        <td style={{ color: 'var(--text-secondary)', fontSize: '0.84rem' }}>
                          {f.description}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Platform Limitations & Boundaries */}
          <div className="card" style={{ backgroundColor: 'var(--bg-surface-subtle)' }}>
            <h3 style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
              Assessment Disclosures & Known Boundaries
            </h3>
            <ul style={{ paddingLeft: '1.25rem', fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
              <li>
                <strong>Verbatim Matching:</strong> Synthetic canary detection checks verbatim token occurrences and does not infer encoded or multi-lingual translations.
              </li>
              <li>
                <strong>Response vs. Tool Guards:</strong> Active guardrails D1 and D2 inspect tool call parameters. Direct disclosure inside conversational replies requires D3 response filtering.
              </li>
              <li>
                <strong>Configuration Scope:</strong> Testing is bound to the target configuration specification (<code className="mono">demo-company-assistant</code>).
              </li>
            </ul>
          </div>
        </div>
      )}
    </div>
  );
};
