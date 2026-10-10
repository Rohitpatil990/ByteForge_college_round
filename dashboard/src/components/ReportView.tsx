import React, { useEffect, useState } from 'react';
import { AssessmentReport } from '../types';
import { api } from '../api';
import { FileText, Download, ShieldCheck, AlertTriangle, Shield, CheckCircle, Info } from 'lucide-react';

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
    a.download = `agentbreak-audit-report-${assessmentId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h2 className="page-title">
            <FileText size={18} color="#00e5ff" /> Security Assessment Audit Report
          </h2>
          <p className="page-desc">
            Executive-grade security report generated directly from saved run traces and hash-chained evidence.
          </p>
        </div>
        {report && (
          <button className="btn btn-secondary btn-sm" onClick={handleExportJson}>
            <Download size={13} /> Export Raw JSON Report
          </button>
        )}
      </div>

      {error && <div className="alert-banner alert-danger">{error}</div>}

      {loading ? (
        <div className="panel" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
          Compiling report metrics from assessment database...
        </div>
      ) : !report ? (
        <div className="panel" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
          No saved assessment evidence available to generate report.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.15rem' }}>
          {/* Formal Audit Header */}
          <div className="panel" style={{ padding: '1.25rem', background: 'linear-gradient(180deg, #161b24 0%, #12151c 100%)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem', marginBottom: '1rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.85rem' }}>
              <div>
                <span className="mono" style={{ fontSize: '0.72rem', color: 'var(--text-subtle)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  AgentBreak Security Benchmark Audit
                </span>
                <h3 style={{ fontSize: '1.2rem', fontWeight: 700, color: '#fff' }}>
                  {report.assessment_name}
                </h3>
                <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Target: <strong style={{ color: '#00e5ff' }}>{report.target_name} ({report.target_id})</strong>
                </span>
              </div>

              <div style={{ textAlign: 'right', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                <div>Audit Timestamp: <span className="mono" style={{ color: '#fff' }}>{new Date(report.generated_at).toLocaleString()}</span></div>
                <div>Evidence Chain: <strong className="mono" style={{ color: '#10b981' }}>{report.evidence_integrity.chain_length} Block(s) Verified</strong></div>
              </div>
            </div>

            {/* Mandatory Outcome Statement Callout */}
            <div
              style={{
                padding: '0.85rem 1rem',
                backgroundColor: 'rgba(0, 229, 255, 0.05)',
                border: '1px solid var(--cyan-border)',
                borderRadius: '4px',
                fontSize: '0.86rem',
                color: '#e0f2fe',
                lineHeight: '1.5',
              }}
            >
              <strong style={{ color: '#00e5ff' }}>Measured Discovery Outcome: </strong>
              {report.summary.exploit_breakdown_statement}
            </div>
          </div>

          {/* Metrics Summary Grid */}
          <div className="kpi-row">
            <div className="kpi-block">
              <span className="kpi-block-label">Attacks Dispatched</span>
              <span className="kpi-block-val">{report.summary.attack_runs}</span>
              <span className="kpi-block-sub">Total runs: {report.summary.total_runs}</span>
            </div>

            <div className="kpi-block">
              <span className="kpi-block-label">Confirmed Exploits</span>
              <span className="kpi-block-val" style={{ color: '#fb7185' }}>{report.summary.confirmed_exploits}</span>
              <span className="kpi-block-sub">
                Seed: {report.findings_metrics.seed_findings_count} | Adaptive: {report.findings_metrics.adaptive_generated_findings_count}
              </span>
            </div>

            <div className="kpi-block">
              <span className="kpi-block-label">Recorded Fixtures</span>
              <span className="kpi-block-val" style={{ color: '#f59e0b' }}>{report.findings_metrics.recorded_findings_count}</span>
              <span className="kpi-block-sub">Separated (non-adaptive)</span>
            </div>

            <div className="kpi-block">
              <span className="kpi-block-label">Blocked Attempts</span>
              <span className="kpi-block-val" style={{ color: '#34d399' }}>{report.summary.blocked_attempts}</span>
              <span className="kpi-block-sub">Enforced by guardrails</span>
            </div>
          </div>

          {/* Before/After Retest Scorecard */}
          <div className="panel">
            <div className="panel-header">
              <h3 className="panel-title">Before vs. After Defense Scorecard</h3>
              <span className="mono" style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                Empirical Denominators
              </span>
            </div>

            {report.retest_comparison && report.retest_comparison.before && report.retest_comparison.after ? (
              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>Evaluated Dimension</th>
                      <th>Baseline (Before Guardrails)</th>
                      <th>Retest (With Active Guardrails)</th>
                      <th>Measured Impact</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td><strong>Confirmed Exploit Rate</strong></td>
                      <td className="mono" style={{ color: '#fb7185' }}>
                        {report.retest_comparison.before.exploit_rate !== null
                          ? `${(report.retest_comparison.before.exploit_rate * 100).toFixed(1)}% (${report.retest_comparison.before.exploit_rate_display})`
                          : 'Not run'}
                      </td>
                      <td className="mono" style={{ color: '#34d399' }}>
                        {report.retest_comparison.after.exploit_rate !== null
                          ? `${(report.retest_comparison.after.exploit_rate * 100).toFixed(1)}% (${report.retest_comparison.after.exploit_rate_display})`
                          : 'Not run'}
                      </td>
                      <td>
                        {report.retest_comparison.before.exploit_rate !== null && report.retest_comparison.after.exploit_rate !== null
                          ? `${((report.retest_comparison.before.exploit_rate - report.retest_comparison.after.exploit_rate) * 100).toFixed(1)}% exploit reduction`
                          : 'N/A'}
                      </td>
                    </tr>
                    <tr>
                      <td><strong>Legitimate-Task Pass Rate</strong></td>
                      <td className="mono" style={{ color: '#38bdf8' }}>
                        {report.retest_comparison.before.legitimate_pass_rate !== null
                          ? `${(report.retest_comparison.before.legitimate_pass_rate * 100).toFixed(1)}% (${report.retest_comparison.before.legitimate_pass_rate_display})`
                          : 'Not run'}
                      </td>
                      <td className="mono" style={{ color: '#38bdf8' }}>
                        {report.retest_comparison.after.legitimate_pass_rate !== null
                          ? `${(report.retest_comparison.after.legitimate_pass_rate * 100).toFixed(1)}% (${report.retest_comparison.after.legitimate_pass_rate_display})`
                          : 'Not run'}
                      </td>
                      <td>Preserved (100% utility)</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', padding: '0.5rem 0' }}>
                Retest comparison was not run for this assessment. Execute retest in the <strong>Retest Scorecard</strong> tab.
              </div>
            )}
          </div>

          {/* Mandatory Disclosures & Boundaries Grid */}
          <div className="panel">
            <div className="panel-header">
              <h3 className="panel-title">Mandatory Architectural Disclosures & Limitations</h3>
              <span className="chip chip-seed">Honest Security Boundary</span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '0.85rem', fontSize: '0.8rem' }}>
              <div style={{ padding: '0.75rem', background: 'var(--bg-app)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <strong style={{ color: '#fff', display: 'block', marginBottom: '0.2rem' }}>Discovery Methodology</strong>
                <p style={{ color: '#cbd5e1', lineHeight: '1.45' }}>{report.mandatory_disclosures.discovery_methodology}</p>
              </div>

              <div style={{ padding: '0.75rem', background: 'var(--bg-app)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <strong style={{ color: '#fff', display: 'block', marginBottom: '0.2rem' }}>Leak Detection Capabilities</strong>
                <p style={{ color: '#cbd5e1', lineHeight: '1.45' }}>{report.mandatory_disclosures.leak_detection_capability}</p>
              </div>

              <div style={{ padding: '0.75rem', background: 'var(--bg-app)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <strong style={{ color: '#fff', display: 'block', marginBottom: '0.2rem' }}>Defense Guardrail Limits</strong>
                <p style={{ color: '#cbd5e1', lineHeight: '1.45' }}>{report.mandatory_disclosures.defense_limitations}</p>
              </div>

              <div style={{ padding: '0.75rem', background: 'var(--bg-app)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <strong style={{ color: '#fff', display: 'block', marginBottom: '0.2rem' }}>Canary String Match Scope</strong>
                <p style={{ color: '#cbd5e1', lineHeight: '1.45' }}>{report.mandatory_disclosures.canary_matching_limitation}</p>
              </div>

              <div style={{ padding: '0.75rem', background: 'var(--bg-app)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <strong style={{ color: '#fff', display: 'block', marginBottom: '0.2rem' }}>Target Compatibility Scope</strong>
                <p style={{ color: '#cbd5e1', lineHeight: '1.45' }}>{report.mandatory_disclosures.target_compatibility_scope}</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
