import React, { useEffect, useState } from 'react';
import { TargetConfig } from '../types';
import { api } from '../api';
import { Target, CheckCircle, AlertOctagon, RefreshCw, Key, Shield, FileCode } from 'lucide-react';

interface Props {
  currentAssessmentId: string;
  currentTargetId: string | null;
  onTargetSelected: (targetId: string, targetName: string) => void;
}

export const TargetSetupView: React.FC<Props> = ({
  currentAssessmentId,
  currentTargetId,
  onTargetSelected,
}) => {
  const [configs, setConfigs] = useState<TargetConfig[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const fetchConfigs = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getTargetConfigs();
      setConfigs(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load target configurations');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchConfigs();
  }, []);

  const handleSelect = async (config: TargetConfig) => {
    if (!config.valid) return;
    setSubmitting(true);
    setError(null);
    setSuccessMsg(null);
    try {
      await api.assignTarget(currentAssessmentId, config.id);
      setSuccessMsg(`Target '${config.name}' assigned to assessment '${currentAssessmentId}'.`);
      onTargetSelected(config.id, config.name);
    } catch (err: any) {
      setError(err.message || 'Failed to assign target');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h2 className="page-title">
            <Target size={18} color="#00e5ff" /> Target Agent Configurations
          </h2>
          <p className="page-desc">
            Load and validate YAML configurations from <code className="mono">target/configs/</code>.
            Only strictly validated agent targets are eligible for automated testing.
          </p>
        </div>
        <button className="btn btn-secondary btn-sm" onClick={fetchConfigs} disabled={loading}>
          <RefreshCw size={12} className={loading ? 'animate-spin' : ''} /> Reload Configs
        </button>
      </div>

      {error && <div className="alert-banner alert-danger">{error}</div>}
      {successMsg && <div className="alert-banner alert-info">{successMsg}</div>}

      <div className="panel">
        <div className="panel-header">
          <div>
            <h3 className="panel-title">Available Target Configurations</h3>
            <p className="panel-subtitle">Parsed from repository file system</p>
          </div>
          <span className="mono" style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
            Found {configs.length} file(s)
          </span>
        </div>

        {loading ? (
          <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
            Parsing target configurations...
          </div>
        ) : configs.length === 0 ? (
          <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
            No target configurations found in <code className="mono">target/configs/</code>.
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Target ID</th>
                  <th>Display Name</th>
                  <th>Schema Status</th>
                  <th>Validation Message</th>
                  <th>Selection</th>
                </tr>
              </thead>
              <tbody>
                {configs.map((cfg) => {
                  const isCurrent = cfg.id === currentTargetId;
                  return (
                    <tr key={cfg.id} style={{ opacity: cfg.valid ? 1 : 0.65 }}>
                      <td className="mono" style={{ fontWeight: 600 }}>
                        {cfg.id}
                        {cfg.id === 'demo-company-assistant' && (
                          <span className="chip chip-seed" style={{ marginLeft: '0.45rem', fontSize: '0.62rem' }}>
                            Default Sample
                          </span>
                        )}
                      </td>
                      <td style={{ fontWeight: 500, color: '#fff' }}>{cfg.name}</td>
                      <td>
                        {cfg.valid ? (
                          <span className="chip chip-blocked">
                            <CheckCircle size={10} /> Valid
                          </span>
                        ) : (
                          <span className="chip chip-exploit">
                            <AlertOctagon size={10} /> Invalid
                          </span>
                        )}
                      </td>
                      <td style={{ color: cfg.valid ? 'var(--text-muted)' : '#f87171', fontSize: '0.78rem' }}>
                        {cfg.valid ? 'Passes all schema constraints' : cfg.validation_error}
                      </td>
                      <td>
                        <button
                          className={`btn ${isCurrent ? 'btn-secondary' : cfg.valid ? 'btn-primary' : 'btn-secondary'} btn-sm`}
                          disabled={!cfg.valid || submitting || isCurrent}
                          onClick={() => handleSelect(cfg)}
                          style={{
                            color: isCurrent ? '#10b981' : undefined,
                            borderColor: isCurrent ? 'rgba(16, 185, 129, 0.4)' : undefined,
                          }}
                        >
                          {isCurrent ? 'Currently Active' : cfg.valid ? 'Select Target' : 'Rejected'}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Target Specifications Detail */}
      <div className="panel">
        <div className="panel-header">
          <h3 className="panel-title">
            <FileCode size={15} /> Active Target Specifications (<code className="mono">demo-company-assistant</code>)
          </h3>
          <span className="chip chip-seed">Sandboxed Synthetic Agent</span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.85rem' }}>
          <div style={{ padding: '0.75rem', background: 'var(--bg-app)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-subtle)', textTransform: 'uppercase', display: 'block', marginBottom: '0.2rem' }}>
              Role Constraint
            </span>
            <strong style={{ color: '#fff', fontSize: '0.84rem' }}>support</strong>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginTop: '0.15rem' }}>
              Rate-limited to 5 customer records/run
            </span>
          </div>

          <div style={{ padding: '0.75rem', background: 'var(--bg-app)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-subtle)', textTransform: 'uppercase', display: 'block', marginBottom: '0.2rem' }}>
              Policy Reference
            </span>
            <strong className="mono" style={{ color: '#fff', fontSize: '0.84rem' }}>policy.yaml</strong>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginTop: '0.15rem' }}>
              Outbound email strictly restricted to @company.com
            </span>
          </div>

          <div style={{ padding: '0.75rem', background: 'var(--bg-app)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-subtle)', textTransform: 'uppercase', display: 'block', marginBottom: '0.2rem' }}>
              Synthetic Canary Token
            </span>
            <code className="mono" style={{ color: '#00e5ff', fontSize: '0.82rem' }}>
              CANARY_TOKEN_DEMO_SECRET_48291
            </code>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginTop: '0.15rem' }}>
              Used to track leakage in args and reply
            </span>
          </div>

          <div style={{ padding: '0.75rem', background: 'var(--bg-app)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-subtle)', textTransform: 'uppercase', display: 'block', marginBottom: '0.2rem' }}>
              Guard Fail-Mode
            </span>
            <strong style={{ color: '#10b981', fontSize: '0.84rem' }}>fail_closed</strong>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginTop: '0.15rem' }}>
              Unmatched tool calls blocked by default
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
