import React, { useEffect, useState } from 'react';
import { TargetConfig } from '../types';
import { api } from '../api';
import { Target, CheckCircle2, AlertCircle, RefreshCw } from 'lucide-react';

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
      setSuccessMsg(`Target '${config.name}' is now active for this assessment.`);
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
          <h1 className="page-title">Targets</h1>
          <p className="page-desc">
            Choose the AI agent configuration you want to test. Target settings define allowed tools, boundaries, and instructions.
          </p>
        </div>
        <button className="btn btn-secondary btn-sm" onClick={fetchConfigs} disabled={loading}>
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} /> Refresh Targets
        </button>
      </div>

      {error && <div className="alert-banner alert-danger">{error}</div>}
      {successMsg && <div className="alert-banner alert-success">{successMsg}</div>}

      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Configured Agents</h2>
            <p className="card-subtitle">Verified agent configurations ready for testing</p>
          </div>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            {configs.length} available target(s)
          </span>
        </div>

        {loading ? (
          <div style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
            Loading target configurations...
          </div>
        ) : configs.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-title">No targets found</div>
            <div className="empty-state-desc">
              No valid agent configuration files found in the target directory.
            </div>
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Agent Name</th>
                  <th>Configuration ID</th>
                  <th>Status</th>
                  <th>Validation</th>
                  <th style={{ textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {configs.map((cfg) => {
                  const isCurrent = cfg.id === currentTargetId;
                  return (
                    <tr key={cfg.id} style={{ opacity: cfg.valid ? 1 : 0.7 }}>
                      <td>
                        <strong style={{ color: 'var(--text-primary)' }}>{cfg.name}</strong>
                      </td>
                      <td className="mono" style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                        {cfg.id}
                      </td>
                      <td>
                        {cfg.valid ? (
                          <span className="badge badge-success">
                            <CheckCircle2 size={12} /> Valid configuration
                          </span>
                        ) : (
                          <span className="badge badge-danger">
                            <AlertCircle size={12} /> Invalid configuration
                          </span>
                        )}
                      </td>
                      <td style={{ fontSize: '0.82rem', color: cfg.valid ? 'var(--text-muted)' : 'var(--danger)' }}>
                        {cfg.valid ? 'Ready for security testing' : cfg.validation_error}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          className={`btn ${isCurrent ? 'btn-secondary' : cfg.valid ? 'btn-primary' : 'btn-secondary'} btn-sm`}
                          disabled={!cfg.valid || submitting || isCurrent}
                          onClick={() => handleSelect(cfg)}
                          style={{
                            color: isCurrent ? 'var(--success)' : undefined,
                            borderColor: isCurrent ? 'var(--success-border)' : undefined,
                          }}
                        >
                          {isCurrent ? 'Currently Active' : cfg.valid ? 'Select Agent' : 'Invalid'}
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
    </div>
  );
};
