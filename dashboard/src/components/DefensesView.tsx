import React, { useEffect, useState } from 'react';
import { Defense, DefenseCandidate, EvolutionResult, PolicyVersion } from '../types';
import { api } from '../api';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  RotateCcw,
  Sparkles,
  XCircle,
  History,
  FileCode,
  ArrowRight,
} from 'lucide-react';

interface Props {
  assessmentId: string;
  defenses: Defense[];
  onDefensesUpdated: (defenses: Defense[]) => void;
  onStateRefresh?: () => void;
}

export const DefensesView: React.FC<Props> = ({
  assessmentId,
  defenses,
  onDefensesUpdated,
  onStateRefresh,
}) => {
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Evolution state
  const [isEvolving, setIsEvolving] = useState(false);
  const [isRunningLoop, setIsRunningLoop] = useState(false);
  const [isRollingBack, setIsRollingBack] = useState(false);
  const [activeVersion, setActiveVersion] = useState<PolicyVersion | null>(null);
  const [history, setHistory] = useState<PolicyVersion[]>([]);
  const [candidates, setCandidates] = useState<DefenseCandidate[]>([]);
  const [selectedCandidate, setSelectedCandidate] = useState<DefenseCandidate | null>(null);

  const loadDefenseState = async () => {
    try {
      const histData = await api.getDefenseHistory(assessmentId);
      setActiveVersion(histData.active_version);
      setHistory(histData.history || []);

      const cands = await api.getDefenseCandidates(assessmentId);
      setCandidates(cands || []);
      if (cands && cands.length > 0) {
        setSelectedCandidate(cands[0]);
      }
    } catch {
      // Quiet fail if not initialized yet
    }
  };

  useEffect(() => {
    loadDefenseState();
  }, [assessmentId]);

  const handleToggle = async (d: Defense) => {
    if (d.is_stub) {
      setError(`'${d.name}' is a development stub and cannot be toggled.`);
      return;
    }

    setTogglingId(d.id);
    setError(null);
    setSuccessMsg(null);
    try {
      const updated = await api.toggleDefense(assessmentId, d.id);
      const newDefenses = defenses.map((item) => (item.id === updated.id ? updated : item));
      onDefensesUpdated(newDefenses);
      onStateRefresh?.();
    } catch (err: any) {
      setError(err.message || 'Failed to update protection status');
    } finally {
      setTogglingId(null);
    }
  };

  const handleEvolve = async () => {
    setIsEvolving(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const result: EvolutionResult = await api.evolveDefenses(assessmentId);
      setSuccessMsg(
        `Adaptive Defense Evolution complete: ${result.candidates_accepted} candidate(s) accepted and promoted to ${result.final_version_id} with 100% legitimate task pass rate!`
      );
      // Reload updated defenses and history
      const updatedDefs = await api.getDefenses(assessmentId);
      onDefensesUpdated(updatedDefs);
      await loadDefenseState();
      onStateRefresh?.();
    } catch (err: any) {
      setError(err.message || 'Failed to run defense evolution');
    } finally {
      setIsEvolving(false);
    }
  };

  const handleAdaptiveLoop = async () => {
    setIsRunningLoop(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const result = await api.runAdaptiveLoop(assessmentId, 5, 'deterministic_offline', false);
      setSuccessMsg(
        `Multi-round adaptive red-team loop complete (${result.total_rounds} rounds, termination: ${result.termination_reason}). Final active version: ${result.final_active_version_id}!`
      );
      const updatedDefs = await api.getDefenses(assessmentId);
      onDefensesUpdated(updatedDefs);
      await loadDefenseState();
      onStateRefresh?.();
    } catch (err: any) {
      setError(err.message || 'Failed to run adaptive red-team loop');
    } finally {
      setIsRunningLoop(false);
    }
  };

  const handleRollback = async () => {
    setIsRollingBack(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const restored = await api.rollbackDefense(assessmentId);
      setSuccessMsg(`Successfully rolled back defense policy to version ${restored.version_id}.`);
      const updatedDefs = await api.getDefenses(assessmentId);
      onDefensesUpdated(updatedDefs);
      await loadDefenseState();
      onStateRefresh?.();
    } catch (err: any) {
      setError(err.message || 'Failed to rollback defense');
    } finally {
      setIsRollingBack(false);
    }
  };

  const isEvolved = activeVersion && activeVersion.version_id !== 'v1.0.0';

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Defenses & Adaptive Protection</h1>
          <p className="page-desc">
            Guardrails and dynamic policy evolution: candidate policies are tested in isolation against exploits and normal customer tasks before promotion.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap' }}>
          {isEvolved && (
            <button
              className="btn btn-secondary btn-sm"
              disabled={isRollingBack}
              onClick={handleRollback}
              title="Roll back active policy to previous version"
            >
              <RotateCcw size={14} /> {isRollingBack ? 'Rolling back...' : 'Rollback Policy'}
            </button>
          )}
          <button
            className="btn btn-secondary btn-sm"
            disabled={isEvolving || isRunningLoop}
            onClick={handleEvolve}
            style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}
          >
            <Sparkles size={14} color="var(--primary)" />
            {isEvolving ? 'Evaluating Candidates...' : 'Evolve Defenses'}
          </button>
          <button
            className="btn btn-primary btn-sm"
            disabled={isRunningLoop || isEvolving}
            onClick={handleAdaptiveLoop}
            style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}
            title="Execute multi-round adaptive red-team and defense learning loop"
          >
            <ShieldCheck size={14} />
            {isRunningLoop ? 'Running Loop...' : 'Run Adaptive Loop'}
          </button>
        </div>
      </div>

      {error && <div className="alert-banner alert-warning">{error}</div>}
      {successMsg && (
        <div className="alert-banner" style={{ background: '#064e3b', borderColor: '#059669', color: '#a7f3d0' }}>
          <CheckCircle2 size={16} style={{ marginRight: '0.4rem', verticalAlign: 'text-bottom' }} />
          {successMsg}
        </div>
      )}

      {/* Dynamic Evolution Status Banner */}
      <div
        className="card"
        style={{
          borderLeft: isEvolved ? '4px solid var(--success)' : '4px solid var(--primary)',
          backgroundColor: isEvolved ? 'var(--success-subtle)' : 'var(--bg-surface)',
          marginBottom: '1.25rem',
          padding: '1rem 1.25rem',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.8rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.25rem' }}>
              <span style={{ fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', fontWeight: 600 }}>
                Active Defense Policy Version:
              </span>
              <span className="badge badge-success" style={{ fontSize: '0.82rem', fontWeight: 600 }}>
                {activeVersion ? activeVersion.version_id : 'v1.0.0'}
              </span>
              {isEvolved ? (
                <span className="badge badge-success">Dynamic / Evolved</span>
              ) : (
                <span className="badge badge-neutral">Baseline Configuration</span>
              )}
            </div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.84rem', margin: 0 }}>
              {activeVersion?.rationale || 'Baseline security policies active from target YAML specification.'}
            </p>
          </div>
          <div style={{ display: 'flex', gap: '1.25rem', alignItems: 'center' }}>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Candidates Evaluated</div>
              <div className="mono" style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--primary)' }}>
                {candidates.length}
              </div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Policy Versions</div>
              <div className="mono" style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--success)' }}>
                {history.length || 1}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Configured Guardrails</h2>
            <p className="card-subtitle">Active and planned security guards for the tested agent</p>
          </div>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            {defenses.length} guardrail(s) configured
          </span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {defenses.map((d) => {
            const isEnforced = d.status === 'enforced';
            const isStub = d.is_stub || d.status === 'stub';

            return (
              <div
                key={d.id}
                style={{
                  padding: '1.25rem',
                  borderRadius: 'var(--radius-md)',
                  backgroundColor: 'var(--bg-surface)',
                  border: isStub
                    ? '1px solid var(--warning-border)'
                    : isEnforced
                    ? '1px solid var(--success-border)'
                    : '1px solid var(--border-default)',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '0.65rem' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                      <strong style={{ fontSize: '0.98rem', color: 'var(--text-primary)' }}>
                        {d.name}
                      </strong>
                      {isStub ? (
                        <span className="badge badge-warning">Development Stub</span>
                      ) : isEnforced ? (
                        <span className="badge badge-success">
                          <CheckCircle2 size={12} /> Active / Enforced
                        </span>
                      ) : (
                        <span className="badge badge-neutral">Disabled</span>
                      )}
                    </div>
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      Interception Target: <strong style={{ color: 'var(--text-secondary)' }}>{d.target_component}</strong>
                      {' • '}
                      Mitigates Rule: <code className="mono">{d.mitigation_rule}</code>
                    </div>
                  </div>

                  {!isStub ? (
                    <button
                      className={`btn ${isEnforced ? 'btn-secondary' : 'btn-primary'} btn-sm`}
                      disabled={togglingId === d.id}
                      onClick={() => handleToggle(d)}
                      style={{ minWidth: '120px' }}
                    >
                      {togglingId === d.id ? 'Updating...' : isEnforced ? 'Disable Guard' : 'Enable Guard'}
                    </button>
                  ) : (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                      <span className="badge badge-warning" style={{ fontSize: '0.74rem' }}>
                        Stub / Roadmap
                      </span>
                      <button
                        className="btn btn-secondary btn-sm"
                        onClick={handleEvolve}
                        disabled={isEvolving || isRunningLoop}
                        title="Run defense evolution to generate active candidate and replace stub"
                        style={{ minWidth: '110px' }}
                      >
                        <Sparkles size={13} style={{ marginRight: '0.3rem', verticalAlign: '-1px' }} />
                        Evolve Guard
                      </button>
                    </div>
                  )}
                </div>

                <p style={{ fontSize: '0.86rem', color: 'var(--text-secondary)', lineHeight: '1.45', marginBottom: d.denial_message ? '0.65rem' : '0' }}>
                  {d.description}
                </p>

                {d.denial_message && (
                  <div
                    style={{
                      padding: '0.5rem 0.75rem',
                      backgroundColor: 'var(--bg-surface-subtle)',
                      borderRadius: 'var(--radius-sm)',
                      border: '1px solid var(--border-light)',
                      fontSize: '0.8rem',
                    }}
                  >
                    <span style={{ color: 'var(--text-muted)' }}>Denial Message: </span>
                    <span className="mono" style={{ color: 'var(--danger)', fontWeight: 500 }}>
                      "{d.denial_message}"
                    </span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Guardrail Scope Note */}
      <div
        className="card"
        style={{
          backgroundColor: 'var(--bg-surface-subtle)',
          marginTop: '1rem',
          padding: '0.85rem 1.15rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem',
        }}
      >
        <Shield size={18} color="var(--primary)" style={{ flexShrink: 0 }} />
        <div style={{ fontSize: '0.83rem', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
          <strong style={{ color: 'var(--text-primary)' }}>Defense Coverage: </strong>
          Tool guards (<strong>D1</strong>, <strong>D2</strong>) block unauthorized tool arguments and untrusted memory writes.
          The conversational filter (<strong>D3</strong>) stops private secrets from leaking in final replies.
        </div>
      </div>

      {/* Candidate Evaluation & Gatekeeper Scorecards */}
      {candidates.length > 0 && (
        <div className="card" style={{ marginTop: '1.25rem' }}>
          <div className="card-header">
            <div>
              <h2 className="card-title">
                <ShieldCheck size={16} color="var(--success)" style={{ display: 'inline', marginRight: '0.4rem', verticalAlign: '-2px' }} />
                Proposed Defense Candidates & Isolated Scorecards
              </h2>
              <p className="card-subtitle">
                Each candidate was tested in an isolated in-memory sandbox against 8 legitimate tasks before activation.
              </p>
            </div>
            <span className="badge badge-neutral">
              Gatekeeper: 100% Legitimate Pass Required
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: candidates.length > 1 ? '1fr 2fr' : '1fr', gap: '1rem' }}>
            {/* Candidate List selector */}
            {candidates.length > 1 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {candidates.map((c) => {
                  const isSel = selectedCandidate?.candidate_id === c.candidate_id;
                  const isAcc = c.status === 'accepted';
                  return (
                    <div
                      key={c.candidate_id}
                      onClick={() => setSelectedCandidate(c)}
                      style={{
                        padding: '0.75rem',
                        borderRadius: 'var(--radius-sm)',
                        cursor: 'pointer',
                        border: isSel ? '1px solid var(--primary)' : '1px solid var(--border-default)',
                        backgroundColor: isSel ? 'var(--primary-subtle)' : 'var(--bg-surface-subtle)',
                        transition: 'all 0.15s ease',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.2rem' }}>
                        <span className="mono" style={{ fontSize: '0.8rem', color: isSel ? 'var(--primary)' : 'var(--text-primary)', fontWeight: 600 }}>
                          {c.candidate_id}
                        </span>
                        <span className={`badge ${isAcc ? 'badge-success' : 'badge-neutral'}`} style={{ fontSize: '0.68rem' }}>
                          {c.status.toUpperCase()}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        Trigger: {c.trigger_finding?.rule_fired || 'Vulnerability Finding'}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {/* Selected Candidate Detailed Inspection */}
            {selectedCandidate && (
              <div style={{ padding: '1rem', background: 'var(--bg-surface-subtle)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-default)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '0.8rem' }}>
                  <div>
                    <h3 style={{ color: 'var(--text-primary)', fontSize: '0.95rem', fontWeight: 600, marginBottom: '0.2rem' }}>
                      Candidate {selectedCandidate.candidate_id}
                    </h3>
                    <span style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                      Base Version: <strong style={{ color: 'var(--primary)' }}>{selectedCandidate.base_version_id}</strong> • Trigger:{' '}
                      <code className="mono">{selectedCandidate.trigger_finding?.rule_fired}</code>
                    </span>
                  </div>
                  <span
                    className={`badge ${
                      selectedCandidate.scorecard?.gatekeeper_verdict === 'ACCEPTED' ? 'badge-success' : 'badge-danger'
                    }`}
                  >
                    Gatekeeper: {selectedCandidate.scorecard?.gatekeeper_verdict || selectedCandidate.status.toUpperCase()}
                  </span>
                </div>

                {/* Scorecard metrics */}
                {selectedCandidate.scorecard && (
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
                      gap: '0.6rem',
                      marginBottom: '0.9rem',
                      padding: '0.75rem',
                      background: 'var(--bg-surface)',
                      borderRadius: 'var(--radius-sm)',
                      border: '1px solid var(--border-default)',
                    }}
                  >
                    <div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Exploit Mitigated</div>
                      <div style={{ fontWeight: 600, color: selectedCandidate.scorecard.exploit_mitigated ? 'var(--success)' : 'var(--danger)' }}>
                        {selectedCandidate.scorecard.exploit_mitigated ? 'Yes (Blocked)' : 'No'}
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Adaptive Resilience</div>
                      <div style={{ fontWeight: 600, color: selectedCandidate.scorecard.adaptive_exploit_mitigated ? 'var(--success)' : 'var(--warning)' }}>
                        {selectedCandidate.scorecard.adaptive_exploit_mitigated ? 'Resilient' : 'Vulnerable'}
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Legitimate Tasks</div>
                      <div style={{ fontWeight: 600, color: 'var(--success)' }}>
                        {selectedCandidate.scorecard.legit_tasks_passed} / {selectedCandidate.scorecard.legit_tasks_total} (100%)
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Eval Latency</div>
                      <div className="mono" style={{ fontWeight: 600, color: 'var(--primary)' }}>
                        {selectedCandidate.scorecard.latency_ms} ms
                      </div>
                    </div>
                  </div>
                )}

                {/* Policy Diff */}
                <div style={{ marginBottom: '0.8rem' }}>
                  <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                    <FileCode size={14} /> Proposed Policy Modifications (Diff)
                  </div>
                  <pre
                    className="mono"
                    style={{
                      background: 'var(--bg-surface)',
                      padding: '0.65rem',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: '0.76rem',
                      color: 'var(--text-primary)',
                      whiteSpace: 'pre-wrap',
                      border: '1px solid var(--border-default)',
                    }}
                  >
                    {selectedCandidate.diff?.summary || 'No policy modifications'}
                  </pre>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Policy Version History */}
      {history.length > 0 && (
        <div className="card" style={{ marginTop: '1.25rem' }}>
          <div className="card-header">
            <div>
              <h2 className="card-title">
                <History size={16} color="var(--primary)" style={{ display: 'inline', marginRight: '0.4rem', verticalAlign: '-2px' }} />
                Policy Version History & Audit Trail
              </h2>
              <p className="card-subtitle">Immutable log of active, candidate, and historic security policies</p>
            </div>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              {history.length} version snapshot(s)
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
            {history.map((v) => {
              const isActive = v.status === 'active';
              return (
                <div
                  key={v.version_id}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '0.75rem 1rem',
                    background: isActive ? 'var(--success-subtle)' : 'var(--bg-surface-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    border: isActive ? '1px solid var(--success-border)' : '1px solid var(--border-default)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.8rem' }}>
                    <span className="mono" style={{ fontWeight: 700, color: isActive ? 'var(--success)' : 'var(--text-primary)' }}>
                      {v.version_id}
                    </span>
                    {isActive ? (
                      <span className="badge badge-success">Active</span>
                    ) : v.status === 'rolled_back' ? (
                      <span className="badge badge-neutral">Rolled Back</span>
                    ) : (
                      <span className="badge badge-neutral">Archived</span>
                    )}
                    <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                      {v.rationale}
                    </span>
                  </div>
                  <div className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    {v.created_at ? new Date(v.created_at).toLocaleTimeString() : 'Baseline'}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
