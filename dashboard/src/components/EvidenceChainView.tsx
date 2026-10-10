import React, { useState } from 'react';
import { ChainVerification } from '../types';
import { api } from '../api';
import { Lock, ShieldCheck, AlertOctagon, CheckCircle2, ShieldAlert, Hash, FileCode } from 'lucide-react';

interface Props {
  assessmentId: string;
}

export const EvidenceChainView: React.FC<Props> = ({ assessmentId }) => {
  const [verifying, setVerifying] = useState<boolean>(false);
  const [verification, setVerification] = useState<ChainVerification | null>(null);
  const [tamperResult, setTamperResult] = useState<any | null>(null);
  const [testingTamper, setTestingTamper] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const handleVerify = async () => {
    setVerifying(true);
    setError(null);
    setTamperResult(null);
    try {
      const res = await api.verifyChain(assessmentId);
      setVerification(res);
    } catch (err: any) {
      setError(err.message || 'Evidence verification failed');
    } finally {
      setVerifying(false);
    }
  };

  const handleTamperTest = async () => {
    setTestingTamper(true);
    setError(null);
    try {
      const res = await api.runTamperTest(assessmentId);
      setTamperResult(res);
    } catch (err: any) {
      setError(err.message || 'Tamper test failed');
    } finally {
      setTestingTamper(false);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h2 className="page-title">
            <Lock size={18} color="#00e5ff" /> Cryptographic Evidence Integrity Chain
          </h2>
          <p className="page-desc">
            Forensic audit trail: every execution step, tool argument, and verdict is linked via a SHA-256 hash chain to prevent tampering.
          </p>
        </div>
      </div>

      {error && <div className="alert-banner alert-danger">{error}</div>}

      <div className="panel">
        <div className="panel-header">
          <div>
            <h3 className="panel-title">Hash Chain Audit Controller</h3>
            <p className="panel-subtitle">Session: <code className="mono">{assessmentId}</code></p>
          </div>
          <span className="chip chip-seed">SHA-256 Linked Ledger</span>
        </div>

        <div style={{ padding: '0.5rem 0 1rem 0' }}>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '1rem', lineHeight: '1.5' }}>
            Verification recomputes each block's cryptographic digest from the genesis seed (<code className="mono">0x000...</code>) to the latest entry.
            Any retroactive modification to past run steps or findings invalidates the chain, ensuring evidence integrity.
          </p>

          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            <button
              className="btn btn-primary"
              onClick={handleVerify}
              disabled={verifying}
              style={{ padding: '0.55rem 1.3rem', fontSize: '0.82rem' }}
            >
              <ShieldCheck size={15} /> {verifying ? 'Recomputing Hash Chain...' : 'Verify Evidence Chain'}
            </button>

            <button
              className="btn btn-secondary"
              onClick={handleTamperTest}
              disabled={testingTamper}
              style={{ padding: '0.55rem 1.3rem', fontSize: '0.82rem' }}
            >
              <ShieldAlert size={15} /> {testingTamper ? 'Running Tamper Test...' : 'Simulate Tamper Detection'}
            </button>
          </div>
        </div>

        {/* Verification Result */}
        {verification && (
          <div
            style={{
              padding: '1rem',
              backgroundColor: verification.verified ? 'var(--bg-surface-elevated)' : 'var(--rose-bg)',
              borderRadius: '5px',
              border: verification.verified ? '1px solid var(--emerald-border)' : '1px solid var(--rose-border)',
              marginTop: '0.75rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem', color: verification.verified ? '#34d399' : '#fb7185', fontWeight: 600 }}>
              {verification.verified ? <CheckCircle2 size={16} /> : <AlertOctagon size={16} />}
              {verification.verified ? 'Verification Passed — Integrity Confirmed' : 'Integrity Mismatch Detected'}
            </div>

            <p style={{ fontSize: '0.82rem', color: '#e2e8f0', marginBottom: '0.6rem' }}>
              <strong>Result: </strong> {verification.message}
            </p>

            <div style={{ display: 'flex', gap: '1.5rem', fontSize: '0.76rem', color: 'var(--text-muted)' }}>
              <span>Verified Blocks: <strong className="mono" style={{ color: '#fff' }}>{verification.chain_length} blocks</strong></span>
              {verification.last_block_hash && (
                <span>Head Hash: <code className="mono" style={{ color: '#00e5ff' }}>{verification.last_block_hash.slice(0, 20)}...</code></span>
              )}
            </div>
          </div>
        )}

        {/* Disposable Tamper Demonstration Result */}
        {tamperResult && (
          <div
            style={{
              padding: '1rem',
              backgroundColor: 'var(--amber-bg)',
              borderRadius: '5px',
              border: '1px solid var(--amber-border)',
              marginTop: '0.75rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem', color: '#fde68a', fontWeight: 600, fontSize: '0.88rem' }}>
              <ShieldAlert size={15} /> Tamper Resistance Verified on Disposable Copy
            </div>

            <p style={{ fontSize: '0.8rem', color: '#fde68a', marginBottom: '0.3rem' }}>
              {tamperResult.message}
            </p>

            <span style={{ fontSize: '0.72rem', color: '#facc15' }}>
              Notice: The demonstration altered one character in a disposable memory copy. The actual saved evidence chain remained untouched.
            </span>
          </div>
        )}
      </div>

      {/* Cryptographic Specification */}
      <div className="panel">
        <h4 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
          Cryptographic Hash Chain Specification
        </h4>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', lineHeight: '1.5', marginBottom: '0.5rem' }}>
          Each block links to its predecessor via <code className="mono" style={{ color: '#00e5ff' }}>block_hash = sha256(prev_hash + json(record))</code>.
          Genesis block links to <code className="mono">0x000...</code>. The phrase <em>“unmodified since logging”</em> is only asserted when every link in the chain recomputes to its recorded digest.
        </p>
      </div>
    </div>
  );
};
