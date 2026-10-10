import React, { useState } from 'react';
import { ChainVerification } from '../types';
import { api } from '../api';
import { ShieldCheck, ShieldAlert, CheckCircle2, AlertOctagon, Lock, RefreshCw } from 'lucide-react';

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
      setError(err.message || 'Tamper simulation failed');
    } finally {
      setTestingTamper(false);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Check Evidence</h1>
          <p className="page-desc">
            Cryptographically verify that test records, tool calls, and verdicts have not been modified or tampered with.
          </p>
        </div>
      </div>

      {error && <div className="alert-banner alert-danger">{error}</div>}

      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Evidence Integrity Verification</h2>
            <p className="card-subtitle">SHA-256 cryptographic hash seal</p>
          </div>
        </div>

        <div style={{ padding: '0.5rem 0 1rem 0' }}>
          <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', marginBottom: '1.25rem', lineHeight: '1.5' }}>
            Every test action and finding is cryptographically chained.
            Verification recomputes each cryptographic hash from the first record to the latest.
            If any record or verdict was altered after the fact, the check will immediately flag the mismatch.
          </p>

          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            <button
              className="btn btn-primary btn-lg"
              onClick={handleVerify}
              disabled={verifying}
            >
              {verifying ? (
                <>
                  <RefreshCw size={15} className="animate-spin" /> Verifying Evidence...
                </>
              ) : (
                <>
                  <ShieldCheck size={16} /> Verify Evidence Chain
                </>
              )}
            </button>

            <button
              className="btn btn-secondary btn-lg"
              onClick={handleTamperTest}
              disabled={testingTamper}
            >
              {testingTamper ? (
                <>
                  <RefreshCw size={15} className="animate-spin" /> Testing Tamper Simulation...
                </>
              ) : (
                <>
                  <ShieldAlert size={16} /> Simulate Tamper Detection
                </>
              )}
            </button>
          </div>
        </div>

        {/* Verification Outcome */}
        {verification && (
          <div
            style={{
              padding: '1.25rem',
              backgroundColor: verification.verified ? 'var(--success-subtle)' : 'var(--danger-subtle)',
              borderRadius: 'var(--radius-md)',
              border: `1px solid ${verification.verified ? 'var(--success-border)' : 'var(--danger-border)'}`,
              marginTop: '1rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem', color: verification.verified ? 'var(--success)' : 'var(--danger)', fontWeight: 600, fontSize: '0.95rem' }}>
              {verification.verified ? <CheckCircle2 size={18} /> : <AlertOctagon size={18} />}
              {verification.verified ? 'Verified — All Evidence Authentic' : 'Verification Failed — Tampering Detected'}
            </div>

            <p style={{ fontSize: '0.86rem', color: 'var(--text-primary)', marginBottom: '0.75rem' }}>
              {verification.message}
            </p>

            <div style={{ display: 'flex', gap: '1.5rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              <div>
                Verified Blocks: <strong style={{ color: 'var(--text-primary)' }}>{verification.chain_length} blocks</strong>
              </div>
              {verification.last_block_hash && (
                <div>
                  Head Hash: <code className="mono" style={{ color: 'var(--text-primary)' }}>{verification.last_block_hash.slice(0, 24)}...</code>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Tamper Simulation Outcome */}
        {tamperResult && (
          <div
            style={{
              padding: '1.25rem',
              backgroundColor: 'var(--warning-subtle)',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--warning-border)',
              marginTop: '1rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem', color: 'var(--warning)', fontWeight: 600, fontSize: '0.92rem' }}>
              <ShieldAlert size={16} /> Tamper Detection Test on Disposable Copy
            </div>

            <p style={{ fontSize: '0.85rem', color: 'var(--text-primary)', marginBottom: '0.35rem' }}>
              {tamperResult.message}
            </p>
            <div style={{ fontSize: '0.78rem', color: 'var(--warning)' }}>
              Verified: Altering a single byte in the trace immediately invalidates the cryptographic seal.
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
