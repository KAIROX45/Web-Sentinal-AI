import React, { useState } from 'react';
import { Link2, ShieldCheck, AlertOctagon, ExternalLink, ArrowRight } from 'lucide-react';
import { recordThreatOnChain, verifyReportOnChain } from '../services/api';
import { BlockchainVerification } from '../types';
import { truncateHash } from '../utils/formatters';

interface VerificationBadgeProps {
  scanId: string;
  target: string;
  threatType: string;
  riskLevel: string;
  riskScore: number;
  findingsDigest: string;
  canonicalHash: string;
  initialTxHash?: string | null;
}

export const VerificationBadge: React.FC<VerificationBadgeProps> = ({
  scanId,
  target,
  threatType,
  riskLevel,
  riskScore,
  findingsDigest,
  canonicalHash,
  initialTxHash: _initialTxHash,
}) => {
  const [anchoring, setAnchoring] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<BlockchainVerification | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleAnchor = async () => {
    setAnchoring(true);
    setErrorMsg(null);
    try {
      const res = await recordThreatOnChain({
        scan_id: scanId,
        target,
        threat_type: threatType,
        risk_level: riskLevel,
        risk_score: riskScore,
        findings_digest: findingsDigest,
      });
      setVerificationResult(res);
    } catch (e: any) {
      setErrorMsg(e?.response?.data?.detail || e.message || 'Anchoring failed');
    } finally {
      setAnchoring(false);
    }
  };

  const handleVerify = async () => {
    setVerifying(true);
    setErrorMsg(null);
    try {
      const res = await verifyReportOnChain(canonicalHash, {
        scan_id: scanId,
        target,
        threat_type: threatType,
        risk_level: riskLevel,
        risk_score: riskScore,
        findings_digest: findingsDigest,
      });
      setVerificationResult(res);
    } catch (e: any) {
      setErrorMsg(e?.response?.data?.detail || e.message || 'Verification failed');
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[#985E6D]/20 border border-[#985E6D]/40 flex items-center justify-center text-[#e58a9d]">
            <Link2 className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white tracking-wide">
              Blockchain Threat Ledger Verification
            </h3>
            <p className="text-xs text-[#98878F]">
              Canonical SHA-256 fingerprint registration on EVM immutable state tree.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handleAnchor}
            disabled={anchoring}
            className="px-4 py-2 rounded-xl bg-[#985E6D] hover:bg-[#ad6d7d] text-white text-xs font-semibold shadow-[0_0_12px_rgba(152,94,109,0.35)] disabled:opacity-50 transition-all cursor-pointer flex items-center gap-1.5"
          >
            {anchoring ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                <span>Anchoring...</span>
              </>
            ) : (
              <>
                <span>Publish to Chain</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </>
            )}
          </button>

          <button
            type="button"
            onClick={handleVerify}
            disabled={verifying}
            className="px-4 py-2 rounded-xl bg-[#192034] hover:bg-[#494E6B]/30 border border-[#494E6B]/50 text-white text-xs font-medium transition-colors cursor-pointer flex items-center gap-1.5"
          >
            {verifying ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-[#98878F] border-t-transparent rounded-full animate-spin" />
                <span>Verifying...</span>
              </>
            ) : (
              <span>Verify Integrity</span>
            )}
          </button>
        </div>
      </div>

      {/* Hash details bar */}
      <div className="p-3.5 rounded-xl bg-[#192034]/70 border border-[#494E6B]/30 flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
        <div>
          <span className="text-[#98878F]">Digest: </span>
          <span className="text-[#c28190] font-semibold">{canonicalHash}</span>
        </div>
        <span className="text-[10px] text-[#98878F]">Algorithm: SHA-256 (Canonical JSON)</span>
      </div>

      {errorMsg && (
        <div className="p-3 rounded-xl bg-[#985E6D]/20 border border-[#985E6D]/40 text-[#e58a9d] text-xs flex items-center gap-2">
          <AlertOctagon className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Verification Results Panel */}
      {verificationResult && (
        <div className={`p-4 rounded-xl border transition-all ${
          verificationResult.is_tamper_free
            ? 'bg-[#3f6e62]/20 border-[#3f6e62]/60 text-white'
            : 'bg-[#985E6D]/25 border-[#985E6D] text-white'
        }`}>
          <div className="flex items-center gap-2 mb-2">
            {verificationResult.is_tamper_free ? (
              <ShieldCheck className="w-5 h-5 text-[#85c9b7]" />
            ) : (
              <AlertOctagon className="w-5 h-5 text-[#e58a9d]" />
            )}
            <span className="text-sm font-bold">
              {verificationResult.is_tamper_free
                ? 'Report Integrity Cryptographically Verified'
                : 'Tamper Alert Detected'}
            </span>
            {verificationResult.is_simulated && (
              <span className="ml-auto inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-amber-500/20 text-amber-300 border border-amber-500/40">
                Local Simulation Mode
              </span>
            )}
          </div>

          <p className="text-xs text-[#c2b5bc] leading-relaxed mb-3">
            {verificationResult.verification_message}
          </p>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-white/10 text-[11px] font-mono">
            <div>
              <span className="text-[#98878F] block">Network</span>
              <span className="text-white font-medium">{verificationResult.network}</span>
            </div>
            <div>
              <span className="text-[#98878F] block">Block Height</span>
              <span className="text-white font-medium">#{verificationResult.block_number}</span>
            </div>
            <div>
              <span className="text-[#98878F] block">Transaction</span>
              <span className="text-[#c28190] font-medium">
                {verificationResult.tx_hash.startsWith('SIM-') ? (
                  <span>{truncateHash(verificationResult.tx_hash, 8)} (Local)</span>
                ) : (
                  <a
                    href={`https://sepolia.etherscan.io/tx/${verificationResult.tx_hash}`}
                    target="_blank"
                    rel="noreferrer"
                    className="hover:underline inline-flex items-center gap-1"
                  >
                    {truncateHash(verificationResult.tx_hash, 6)}
                    <ExternalLink className="w-3 h-3" />
                  </a>
                )}
              </span>
            </div>
            <div>
              <span className="text-[#98878F] block">Reporter Wallet</span>
              <span className="text-[#c2b5bc] font-medium">{truncateHash(verificationResult.reporter_address, 4)}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

