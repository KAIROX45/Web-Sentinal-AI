import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  AlertOctagon,
  ExternalLink,
  Layers,
  ArrowRight
} from 'lucide-react';
import { getBlockchainStatus, verifyReportOnChain, getBlockchainRecords } from '../services/api';
import { BlockchainStatus, BlockchainVerification } from '../types';
import { truncateHash, formatDate } from '../utils/formatters';

export const BlockchainVerificationPage: React.FC = () => {
  const [status, setStatus] = useState<BlockchainStatus | null>(null);
  const [recentRecords, setRecentRecords] = useState<any[]>([]);
  const [hashInput, setHashInput] = useState('');
  const [payloadInput, setPayloadInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<BlockchainVerification | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    getBlockchainStatus().then(setStatus).catch(() => {});
    getBlockchainRecords().then(setRecentRecords).catch(() => {});
  }, []);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!hashInput.trim()) return;

    setLoading(true);
    setErrorMsg(null);
    setResult(null);

    let parsedPayload: Record<string, unknown> | undefined = undefined;
    if (payloadInput.trim()) {
      try {
        parsedPayload = JSON.parse(payloadInput.trim());
      } catch (err: any) {
        setErrorMsg('Invalid payload JSON format: ' + err.message);
        setLoading(false);
        return;
      }
    }

    try {
      const data = await verifyReportOnChain(hashInput.trim(), parsedPayload);
      setResult(data);
    } catch (err: any) {
      setErrorMsg(err?.response?.data?.detail || err.message || 'Verification failed');
    } finally {
      setLoading(false);
    }
  };

  const handleTestTamper = () => {
    // Demo report hash
    const sampleHash = recentRecords[0]?.report_hash || '0x4f8a9d8e7b6c5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f';
    setHashInput(sampleHash);
    // Modified payload to trigger tamper alert
    setPayloadInput(JSON.stringify({
      target: 'tampered-domain.com',
      scan_type: 'url',
      risk_level: 'LOW',
      findings_digest: 'Altered content to test cryptographic tamper detection'
    }, null, 2));
  };

  return (
    <div className="space-y-8 pb-12">
      <div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          Blockchain Threat Verification Registry
        </h1>
        <p className="text-xs sm:text-sm text-[#98878F] mt-1">
          Cryptographic tamper detection and immutable SHA-256 fingerprint auditing powered by EVM smart contracts.
        </p>
      </div>

      {/* Network Connectivity & Contract Details */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-5 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/35 backdrop-blur-xl">
          <span className="text-[#98878F] text-[10px] font-mono uppercase block mb-1">Active Ledger</span>
          <div className="flex items-center gap-2">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                status?.connection_status === 'LIVE_SEPOLIA_DEPLOYED'
                  ? 'bg-[#85c9b7] animate-pulse'
                  : status?.connection_status === 'LIVE_SEPOLIA_UNDEPLOYED'
                  ? 'bg-amber-400'
                  : 'bg-[#98878F]'
              }`}
            />
            <h3 className="text-base font-bold text-white font-mono">{status?.network || 'EVM Cryptographic Ledger'}</h3>
            {status?.is_simulated && (
              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                SIMULATION
              </span>
            )}
          </div>
          <span className="text-[11px] text-[#98878F] mt-1 block">
            {status?.status_detail || (status?.is_live_sepolia ? 'Sepolia Testnet Connected' : 'Local Verified EVM Ledger Active')}
          </span>
        </div>

        <div className="p-5 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/35 backdrop-blur-xl">
          <span className="text-[#98878F] text-[10px] font-mono uppercase block mb-1">Smart Contract</span>
          <div className="text-xs font-mono font-bold text-white truncate max-w-full">
            {status?.smart_contract_address || 'Local Ledger (Contract Not Deployed)'}
          </div>
          <div className="flex items-center gap-2 mt-1">
            <span className="text-[11px] text-[#c28190] block font-mono">
              {status?.contract_bytecode_verified
                ? 'Bytecode Verified on Chain'
                : status?.smart_contract_address
                ? 'Solidity v0.8.20 Registry'
                : 'Local Cryptographic Ledger'}
            </span>
            {status?.contract_bytecode_verified && (
              <span className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                VERIFIED
              </span>
            )}
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/35 backdrop-blur-xl">
          <span className="text-[#98878F] text-[10px] font-mono uppercase block mb-1">Total Fingerprints Anchored</span>
          <div className="text-2xl font-extrabold text-white font-mono">
            {status?.total_reports_anchored ?? recentRecords.length}
          </div>
          <span className="text-[11px] text-[#85c9b7] mt-1 block">Zero PII / Strictly Canonical SHA-256</span>
        </div>
      </div>

      {/* Verify Report Form */}
      <form onSubmit={handleVerify} className="p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl space-y-4">
        <div className="flex items-center justify-between border-b border-[#494E6B]/30 pb-3">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-[#985E6D]" />
            <span>Verify Threat Investigation Integrity</span>
          </h2>

          <button
            type="button"
            onClick={handleTestTamper}
            className="text-xs text-[#e58a9d] hover:underline font-mono"
          >
            Load Tamper Simulation Scenario
          </button>
        </div>

        <div>
          <label className="block text-[#98878F] mb-1 font-mono uppercase text-[10px]">
            Report SHA-256 Hash (32-Byte Hex)
          </label>
          <input
            type="text"
            required
            value={hashInput}
            onChange={(e) => setHashInput(e.target.value)}
            placeholder="0x..."
            className="w-full bg-[#192034] border border-[#494E6B]/40 focus:border-[#985E6D] rounded-xl px-3.5 py-2.5 text-xs text-white placeholder-[#98878F] focus:outline-none font-mono"
          />
        </div>

        <div>
          <label className="block text-[#98878F] mb-1 font-mono uppercase text-[10px]">
            Optional: Investigation Payload JSON (To verify data has not been modified)
          </label>
          <textarea
            rows={3}
            value={payloadInput}
            onChange={(e) => setPayloadInput(e.target.value)}
            placeholder='Paste canonical JSON payload to test tamper-resistance...'
            className="w-full bg-[#192034] border border-[#494E6B]/40 focus:border-[#985E6D] rounded-xl px-3.5 py-2 text-xs text-white placeholder-[#98878F] focus:outline-none font-mono resize-none"
          />
        </div>

        <button
          type="submit"
          disabled={loading || !hashInput.trim()}
          className="px-6 py-2.5 rounded-xl bg-[#985E6D] hover:bg-[#ad6d7d] text-white font-semibold text-xs shadow-[0_0_12px_rgba(152,94,109,0.35)] disabled:opacity-50 transition-all cursor-pointer flex items-center gap-2"
        >
          {loading ? 'Querying Blockchain State...' : 'Verify on Ledger'}
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </form>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-[#985E6D]/20 border border-[#985E6D]/50 text-[#e58a9d] text-xs flex items-center gap-3">
          <AlertOctagon className="w-5 h-5 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Verification Result Card */}
      {result && (
        <div className={`p-6 rounded-2xl border transition-all ${
          result.is_tamper_free && result.is_verified
            ? 'bg-[#3f6e62]/20 border-[#3f6e62]/60 text-white'
            : 'bg-[#985E6D]/25 border-[#985E6D] text-white'
        }`}>
          <div className="flex items-center gap-3 mb-2">
            {result.is_tamper_free && result.is_verified ? (
              <ShieldCheck className="w-6 h-6 text-[#85c9b7]" />
            ) : (
              <AlertOctagon className="w-6 h-6 text-[#e58a9d]" />
            )}
            <div>
              <h3 className="text-base font-bold">
                {result.is_tamper_free && result.is_verified
                  ? 'Cryptographic Authenticity Confirmed'
                  : result.is_verified
                  ? 'DATA TAMPERING DETECTED'
                  : 'Report Not Found on Ledger'}
              </h3>
              <p className="text-xs text-[#c2b5bc] mt-0.5">{result.verification_message}</p>
            </div>
          </div>

          {result.is_verified && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-4 mt-4 border-t border-white/10 text-xs font-mono">
              <div>
                <span className="text-[#98878F] block text-[10px]">Network Registry</span>
                <span className="text-white font-semibold flex items-center gap-1.5">
                  {result.network}
                  {result.is_simulated && (
                    <span className="px-1.5 py-0.2 rounded text-[9px] bg-amber-500/20 text-amber-300 border border-amber-500/40">
                      SIM
                    </span>
                  )}
                </span>
              </div>
              <div>
                <span className="text-[#98878F] block text-[10px]">Block Number</span>
                <span className="text-white font-semibold">#{result.block_number}</span>
              </div>
              <div>
                <span className="text-[#98878F] block text-[10px]">Transaction Hash</span>
                <span className="text-[#c28190] font-semibold">
                  {result.tx_hash.startsWith('SIM-') ? (
                    <span>{truncateHash(result.tx_hash, 8)} (Local)</span>
                  ) : (
                    <a
                      href={`https://sepolia.etherscan.io/tx/${result.tx_hash}`}
                      target="_blank"
                      rel="noreferrer"
                      className="hover:underline inline-flex items-center gap-1"
                    >
                      {truncateHash(result.tx_hash, 6)}
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  )}
                </span>
              </div>
              <div>
                <span className="text-[#98878F] block text-[10px]">Reporter Wallet</span>
                <span className="text-[#c2b5bc] font-semibold">{truncateHash(result.reporter_address, 4)}</span>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Recent Blockchain Records */}
      <div className="rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl overflow-hidden">
        <div className="p-5 border-b border-[#494E6B]/30 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-[#985E6D]" />
            <h3 className="text-sm font-bold text-white tracking-wide">
              Recent On-Chain Threat Anchors
            </h3>
          </div>
          <span className="text-xs font-mono text-[#98878F]">EVM State Ledger</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#192034]/60 text-[#98878F] uppercase font-mono tracking-wider border-b border-[#494E6B]/30">
              <tr>
                <th className="py-3 px-5">Report SHA-256 Digest</th>
                <th className="py-3 px-4">Threat Type</th>
                <th className="py-3 px-4">Block Height</th>
                <th className="py-3 px-4">Tx Hash</th>
                <th className="py-3 px-4">Reporter Wallet</th>
                <th className="py-3 px-5 text-right">Anchored UTC</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#494E6B]/20 text-[#c2b5bc]">
              {recentRecords.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-8 text-[#98878F]">
                    No threat fingerprints recorded to the ledger yet. Run an investigation to anchor!
                  </td>
                </tr>
              ) : (
                recentRecords.map((r, i) => (
                  <tr key={i} className="hover:bg-[#192034]/40 transition-colors">
                    <td className="py-3 px-5 font-mono text-white">
                      <button
                        type="button"
                        onClick={() => { setHashInput(r.report_hash); setPayloadInput(''); }}
                        className="hover:text-[#c28190] hover:underline cursor-pointer"
                      >
                        {truncateHash(r.report_hash, 10)}
                      </button>
                    </td>
                    <td className="py-3 px-4 font-mono uppercase text-[11px] text-[#98878F]">
                      {r.threat_type}
                    </td>
                    <td className="py-3 px-4 font-mono text-white">
                      #{r.block_number}
                    </td>
                    <td className="py-3 px-4 font-mono text-[#c28190]">
                      {r.tx_hash && r.tx_hash.startsWith('SIM-') ? (
                        <span className="inline-flex items-center gap-1.5">
                          <span className="px-1.5 py-0.2 rounded text-[9px] bg-amber-500/15 text-amber-300 border border-amber-500/30">
                            SIM
                          </span>
                          <span>{truncateHash(r.tx_hash, 6)}</span>
                        </span>
                      ) : r.tx_hash ? (
                        <a
                          href={`https://sepolia.etherscan.io/tx/${r.tx_hash}`}
                          target="_blank"
                          rel="noreferrer"
                          className="hover:underline inline-flex items-center gap-1"
                        >
                          {truncateHash(r.tx_hash, 6)}
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      ) : (
                        <span className="text-[#98878F]">N/A</span>
                      )}
                    </td>
                    <td className="py-3 px-4 font-mono text-[#98878F]">
                      {truncateHash(r.reporter_address, 4)}
                    </td>
                    <td className="py-3 px-5 text-right font-mono text-[11px] text-[#98878F]">
                      {formatDate(r.verified_at)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

