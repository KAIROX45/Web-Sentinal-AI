import React, { useState } from 'react';
import {
  Lock,
  AlertTriangle,
  ArrowRight,
  AlertOctagon
} from 'lucide-react';
import { inspectTLS } from '../services/api';
import { TLSScanResponse } from '../types';
import { CertificateChainTree } from '../components/CertificateChainTree';
import { ThreatSeverityCard } from '../components/ThreatSeverityCard';
import { LoadingSkeleton } from '../components/LoadingSkeleton';

export const TLSAnalysis: React.FC = () => {
  const [hostInput, setHostInput] = useState('');
  const [portInput, setPortInput] = useState('443');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<TLSScanResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const runInspect = async (hostOverride?: string) => {
    const host = (hostOverride || hostInput).trim();
    if (!host) return;

    setLoading(true);
    setErrorMsg(null);

    try {
      const data = await inspectTLS(host, parseInt(portInput) || 443);
      setResult(data);
    } catch (err: any) {
      setErrorMsg(err?.response?.data?.detail || err.message || 'TLS inspection failed');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    runInspect();
  };

  return (
    <div className="space-y-8 pb-12">
      <div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          TLS / SSL Certificate Analysis
        </h1>
        <p className="text-xs sm:text-sm text-[#98878F] mt-1">
          Cryptographic handshake inspection, certificate chain trust hierarchy, expiration auditing, and hostname validation.
        </p>
      </div>

      {/* Input Form */}
      <form onSubmit={handleSubmit} className="p-4 sm:p-5 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <div className="relative flex-1">
            <Lock className="w-5 h-5 text-[#98878F] absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={hostInput}
              onChange={(e) => setHostInput(e.target.value)}
              placeholder="Enter domain name (e.g., google.com or github.com)..."
              className="w-full bg-[#192034]/90 border border-[#494E6B]/40 focus:border-[#985E6D] rounded-xl pl-11 pr-4 py-3 text-sm text-white placeholder-[#98878F] focus:outline-none font-mono"
            />
          </div>

          <div className="flex items-center gap-3">
            <div className="w-24">
              <input
                type="number"
                value={portInput}
                onChange={(e) => setPortInput(e.target.value)}
                placeholder="Port"
                className="w-full bg-[#192034]/90 border border-[#494E6B]/40 focus:border-[#985E6D] rounded-xl px-3 py-3 text-sm text-white placeholder-[#98878F] focus:outline-none font-mono text-center"
              />
            </div>

            <button
              type="submit"
              disabled={loading || !hostInput.trim()}
              className="px-6 py-3 rounded-xl bg-[#985E6D] hover:bg-[#ad6d7d] text-white font-semibold text-xs shadow-[0_0_16px_rgba(152,94,109,0.35)] disabled:opacity-40 transition-all cursor-pointer flex items-center justify-center gap-2 whitespace-nowrap"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  <span>Inspecting...</span>
                </>
              ) : (
                <>
                  <span>Inspect TLS</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </div>
        </div>

        {/* Quick Presets */}
        <div className="mt-3 pt-3 border-t border-[#494E6B]/25 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-[#98878F]">Controlled Test Presets:</span>
          <button
            type="button"
            onClick={() => { setHostInput('google.com'); runInspect('google.com'); }}
            className="px-2 py-0.5 rounded bg-[#192034] hover:bg-[#494E6B]/30 text-[#85c9b7] border border-[#3f6e62]/40 text-[11px] font-mono"
          >
            google.com (Valid TLS 1.3)
          </button>
          <button
            type="button"
            onClick={() => { setHostInput('github.com'); runInspect('github.com'); }}
            className="px-2 py-0.5 rounded bg-[#192034] hover:bg-[#494E6B]/30 text-[#85c9b7] border border-[#3f6e62]/40 text-[11px] font-mono"
          >
            github.com (Valid DigiCert)
          </button>
          <button
            type="button"
            onClick={() => { setHostInput('expired.badssl.com'); runInspect('expired.badssl.com'); }}
            className="px-2 py-0.5 rounded bg-[#192034] hover:bg-[#494E6B]/30 text-[#e58a9d] border border-[#985E6D]/40 text-[11px] font-mono"
          >
            expired.badssl.com (Expired Cert Test)
          </button>
          <button
            type="button"
            onClick={() => { setHostInput('self-signed.badssl.com'); runInspect('self-signed.badssl.com'); }}
            className="px-2 py-0.5 rounded bg-[#192034] hover:bg-[#494E6B]/30 text-[#eac498] border border-[#b5834f]/40 text-[11px] font-mono"
          >
            self-signed.badssl.com (Untrusted Root Test)
          </button>
        </div>
      </form>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-[#985E6D]/20 border border-[#985E6D]/50 text-[#e58a9d] text-xs flex items-center gap-3">
          <AlertOctagon className="w-5 h-5 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {loading && <LoadingSkeleton label="Initiating Direct TLS Socket Handshake..." />}

      {result && !loading && (
        <div className="space-y-6">
          <ThreatSeverityCard
            target={`${result.hostname}:${result.port}`}
            scanType="TLS Certificate"
            riskLevel={result.risk_level}
            riskScore={result.risk_score}
            summary={`Negotiated ${result.protocol_version} with cipher suite ${result.cipher_suite}. Issuer: ${result.issuer_cn || result.issuer_org || 'Certificate Authority'}. Remaining validity: ${result.days_remaining} days.`}
            timestamp={result.timestamp}
          />

          {/* Warnings Banner if any */}
          {result.warnings.length > 0 && (
            <div className="p-4 rounded-xl bg-[#985E6D]/20 border border-[#985E6D]/50 space-y-2">
              <div className="flex items-center gap-2 text-xs font-bold text-[#e58a9d] uppercase tracking-wider font-mono">
                <AlertTriangle className="w-4 h-4" />
                <span>Certificate Security Warnings ({result.warnings.length})</span>
              </div>
              <ul className="list-disc list-inside space-y-1 text-xs text-white">
                {result.warnings.map((w, idx) => (
                  <li key={idx} className="font-mono">{w}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Key Parameters Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-[#202740]/80 border border-[#494E6B]/30">
              <span className="text-[#98878F] text-[10px] font-mono uppercase block mb-1">
                Protocol Version
              </span>
              <span className="text-base font-bold text-white font-mono">
                {result.protocol_version}
              </span>
            </div>

            <div className="p-4 rounded-xl bg-[#202740]/80 border border-[#494E6B]/30">
              <span className="text-[#98878F] text-[10px] font-mono uppercase block mb-1">
                Validity Days
              </span>
              <span className={`text-base font-bold font-mono ${
                result.days_remaining <= 0
                  ? 'text-[#e58a9d]'
                  : result.days_remaining < 30
                  ? 'text-[#eac498]'
                  : 'text-[#85c9b7]'
              }`}>
                {result.days_remaining > 0 ? `${result.days_remaining} Days Left` : `${Math.abs(result.days_remaining)} Days Expired`}
              </span>
            </div>

            <div className="p-4 rounded-xl bg-[#202740]/80 border border-[#494E6B]/30">
              <span className="text-[#98878F] text-[10px] font-mono uppercase block mb-1">
                Hostname Match
              </span>
              <span className={`text-base font-bold font-mono ${
                result.hostname_matches ? 'text-[#85c9b7]' : 'text-[#e58a9d]'
              }`}>
                {result.hostname_matches ? 'RFC 6125 Valid' : 'MISMATCH'}
              </span>
            </div>

            <div className="p-4 rounded-xl bg-[#202740]/80 border border-[#494E6B]/30">
              <span className="text-[#98878F] text-[10px] font-mono uppercase block mb-1">
                Key Parameters
              </span>
              <span className="text-base font-bold text-white font-mono">
                {result.key_type} {result.key_bits}b
              </span>
            </div>
          </div>

          {/* Certificate Trust Hierarchy Visual Tree */}
          <CertificateChainTree
            nodes={result.certificate_chain}
            isExpired={result.is_expired}
            isSelfSigned={result.is_self_signed}
          />

          {/* Detailed Certificate Metadata Breakdown */}
          <div className="p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl space-y-4">
            <h3 className="text-sm font-bold text-white tracking-wide">
              Certificate Subject & Cryptographic Properties
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
              <div className="space-y-2 p-4 rounded-xl bg-[#192034]/60 border border-[#494E6B]/30">
                <span className="text-[#98878F] font-bold block mb-2 uppercase text-[10px]">
                  Subject Attributes
                </span>
                <div className="flex justify-between py-1 border-b border-[#494E6B]/20">
                  <span className="text-[#98878F]">Common Name (CN)</span>
                  <span className="text-white font-semibold">{result.subject_cn || 'None'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#494E6B]/20">
                  <span className="text-[#98878F]">Organization (O)</span>
                  <span className="text-[#c2b5bc]">{result.subject_org || 'None'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#494E6B]/20">
                  <span className="text-[#98878F]">Valid From</span>
                  <span className="text-white">{result.valid_from.split('T')[0]}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#494E6B]/20">
                  <span className="text-[#98878F]">Valid To</span>
                  <span className="text-white">{result.valid_to.split('T')[0]}</span>
                </div>
              </div>

              <div className="space-y-2 p-4 rounded-xl bg-[#192034]/60 border border-[#494E6B]/30">
                <span className="text-[#98878F] font-bold block mb-2 uppercase text-[10px]">
                  Cryptographic Parameters
                </span>
                <div className="flex justify-between py-1 border-b border-[#494E6B]/20">
                  <span className="text-[#98878F]">Cipher Suite</span>
                  <span className="text-white font-semibold truncate max-w-[200px]">{result.cipher_suite}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#494E6B]/20">
                  <span className="text-[#98878F]">Signature Hash</span>
                  <span className="text-white">{result.signature_algorithm}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#494E6B]/20">
                  <span className="text-[#98878F]">Serial Number</span>
                  <span className="text-[#c2b5bc] truncate max-w-[200px]">{result.serial_number}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#494E6B]/20">
                  <span className="text-[#98878F]">Revocation Status</span>
                  <span className="text-[#85c9b7]">{result.revocation_status}</span>
                </div>
              </div>
            </div>

            {/* Subject Alternative Names (SANs) List */}
            {result.sans && result.sans.length > 0 && (
              <div className="pt-3">
                <span className="text-xs text-[#98878F] block mb-2 font-mono">
                  Subject Alternative Names (SANs) ({result.sans.length} entries):
                </span>
                <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto p-3 rounded-xl bg-[#192034]/60 border border-[#494E6B]/30 font-mono text-[11px]">
                  {result.sans.map((san, i) => (
                    <span key={i} className="px-2 py-0.5 rounded bg-[#494E6B]/30 text-[#c2b5bc]">
                      {san}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

