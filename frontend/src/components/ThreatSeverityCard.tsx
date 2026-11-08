import React, { useState } from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle, Copy, Check, Link2 } from 'lucide-react';
import { RiskLevel } from '../types';
import { getRiskLevelBadge, truncateHash } from '../utils/formatters';

interface ThreatSeverityCardProps {
  target: string;
  scanType: string;
  riskLevel: RiskLevel | string;
  riskScore: number;
  summary?: string;
  canonicalHash?: string;
  timestamp?: string;
}

export const ThreatSeverityCard: React.FC<ThreatSeverityCardProps> = ({
  target,
  scanType,
  riskLevel,
  riskScore,
  summary,
  canonicalHash,
  timestamp,
}) => {
  const [copied, setCopied] = useState(false);
  const badge = getRiskLevelBadge(riskLevel);

  const handleCopyHash = () => {
    if (!canonicalHash) return;
    navigator.clipboard.writeText(canonicalHash);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const normRisk = (riskLevel || '').toUpperCase();

  return (
    <div className={`p-6 rounded-2xl bg-[#202740]/90 border ${badge.border} ${badge.glow} backdrop-blur-xl relative overflow-hidden transition-all duration-300`}>
      {/* Decorative background glow */}
      <div
        className="absolute -top-24 -right-24 w-56 h-56 rounded-full blur-3xl opacity-20 pointer-events-none"
        style={{ backgroundColor: badge.color }}
      />

      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#494E6B]/35 pb-5 mb-5">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-xs uppercase font-mono tracking-wider text-[#98878F]">
              {scanType} Investigation
            </span>
            <span className="text-[#494E6B]">•</span>
            <span className="text-xs text-[#98878F] font-mono">
              {timestamp ? new Date(timestamp).toUTCString() : 'Active Analysis'}
            </span>
          </div>
          <h2 className="text-xl font-bold text-white break-all font-mono">
            {target}
          </h2>
        </div>

        {/* Severity Badge & Numeric Score */}
        <div className="flex items-center gap-4">
          <div className="text-right">
            <div className="text-xs uppercase font-mono text-[#98878F]">Threat Score</div>
            <div className="text-2xl font-extrabold font-mono text-white">
              {riskScore}<span className="text-sm text-[#98878F]">/100</span>
            </div>
          </div>
          <div className={`flex items-center gap-2 px-4 py-2.5 rounded-xl border ${badge.bg} ${badge.border} ${badge.text}`}>
            {normRisk === 'CONFIRMED MALICIOUS' || normRisk === 'HIGH' ? (
              <ShieldAlert className="w-5 h-5" />
            ) : normRisk === 'SUSPICIOUS' ? (
              <AlertTriangle className="w-5 h-5" />
            ) : (
              <ShieldCheck className="w-5 h-5" />
            )}
            <span className="font-bold text-sm tracking-wide uppercase">{badge.label}</span>
          </div>
        </div>
      </div>

      {summary && (
        <p className="text-sm text-[#c2b5bc] leading-relaxed mb-5">
          {summary}
        </p>
      )}

      {/* Canonical Fingerprint Stamp */}
      {canonicalHash && (
        <div className="flex flex-wrap items-center justify-between gap-3 pt-4 border-t border-[#494E6B]/30 bg-[#192034]/50 -mx-6 -mb-6 px-6 py-3.5">
          <div className="flex items-center gap-2 text-xs text-[#98878F]">
            <Link2 className="w-4 h-4 text-[#985E6D]" />
            <span className="font-semibold text-white">Canonical Threat Hash:</span>
            <span className="font-mono text-[#c28190]">{truncateHash(canonicalHash, 10)}</span>
          </div>

          <button
            type="button"
            onClick={handleCopyHash}
            className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-[#494E6B]/30 hover:bg-[#494E6B]/50 border border-[#494E6B]/40 text-xs font-mono text-[#c2b5bc] hover:text-white transition-colors cursor-pointer"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-[#85c9b7]" />
                <span>Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy SHA-256</span>
              </>
            )}
          </button>
        </div>
      )}
    </div>
  );
};

