import React, { useState, useEffect, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Network,
  MapPin,
  Server,
  ShieldCheck,
  ArrowRight,
  AlertOctagon,
  Radio
} from 'lucide-react';
import { scanIP } from '../services/api';
import { IPScanResponse } from '../types';
import { ThreatSeverityCard } from '../components/ThreatSeverityCard';
import { EvidencePanel } from '../components/EvidencePanel';
import { VerificationBadge } from '../components/VerificationBadge';
import { LoadingSkeleton } from '../components/LoadingSkeleton';

export const IPAnalysis: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [ipInput, setIpInput] = useState(() => searchParams.get('target') || '');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<IPScanResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const runScan = useCallback(async (ipToScan?: string) => {
    const ip = (ipToScan || ipInput).trim();
    if (!ip) return;

    setLoading(true);
    setErrorMsg(null);

    try {
      const data = await scanIP(ip);
      setResult(data);
    } catch (err: any) {
      setErrorMsg(err?.response?.data?.detail || err.message || 'IP investigation failed');
    } finally {
      setLoading(false);
    }
  }, [ipInput]);

  useEffect(() => {
    const targetParam = searchParams.get('target');
    if (targetParam) {
      runScan(targetParam);
    }
  }, [searchParams, runScan]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    runScan();
  };

  return (
    <div className="space-y-8 pb-12">
      <div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          IP Address Intelligence & Infrastructure Audit
        </h1>
        <p className="text-xs sm:text-sm text-[#98878F] mt-1">
          Autonomous system ownership, geolocation mapping, reverse DNS, and strict RFC 1918 private boundary enforcement.
        </p>
      </div>

      {/* Input Form */}
      <form onSubmit={handleSubmit} className="p-4 sm:p-5 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <div className="relative flex-1">
            <Network className="w-5 h-5 text-[#98878F] absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={ipInput}
              onChange={(e) => setIpInput(e.target.value)}
              placeholder="Enter IPv4 or IPv6 address (e.g., 1.1.1.1, 45.154.255.89)..."
              className="w-full bg-[#192034]/90 border border-[#494E6B]/40 focus:border-[#985E6D] rounded-xl pl-11 pr-4 py-3 text-sm text-white placeholder-[#98878F] focus:outline-none font-mono"
            />
          </div>

          <button
            type="submit"
            disabled={loading || !ipInput.trim()}
            className="px-6 py-3 rounded-xl bg-[#985E6D] hover:bg-[#ad6d7d] text-white font-semibold text-xs shadow-[0_0_16px_rgba(152,94,109,0.35)] disabled:opacity-40 transition-all cursor-pointer flex items-center justify-center gap-2 whitespace-nowrap"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                <span>Investigating...</span>
              </>
            ) : (
              <>
                <span>Inspect IP</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>

        {/* Quick Presets */}
        <div className="mt-3 pt-3 border-t border-[#494E6B]/25 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-[#98878F]">Presets:</span>
          <button
            type="button"
            onClick={() => { setIpInput('1.1.1.1'); runScan('1.1.1.1'); }}
            className="px-2 py-0.5 rounded bg-[#192034] hover:bg-[#494E6B]/30 text-[#85c9b7] border border-[#3f6e62]/40 text-[11px] font-mono"
          >
            1.1.1.1 (Cloudflare DNS)
          </button>
          <button
            type="button"
            onClick={() => { setIpInput('8.8.8.8'); runScan('8.8.8.8'); }}
            className="px-2 py-0.5 rounded bg-[#192034] hover:bg-[#494E6B]/30 text-[#85c9b7] border border-[#3f6e62]/40 text-[11px] font-mono"
          >
            8.8.8.8 (Google Public DNS)
          </button>
          <button
            type="button"
            onClick={() => { setIpInput('45.154.255.89'); runScan('45.154.255.89'); }}
            className="px-2 py-0.5 rounded bg-[#192034] hover:bg-[#494E6B]/30 text-[#e58a9d] border border-[#985E6D]/40 text-[11px] font-mono"
          >
            45.154.255.89 (Malicious C2 Node)
          </button>
          <button
            type="button"
            onClick={() => { setIpInput('185.220.101.5'); runScan('185.220.101.5'); }}
            className="px-2 py-0.5 rounded bg-[#192034] hover:bg-[#494E6B]/30 text-[#eac498] border border-[#b5834f]/40 text-[11px] font-mono"
          >
            185.220.101.5 (Tor Exit Relay)
          </button>
          <button
            type="button"
            onClick={() => { setIpInput('192.168.1.1'); runScan('192.168.1.1'); }}
            className="px-2 py-0.5 rounded bg-[#192034] hover:bg-[#494E6B]/30 text-[#c2b5bc] border border-[#494E6B]/50 text-[11px] font-mono"
          >
            192.168.1.1 (RFC 1918 Private Test)
          </button>
        </div>
      </form>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-[#985E6D]/20 border border-[#985E6D]/50 text-[#e58a9d] text-xs flex items-center gap-3">
          <AlertOctagon className="w-5 h-5 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {loading && <LoadingSkeleton label="Querying ASN Allocation, Reverse DNS, and Abuse History..." />}

      {result && !loading && (
        <div className="space-y-6">
          <ThreatSeverityCard
            target={result.ip_address}
            scanType="IP Intelligence"
            riskLevel={result.risk_level}
            riskScore={result.reputation_score}
            summary={`Topology: ${result.classification}. ASN: ${result.network_info.asn || 'Unassigned'} (${result.network_info.asn_org || 'Independent'}). Location: ${result.geo_info.city}, ${result.geo_info.country}. Reverse DNS: ${result.network_info.reverse_dns || 'No PTR Record'}.`}
            canonicalHash={result.canonical_hash}
            timestamp={result.timestamp}
          />

          {/* Private IP Protection Alert Banner */}
          {(result.is_private || result.is_loopback || result.is_reserved) && (
            <div className="p-4 rounded-xl bg-[#494E6B]/25 border border-[#494E6B]/50 text-xs text-[#c2b5bc] flex items-center gap-3">
              <ShieldCheck className="w-5 h-5 text-[#85c9b7] shrink-0" />
              <p className="leading-relaxed">
                <strong className="text-white">SSRF Security Boundary Active: </strong>
                This address resides within protected private or local non-routable address space. WebSentinel AI strictly blocks outbound vulnerability probing against internal networks.
              </p>
            </div>
          )}

          {/* Metadata Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Network Ownership */}
            <div className="p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl space-y-3 font-mono text-xs">
              <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
                <Server className="w-4 h-4 text-[#985E6D]" />
                <span>Autonomous System & ISP</span>
              </h3>

              <div className="space-y-2 pt-1">
                <div className="flex justify-between py-1.5 border-b border-[#494E6B]/20">
                  <span className="text-[#98878F]">AS Number</span>
                  <span className="text-white font-semibold">{result.network_info.asn || 'Unassigned'}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-[#494E6B]/20">
                  <span className="text-[#98878F]">Organization</span>
                  <span className="text-white truncate max-w-[220px]">{result.network_info.asn_org || 'N/A'}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-[#494E6B]/20">
                  <span className="text-[#98878F]">ISP / Operator</span>
                  <span className="text-[#c2b5bc] truncate max-w-[220px]">{result.network_info.isp || 'N/A'}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-[#494E6B]/20">
                  <span className="text-[#98878F]">Reverse DNS (PTR)</span>
                  <span className="text-[#85c9b7] truncate max-w-[220px]">{result.network_info.reverse_dns || '(None)'}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-[#494E6B]/20">
                  <span className="text-[#98878F]">Datacenter Hosting</span>
                  <span className={result.network_info.is_hosting ? 'text-[#eac498]' : 'text-white'}>
                    {result.network_info.is_hosting ? 'Yes (Hosting Facility)' : 'Residential / Enterprise'}
                  </span>
                </div>
              </div>
            </div>

            {/* Geolocation Details */}
            <div className="p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl space-y-3 font-mono text-xs">
              <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
                <MapPin className="w-4 h-4 text-[#985E6D]" />
                <span>Geolocation Telemetry</span>
              </h3>

              <div className="space-y-2 pt-1">
                <div className="flex justify-between py-1.5 border-b border-[#494E6B]/20">
                  <span className="text-[#98878F]">Country</span>
                  <span className="text-white font-semibold">{result.geo_info.country} ({result.geo_info.country_code})</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-[#494E6B]/20">
                  <span className="text-[#98878F]">City & Region</span>
                  <span className="text-white">{result.geo_info.city}, {result.geo_info.region}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-[#494E6B]/20">
                  <span className="text-[#98878F]">Coordinates</span>
                  <span className="text-[#c2b5bc]">{result.geo_info.latitude}, {result.geo_info.longitude}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-[#494E6B]/20">
                  <span className="text-[#98878F]">Timezone</span>
                  <span className="text-white">{result.geo_info.timezone}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-[#494E6B]/20">
                  <span className="text-[#98878F]">Topology Classification</span>
                  <span className="text-white">{result.classification}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Abuse Categories & Threat Indicators */}
          {result.abuse_categories.length > 0 && (
            <div className="p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl space-y-3">
              <h3 className="text-sm font-bold text-white tracking-wide">
                Identified Infrastructure Abuse Tags
              </h3>

              <div className="flex flex-wrap gap-2">
                {result.abuse_categories.map((cat, i) => (
                  <span
                    key={i}
                    className="px-3 py-1.5 rounded-xl bg-[#985E6D]/20 text-[#e58a9d] border border-[#985E6D]/40 text-xs font-mono font-medium flex items-center gap-1.5"
                  >
                    <Radio className="w-3.5 h-3.5" />
                    <span>{cat}</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Evidence Panel */}
          <EvidencePanel evidence={result.evidence} />

          {/* Recommended Actions */}
          {result.recommendations.length > 0 && (
            <div className="p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl space-y-4">
              <h3 className="text-sm font-bold text-white tracking-wide">
                Recommended Ingress / Egress Actions
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {result.recommendations.map((rec, i) => (
                  <div key={i} className="p-4 rounded-xl bg-[#192034]/60 border border-[#494E6B]/30 space-y-1">
                    <div className="flex items-center justify-between">
                      <h4 className="text-xs font-bold text-white">{rec.title}</h4>
                      <span className="text-[10px] font-mono uppercase font-bold text-[#c28190]">
                        {rec.priority}
                      </span>
                    </div>
                    <p className="text-xs text-[#98878F] leading-relaxed">{rec.action}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Blockchain Verification */}
          <VerificationBadge
            scanId={result.id}
            target={result.ip_address}
            threatType="ip"
            riskLevel={result.risk_level}
            riskScore={result.reputation_score}
            findingsDigest={`${result.ip_address} (${result.classification}) - ${result.network_info.asn_org || 'Host'}`}
            canonicalHash={result.canonical_hash}
          />
        </div>
      )}
    </div>
  );
};

