import React, { useState, useEffect, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Globe,
  FileJson,
  FileText,
  AlertOctagon,
  ArrowRight,
  ShieldCheck,
  CheckCircle2,
  GitBranch
} from 'lucide-react';
import { scanURL, getExportJsonUrl, getExportPdfUrl } from '../services/api';
import { URLScanResponse } from '../types';
import { ThreatSeverityCard } from '../components/ThreatSeverityCard';
import { SecurityScoreGauge } from '../components/SecurityScoreGauge';
import { EvidencePanel } from '../components/EvidencePanel';
import { VerificationBadge } from '../components/VerificationBadge';
import { LoadingSkeleton } from '../components/LoadingSkeleton';

export const URLAnalysis: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [urlInput, setUrlInput] = useState(() => searchParams.get('target') || '');
  const [deepScan, setDeepScan] = useState(true);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<URLScanResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const runScan = useCallback(async (targetToScan?: string) => {
    const target = (targetToScan || urlInput).trim();
    if (!target) return;

    setLoading(true);
    setErrorMsg(null);

    try {
      const data = await scanURL(target, deepScan);
      setResult(data);
    } catch (err: any) {
      setErrorMsg(err?.response?.data?.detail || err.message || 'URL inspection failed');
    } finally {
      setLoading(false);
    }
  }, [urlInput, deepScan]);

  // Auto trigger scan if target is passed via query param
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
      {/* Page Header */}
      <div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          URL Threat Investigation
        </h1>
        <p className="text-xs sm:text-sm text-[#98878F] mt-1">
          Lexical decomposition, typosquatting recognition, homograph lookalikes, DNS resolution, and redirect tracing.
        </p>
      </div>

      {/* Input Search Form */}
      <form onSubmit={handleSubmit} className="p-4 sm:p-5 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <div className="relative flex-1">
            <Globe className="w-5 h-5 text-[#98878F] absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="Enter target URL (e.g., https://example.com or suspicious link)..."
              className="w-full bg-[#192034]/90 border border-[#494E6B]/40 focus:border-[#985E6D] rounded-xl pl-11 pr-4 py-3 text-sm text-white placeholder-[#98878F] focus:outline-none font-mono"
            />
          </div>

          <div className="flex items-center gap-3">
            <label className="flex items-center gap-2 text-xs text-[#98878F] cursor-pointer px-2 select-none">
              <input
                type="checkbox"
                checked={deepScan}
                onChange={(e) => setDeepScan(e.target.checked)}
                className="rounded border-[#494E6B] text-[#985E6D] focus:ring-0 bg-[#192034]"
              />
              <span>Inspect Redirects</span>
            </label>

            <button
              type="submit"
              disabled={loading || !urlInput.trim()}
              className="px-6 py-3 rounded-xl bg-[#985E6D] hover:bg-[#ad6d7d] text-white font-semibold text-xs shadow-[0_0_16px_rgba(152,94,109,0.35)] disabled:opacity-40 transition-all cursor-pointer flex items-center justify-center gap-2 whitespace-nowrap"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <span>Analyze URL</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </div>
        </div>

        {/* Quick Test Presets */}
        <div className="mt-3 pt-3 border-t border-[#494E6B]/25 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-[#98878F]">Presets:</span>
          <button
            type="button"
            onClick={() => { setUrlInput('https://example.com'); runScan('https://example.com'); }}
            className="px-2 py-0.5 rounded bg-[#192034] hover:bg-[#494E6B]/30 text-[#85c9b7] border border-[#3f6e62]/40 text-[11px] font-mono"
          >
            example.com (Clean)
          </button>
          <button
            type="button"
            onClick={() => { setUrlInput('http://paypa1-security-verification.com/login'); runScan('http://paypa1-security-verification.com/login'); }}
            className="px-2 py-0.5 rounded bg-[#192034] hover:bg-[#494E6B]/30 text-[#e58a9d] border border-[#985E6D]/40 text-[11px] font-mono"
          >
            paypa1-security.com (Typosquat)
          </button>
          <button
            type="button"
            onClick={() => { setUrlInput('https://appleid-recovery-alert.top'); runScan('https://appleid-recovery-alert.top'); }}
            className="px-2 py-0.5 rounded bg-[#192034] hover:bg-[#494E6B]/30 text-[#e58a9d] border border-[#985E6D]/40 text-[11px] font-mono"
          >
            appleid-alert.top (High Risk TLD)
          </button>
        </div>
      </form>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-[#985E6D]/20 border border-[#985E6D]/50 text-[#e58a9d] text-xs flex items-center gap-3">
          <AlertOctagon className="w-5 h-5 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {loading && <LoadingSkeleton label="Executing Parallel URL Security Analysis..." />}

      {result && !loading && (
        <div className="space-y-6">
          {/* Executive Assessment Card */}
          <ThreatSeverityCard
            target={result.submitted_url}
            scanType="URL"
            riskLevel={result.risk_level}
            riskScore={result.risk_score}
            summary={`Decomposed domain '${result.domain_info.registered_domain}'. Identified ${result.evidence.length} threat indicators and ${result.suspicious_patterns.length} anomalous pattern tokens.`}
            canonicalHash={result.canonical_hash}
            timestamp={result.timestamp}
          />

          {/* Export & Actions Toolbar */}
          <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl bg-[#202740]/60 border border-[#494E6B]/30 text-xs">
            <div className="flex items-center gap-2 text-[#98878F] font-mono">
              <CheckCircle2 className="w-4 h-4 text-[#85c9b7]" />
              <span>Report ID: <span className="text-white">{result.id.slice(0, 16)}...</span></span>
            </div>

            <div className="flex items-center gap-2">
              <a
                href={getExportJsonUrl(result.id)}
                download
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#192034] hover:bg-[#494E6B]/30 border border-[#494E6B]/40 text-[#c2b5bc] hover:text-white transition-colors cursor-pointer"
              >
                <FileJson className="w-3.5 h-3.5" />
                <span>Export JSON</span>
              </a>

              <a
                href={getExportPdfUrl(result.id)}
                download
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#985E6D]/20 hover:bg-[#985E6D]/30 border border-[#985E6D]/40 text-[#e58a9d] hover:text-white transition-colors cursor-pointer"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Export PDF Report</span>
              </a>
            </div>
          </div>

          {/* Technical Decomposition Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Domain & Lexical Analysis */}
            <div className="p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl space-y-4">
              <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
                <Globe className="w-4 h-4 text-[#985E6D]" />
                <span>Domain Structure Breakdown</span>
              </h3>

              <div className="space-y-2.5 text-xs font-mono">
                <div className="flex justify-between py-1.5 border-b border-[#494E6B]/25">
                  <span className="text-[#98878F]">Registered Domain</span>
                  <span className="text-white font-semibold">{result.domain_info.registered_domain}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-[#494E6B]/25">
                  <span className="text-[#98878F]">Subdomain</span>
                  <span className="text-[#c2b5bc]">{result.domain_info.subdomain || '(None)'}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-[#494E6B]/25">
                  <span className="text-[#98878F]">TLD Suffix</span>
                  <span className="text-white">.{result.domain_info.suffix}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-[#494E6B]/25">
                  <span className="text-[#98878F]">Shannon Entropy</span>
                  <span className="text-white">{result.domain_info.entropy}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-[#494E6B]/25">
                  <span className="text-[#98878F]">TLD Risk Tier</span>
                  <span className={result.domain_info.tld_risk_tier === 'High-Risk' ? 'text-[#e58a9d] font-bold' : 'text-[#85c9b7]'}>
                    {result.domain_info.tld_risk_tier}
                  </span>
                </div>
              </div>
            </div>

            {/* Typosquatting & Homograph Attacks */}
            <div className="p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl space-y-4">
              <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-[#985E6D]" />
                <span>Deceptive Mimicry Inspection</span>
              </h3>

              <div className="space-y-3 text-xs">
                {/* Typosquat box */}
                <div className={`p-3 rounded-xl border ${
                  result.typosquatting.is_typosquat
                    ? 'bg-[#985E6D]/15 border-[#985E6D]/40 text-white'
                    : 'bg-[#192034]/60 border-[#494E6B]/30 text-[#98878F]'
                }`}>
                  <div className="flex items-center justify-between font-mono font-semibold mb-1">
                    <span>Typosquatting</span>
                    <span className={result.typosquatting.is_typosquat ? 'text-[#e58a9d]' : 'text-[#85c9b7]'}>
                      {result.typosquatting.is_typosquat ? 'DETECTED' : 'CLEAN'}
                    </span>
                  </div>
                  {result.typosquatting.is_typosquat ? (
                    <p className="text-[11px] text-[#c2b5bc] leading-relaxed">
                      {result.typosquatting.explanation}
                    </p>
                  ) : (
                    <p className="text-[11px] text-[#98878F]">No brand imitation signatures detected.</p>
                  )}
                </div>

                {/* Homograph box */}
                <div className={`p-3 rounded-xl border ${
                  result.homograph.has_homograph
                    ? 'bg-[#985E6D]/15 border-[#985E6D]/40 text-white'
                    : 'bg-[#192034]/60 border-[#494E6B]/30 text-[#98878F]'
                }`}>
                  <div className="flex items-center justify-between font-mono font-semibold mb-1">
                    <span>Homograph (IDN) Attack</span>
                    <span className={result.homograph.has_homograph ? 'text-[#e58a9d]' : 'text-[#85c9b7]'}>
                      {result.homograph.has_homograph ? 'DETECTED' : 'CLEAN'}
                    </span>
                  </div>
                  {result.homograph.has_homograph ? (
                    <p className="text-[11px] text-[#c2b5bc] leading-relaxed">
                      {result.homograph.explanation}
                    </p>
                  ) : (
                    <p className="text-[11px] text-[#98878F]">Latin character script is canonical and un-spoofed.</p>
                  )}
                </div>
              </div>
            </div>

            {/* Security Posture Gauge */}
            <SecurityScoreGauge scoreData={result.security_score} />
          </div>

          {/* DNS Resolution Details */}
          <div className="p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
                <span>DNS Resolution Telemetry</span>
              </h3>
              <span className="text-xs font-mono text-[#85c9b7]">
                Status: {result.dns.lookup_status}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-mono">
              <div className="p-3.5 rounded-xl bg-[#192034]/70 border border-[#494E6B]/30">
                <span className="text-[#98878F] block mb-1">A / AAAA Records</span>
                {result.dns.a_records.length > 0 ? (
                  result.dns.a_records.map((ip, i) => (
                    <div key={i} className="text-white font-medium">{ip}</div>
                  ))
                ) : (
                  <div className="text-[#98878F]">No A records mapped</div>
                )}
              </div>

              <div className="p-3.5 rounded-xl bg-[#192034]/70 border border-[#494E6B]/30">
                <span className="text-[#98878F] block mb-1">MX Mail Exchangers</span>
                {result.dns.mx_records.length > 0 ? (
                  result.dns.mx_records.map((mx, i) => (
                    <div key={i} className="text-[#c2b5bc] truncate">{mx}</div>
                  ))
                ) : (
                  <div className="text-[#98878F]">No MX records</div>
                )}
              </div>

              <div className="p-3.5 rounded-xl bg-[#192034]/70 border border-[#494E6B]/30">
                <span className="text-[#98878F] block mb-1">Nameservers (NS)</span>
                {result.dns.ns_records.length > 0 ? (
                  result.dns.ns_records.map((ns, i) => (
                    <div key={i} className="text-[#c2b5bc] truncate">{ns}</div>
                  ))
                ) : (
                  <div className="text-[#98878F]">No NS records</div>
                )}
              </div>
            </div>
          </div>

          {/* Redirect Chain Inspection */}
          {result.redirect_chain && result.redirect_chain.length > 0 && (
            <div className="p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
                  <GitBranch className="w-4 h-4 text-[#985E6D]" />
                  <span>Redirect Chain Inspection ({result.redirect_chain.length} Hops)</span>
                </h3>
                <span className="text-xs font-mono text-[#85c9b7]">SSRF Re-Validated At Every Jump</span>
              </div>

              <div className="space-y-2">
                {result.redirect_chain.map((hop) => (
                  <div
                    key={hop.hop_number}
                    className="p-3 rounded-xl bg-[#192034]/60 border border-[#494E6B]/30 flex flex-wrap items-center justify-between gap-3 text-xs font-mono"
                  >
                    <div className="flex items-center gap-3">
                      <span className="w-6 h-6 rounded-lg bg-[#494E6B]/30 flex items-center justify-center font-bold text-white">
                        {hop.hop_number}
                      </span>
                      <span className="text-white font-medium break-all">{hop.url}</span>
                    </div>

                    <div className="flex items-center gap-3">
                      <span className="px-2 py-0.5 rounded bg-[#494E6B]/25 text-[#85c9b7]">
                        HTTP {hop.status_code}
                      </span>
                      <span className="text-[#98878F]">{hop.response_time_ms} ms</span>
                      <span className="text-[#c28190]">{hop.resolved_ip}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Threat Intelligence Feeds */}
          <div className="p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl space-y-4">
            <h3 className="text-sm font-bold text-white tracking-wide">
              Global Threat Intelligence Feeds
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {result.threat_intel.map((feed, idx) => (
                <div
                  key={idx}
                  className={`p-4 rounded-xl border flex flex-col justify-between ${
                    feed.is_flagged
                      ? 'bg-[#985E6D]/20 border-[#985E6D] text-white'
                      : 'bg-[#192034]/60 border-[#494E6B]/30 text-[#98878F]'
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-bold text-xs text-white">{feed.source_name}</span>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                        feed.is_flagged ? 'bg-[#985E6D] text-white font-bold' : 'bg-[#494E6B]/30 text-[#85c9b7]'
                      }`}>
                        {feed.status_note}
                      </span>
                    </div>
                    <p className="text-[11px] text-[#c2b5bc] leading-relaxed">
                      {feed.details}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Evidence Panel */}
          <EvidencePanel evidence={result.evidence} />

          {/* Recommended Actions Panel */}
          {result.recommendations && result.recommendations.length > 0 && (
            <div className="p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl space-y-4">
              <h3 className="text-sm font-bold text-white tracking-wide">
                Recommended Remediation Actions
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

          {/* Blockchain Verification Anchor */}
          <VerificationBadge
            scanId={result.id}
            target={result.submitted_url}
            threatType="url"
            riskLevel={result.risk_level}
            riskScore={result.risk_score}
            findingsDigest={`${result.domain_info.registered_domain} - ${result.evidence.length} evidence indicators`}
            canonicalHash={result.canonical_hash}
          />
        </div>
      )}
    </div>
  );
};

