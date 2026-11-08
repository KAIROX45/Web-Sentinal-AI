import React, { useState } from 'react';
import {
  FileCode2,
  AlertTriangle,
  Info,
  CheckCircle2,
  XCircle,
  ArrowRight,
  AlertOctagon
} from 'lucide-react';
import { inspectHeaders } from '../services/api';
import { HeaderScanResponse } from '../types';
import { LoadingSkeleton } from '../components/LoadingSkeleton';

export const HeadersAnalysis: React.FC = () => {
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<HeaderScanResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const runInspect = async (urlOverride?: string) => {
    const target = (urlOverride || urlInput).trim();
    if (!target) return;

    setLoading(true);
    setErrorMsg(null);

    try {
      const data = await inspectHeaders(target);
      setResult(data);
    } catch (err: any) {
      setErrorMsg(err?.response?.data?.detail || err.message || 'Header inspection failed');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    runInspect();
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'PRESENT_OPTIMAL':
        return {
          bg: 'bg-[#3f6e62]/20',
          text: 'text-[#85c9b7]',
          border: 'border-[#3f6e62]/50',
          label: 'Optimal',
          icon: CheckCircle2
        };
      case 'PRESENT_WEAK':
        return {
          bg: 'bg-[#b5834f]/20',
          text: 'text-[#eac498]',
          border: 'border-[#b5834f]/50',
          label: 'Weak Config',
          icon: AlertTriangle
        };
      case 'MISSING':
      default:
        return {
          bg: 'bg-[#985E6D]/20',
          text: 'text-[#e58a9d]',
          border: 'border-[#985E6D]/50',
          label: 'Missing',
          icon: XCircle
        };
    }
  };

  return (
    <div className="space-y-8 pb-12">
      <div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          HTTP Security Header Compliance
        </h1>
        <p className="text-xs sm:text-sm text-[#98878F] mt-1">
          Verifies implementation of HSTS, CSP, anti-clickjacking guards, and MIME-sniffing protection.
        </p>
      </div>

      {/* Input Form */}
      <form onSubmit={handleSubmit} className="p-4 sm:p-5 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <div className="relative flex-1">
            <FileCode2 className="w-5 h-5 text-[#98878F] absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="Enter target website URL (e.g., https://example.com)..."
              className="w-full bg-[#192034]/90 border border-[#494E6B]/40 focus:border-[#985E6D] rounded-xl pl-11 pr-4 py-3 text-sm text-white placeholder-[#98878F] focus:outline-none font-mono"
            />
          </div>

          <button
            type="submit"
            disabled={loading || !urlInput.trim()}
            className="px-6 py-3 rounded-xl bg-[#985E6D] hover:bg-[#ad6d7d] text-white font-semibold text-xs shadow-[0_0_16px_rgba(152,94,109,0.35)] disabled:opacity-40 transition-all cursor-pointer flex items-center justify-center gap-2 whitespace-nowrap"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                <span>Checking...</span>
              </>
            ) : (
              <>
                <span>Inspect Headers</span>
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
            onClick={() => { setUrlInput('https://google.com'); runInspect('https://google.com'); }}
            className="px-2 py-0.5 rounded bg-[#192034] hover:bg-[#494E6B]/30 text-[#85c9b7] border border-[#3f6e62]/40 text-[11px] font-mono"
          >
            google.com (Well Configured)
          </button>
          <button
            type="button"
            onClick={() => { setUrlInput('http://example.com'); runInspect('http://example.com'); }}
            className="px-2 py-0.5 rounded bg-[#192034] hover:bg-[#494E6B]/30 text-[#e58a9d] border border-[#985E6D]/40 text-[11px] font-mono"
          >
            example.com (Missing Headers Test)
          </button>
        </div>
      </form>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-[#985E6D]/20 border border-[#985E6D]/50 text-[#e58a9d] text-xs flex items-center gap-3">
          <AlertOctagon className="w-5 h-5 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {loading && <LoadingSkeleton label="Evaluating HTTP Response Header Security Posture..." />}

      {result && !loading && (
        <div className="space-y-6">
          {/* Summary Metric Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-5 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/35 backdrop-blur-xl">
              <span className="text-[#98878F] text-xs font-mono uppercase block mb-1">Compliance Score</span>
              <div className="text-3xl font-extrabold text-white font-mono">
                {result.security_score}<span className="text-sm text-[#98878F]">/100</span>
              </div>
              <span className="text-[11px] text-[#85c9b7] mt-1 block">Defense-in-depth metric</span>
            </div>

            <div className="p-5 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/35 backdrop-blur-xl">
              <span className="text-[#98878F] text-xs font-mono uppercase block mb-1">Optimal Headers</span>
              <div className="text-3xl font-extrabold text-[#85c9b7] font-mono">
                {result.optimal_count}
              </div>
              <span className="text-[11px] text-[#98878F] mt-1 block">Strictly enforced</span>
            </div>

            <div className="p-5 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/35 backdrop-blur-xl">
              <span className="text-[#98878F] text-xs font-mono uppercase block mb-1">Weak Config</span>
              <div className="text-3xl font-extrabold text-[#eac498] font-mono">
                {result.weak_count}
              </div>
              <span className="text-[11px] text-[#98878F] mt-1 block">Needs tuning</span>
            </div>

            <div className="p-5 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/35 backdrop-blur-xl">
              <span className="text-[#98878F] text-xs font-mono uppercase block mb-1">Missing Headers</span>
              <div className="text-3xl font-extrabold text-[#e58a9d] font-mono">
                {result.missing_count}
              </div>
              <span className="text-[11px] text-[#98878F] mt-1 block">Protection gap</span>
            </div>
          </div>

          {/* Mandatory Cybersecurity Disclaimer */}
          <div className="p-4 rounded-xl bg-[#202740]/60 border border-[#494E6B]/40 flex items-center gap-3 text-xs text-[#c2b5bc]">
            <Info className="w-5 h-5 text-[#985E6D] shrink-0" />
            <p className="leading-relaxed">
              <strong className="text-white">Analyst Notice: </strong>
              {result.disclaimer}
            </p>
          </div>

          {/* Headers Compliance Table */}
          <div className="rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl overflow-hidden">
            <div className="p-5 border-b border-[#494E6B]/30 flex items-center justify-between">
              <h3 className="text-sm font-bold text-white tracking-wide">
                Security Headers Assessment Matrix
              </h3>
              <span className="text-xs font-mono text-[#98878F]">HTTP Status {result.status_code}</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#192034]/60 text-[#98878F] uppercase font-mono tracking-wider border-b border-[#494E6B]/30">
                  <tr>
                    <th className="py-3.5 px-5">Header Name</th>
                    <th className="py-3.5 px-4">Status</th>
                    <th className="py-3.5 px-4">Importance</th>
                    <th className="py-3.5 px-4">Detected Value</th>
                    <th className="py-3.5 px-5">Recommended Value</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#494E6B]/20 text-[#c2b5bc]">
                  {result.headers_table.map((h, i) => {
                    const badge = getStatusBadge(h.status);
                    const Icon = badge.icon;
                    return (
                      <tr key={i} className="hover:bg-[#192034]/40 transition-colors">
                        <td className="py-4 px-5">
                          <div className="font-mono text-white font-bold">{h.name}</div>
                          <div className="text-[11px] text-[#98878F] mt-0.5 max-w-xs leading-normal">
                            {h.purpose}
                          </div>
                        </td>

                        <td className="py-4 px-4 whitespace-nowrap">
                          <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-bold font-mono border ${badge.bg} ${badge.border} ${badge.text}`}>
                            <Icon className="w-3.5 h-3.5" />
                            <span>{badge.label}</span>
                          </span>
                        </td>

                        <td className="py-4 px-4 font-mono uppercase text-[11px]">
                          <span className={h.importance === 'HIGH' ? 'text-[#e58a9d] font-bold' : 'text-[#98878F]'}>
                            {h.importance}
                          </span>
                        </td>

                        <td className="py-4 px-4 font-mono text-[11px] max-w-xs break-all">
                          {h.actual_value ? (
                            <span className="text-white bg-[#192034] px-2 py-1 rounded border border-[#494E6B]/30 block truncate">
                              {h.actual_value}
                            </span>
                          ) : (
                            <span className="text-[#98878F] italic">Not Set</span>
                          )}
                        </td>

                        <td className="py-4 px-5 font-mono text-[11px] max-w-xs text-[#85c9b7]">
                          <span className="bg-[#192034] px-2 py-1 rounded border border-[#3f6e62]/30 block truncate">
                            {h.recommended_value}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Server Information Disclosure */}
          {result.information_disclosure.length > 0 && (
            <div className="p-5 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 space-y-2">
              <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-[#b5834f]" />
                <span>Information Disclosure Headers</span>
              </h4>
              <ul className="space-y-1 text-xs text-[#c2b5bc] font-mono">
                {result.information_disclosure.map((disc, idx) => (
                  <li key={idx} className="p-2 rounded bg-[#192034]/60 border border-[#494E6B]/25">
                    {disc}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

