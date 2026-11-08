import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  Globe,
  Lock,
  MailWarning,
  Network,
  Link2,
  FileCode2,
  ArrowRight,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Cpu
} from 'lucide-react';
import { UnifiedSearchBar } from '../components/UnifiedSearchBar';
import { getThreatStats } from '../services/api';
import { ThreatStats } from '../types';

export const Home: React.FC = () => {
  const [stats, setStats] = useState<ThreatStats | null>(null);
  const [apiError, setApiError] = useState(false);

  useEffect(() => {
    getThreatStats()
      .then((data) => {
        setStats(data);
        setApiError(false);
      })
      .catch((err) => {
        console.error('Failed to load telemetry stats:', err);
        setApiError(true);
      });
  }, []);

  const getDefenseGrade = (score: number) => {
    if (score >= 90) return 'Grade A+ Resilient';
    if (score >= 80) return 'Grade A Optimal';
    if (score >= 70) return 'Grade B Monitored';
    if (score >= 50) return 'Grade C Elevated Risk';
    return 'Grade D Critical';
  };

  const featureCards = [
    {
      title: 'URL Threat Analysis',
      desc: 'Deep inspection of malicious domains, typosquatting imitation, homograph lookalikes, and DNS infrastructure.',
      icon: Globe,
      link: '/url',
      tag: 'Heuristics + Intel'
    },
    {
      title: 'AI Phishing & Scam Analyzer',
      desc: 'Detects psychological manipulation, brand spoofing, urgent coercion, and fraudulent payment solicitations.',
      icon: MailWarning,
      link: '/message',
      tag: 'Gemini 2.5 AI'
    },
    {
      title: 'IP Address Intelligence',
      desc: 'Routable IP classification, autonomous system ownership (ASN), reverse DNS, and abuse reputation scoring.',
      icon: Network,
      link: '/ip',
      tag: 'SSRF Protected'
    },
    {
      title: 'TLS Certificate Inspection',
      desc: 'Validates SSL/TLS handshake, trust chain hierarchy, remaining expiration days, and RFC hostname matching.',
      icon: Lock,
      link: '/tls',
      tag: 'Cryptographic'
    },
    {
      title: 'HTTP Security Headers',
      desc: 'Assesses HSTS, Content-Security-Policy, and anti-clickjacking headers to ensure defensive compliance.',
      icon: FileCode2,
      link: '/headers',
      tag: 'Defense-in-Depth'
    },
    {
      title: 'Blockchain Verification',
      desc: 'Anchors canonical SHA-256 investigation fingerprints on EVM smart contracts for immutable audit proof.',
      icon: Link2,
      link: '/blockchain',
      tag: 'EVM Solidity'
    }
  ];

  return (
    <div className="space-y-12 pb-12">
      {/* Hero Section */}
      <section className="text-center pt-6 pb-4 space-y-6 max-w-4xl mx-auto">
        {/* Top Announcement Badge */}
        <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-[#202740] border border-[#494E6B]/50 shadow-[0_0_16px_rgba(152,94,109,0.2)] text-xs text-[#c2b5bc]">
          <span className="w-2 h-2 rounded-full bg-[#985E6D] animate-ping" />
          <span className="font-mono text-white font-semibold">WebSentinel AI v1.0</span>
          <span className="text-[#98878F]">—</span>
          <span>Enterprise Cyber Threat Intelligence & AI Defense Platform</span>
        </div>

        {/* Main Headline */}
        <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight text-white leading-tight">
          Your Digital World.{' '}
          <span className="bg-gradient-to-r from-white via-[#c28190] to-[#985E6D] bg-clip-text text-transparent">
            Under Intelligent Protection.
          </span>
        </h1>

        <p className="text-base sm:text-lg text-[#98878F] max-w-2xl mx-auto leading-relaxed">
          WebSentinel AI delivers enterprise-grade threat detection across malicious URLs, fraudulent communications, suspicious IP addresses, and compromised certificates with cryptographic verification.
        </p>

        {/* Unified Search Input */}
        <div className="pt-4">
          <UnifiedSearchBar autoFocus />
        </div>
      </section>

      {apiError && (
        <div className="max-w-5xl mx-auto p-4 rounded-xl bg-[#985E6D]/20 border border-[#985E6D]/50 text-[#e58a9d] text-xs flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>Telemetry endpoint unreachable. Please verify backend is running on port 8000.</span>
          </div>
        </div>
      )}

      {/* Security Metrics Row */}
      <section className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-5xl mx-auto">
        <div className="p-5 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/35 backdrop-blur-xl">
          <div className="flex items-center justify-between text-[#98878F] text-xs font-mono mb-2">
            <span>TOTAL SCANS</span>
            <Activity className="w-4 h-4 text-[#985E6D]" />
          </div>
          <div className="text-3xl font-extrabold text-white font-mono">
            {stats ? stats.total_scans : 0}
          </div>
          <div className="text-[11px] text-[#85c9b7] mt-1 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" /> Live analysis active
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/35 backdrop-blur-xl">
          <div className="flex items-center justify-between text-[#98878F] text-xs font-mono mb-2">
            <span>MALICIOUS DETECTED</span>
            <Shield className="w-4 h-4 text-[#985E6D]" />
          </div>
          <div className="text-3xl font-extrabold text-[#e58a9d] font-mono">
            {stats ? stats.malicious_detected : 0}
          </div>
          <div className="text-[11px] text-[#98878F] mt-1">
            Flagged across global feeds
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/35 backdrop-blur-xl">
          <div className="flex items-center justify-between text-[#98878F] text-xs font-mono mb-2">
            <span>THREATS BLOCKED</span>
            <AlertTriangle className="w-4 h-4 text-[#b5834f]" />
          </div>
          <div className="text-3xl font-extrabold text-white font-mono">
            {stats ? stats.threats_blocked : 0}
          </div>
          <div className="text-[11px] text-[#85c9b7] mt-1">
            Proactive mitigation
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/35 backdrop-blur-xl">
          <div className="flex items-center justify-between text-[#98878F] text-xs font-mono mb-2">
            <span>DEFENSE SCORE</span>
            <Cpu className="w-4 h-4 text-[#85c9b7]" />
          </div>
          <div className="text-3xl font-extrabold text-[#85c9b7] font-mono">
            {stats ? stats.security_score : 100}<span className="text-sm text-[#98878F]">/100</span>
          </div>
          <div className="text-[11px] text-[#98878F] mt-1">
            {stats ? getDefenseGrade(stats.security_score) : 'Grade A+ Resilient'}
          </div>
        </div>
      </section>

      {/* Digital Security Network Visual Representation */}
      <section className="p-8 rounded-3xl bg-gradient-to-b from-[#202740]/90 to-[#192034] border border-[#494E6B]/40 shadow-2xl relative overflow-hidden max-w-5xl mx-auto">
        <div className="absolute top-0 right-0 w-80 h-80 bg-[#985E6D]/10 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col lg:flex-row items-center justify-between gap-8 relative z-10">
          <div className="space-y-4 max-w-lg">
            <span className="text-xs font-mono uppercase tracking-widest text-[#985E6D] font-bold">
              Multi-Layer Threat Engine
            </span>
            <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
              Unified Security Architecture
            </h2>
            <p className="text-sm text-[#98878F] leading-relaxed">
              Every target undergoes heuristic token decomposition, DNS boundary resolution, typosquatting distance modeling, and cryptographic hash verification before reaching the analyst.
            </p>
            <div className="pt-2 flex flex-wrap gap-2 text-xs font-mono">
              <span className="px-3 py-1 rounded-lg bg-[#192034] border border-[#494E6B]/40 text-[#c2b5bc]">
                RFC 1918 SSRF Safe
              </span>
              <span className="px-3 py-1 rounded-lg bg-[#192034] border border-[#494E6B]/40 text-[#c2b5bc]">
                EVM SHA-256 Ledger
              </span>
              <span className="px-3 py-1 rounded-lg bg-[#192034] border border-[#494E6B]/40 text-[#c2b5bc]">
                Gemini Multi-Modal
              </span>
            </div>
          </div>

          {/* Visual Network Node Diagram */}
          <div className="w-full lg:w-96 p-5 rounded-2xl bg-[#192034]/80 border border-[#494E6B]/40 space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between text-[#98878F] pb-2 border-b border-[#494E6B]/30">
              <span>SCAN PIPELINE</span>
              <span className="text-[#85c9b7]">PARALLEL EXECUTION</span>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between p-2 rounded-lg bg-[#202740] border border-[#494E6B]/30">
                <span className="text-white flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-[#985E6D]" /> 01. SSRF & DNS Resolver
                </span>
                <span className="text-[#85c9b7]">PROTECTED</span>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-[#202740] border border-[#494E6B]/30">
                <span className="text-white flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-[#b5834f]" /> 02. Typosquat & Homoglyphs
                </span>
                <span className="text-[#c28190]">Damerau-Levenshtein</span>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-[#202740] border border-[#494E6B]/30">
                <span className="text-white flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-[#985E6D]" /> 03. Gemini AI / Heuristic Core
                </span>
                <span className="text-[#85c9b7]">REASONING</span>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-[#202740] border border-[#494E6B]/30">
                <span className="text-white flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-[#4a7568]" /> 04. EVM Canonical Proof
                </span>
                <span className="text-[#85c9b7]">IMMUTABLE</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Quick Action Investigation Cards */}
      <section className="space-y-6 max-w-5xl mx-auto">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-xl font-bold text-white tracking-tight">
              Investigation Modules
            </h3>
            <p className="text-xs text-[#98878F] mt-0.5">
              Select a specialized cybersecurity module for in-depth analysis.
            </p>
          </div>
          <Link
            to="/dashboard"
            className="flex items-center gap-1.5 text-xs text-[#c28190] hover:text-white transition-colors font-medium"
          >
            <span>Open Dashboard</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {featureCards.map((feat) => {
            const Icon = feat.icon;
            return (
              <Link
                key={feat.link}
                to={feat.link}
                className="group p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/35 hover:border-[#985E6D]/60 hover:shadow-[0_8px_24px_-6px_rgba(152,94,109,0.3)] backdrop-blur-xl transition-all duration-300 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-4">
                    <div className="w-10 h-10 rounded-xl bg-[#192034] border border-[#494E6B]/40 group-hover:border-[#985E6D]/50 flex items-center justify-center text-[#985E6D] transition-colors">
                      <Icon className="w-5 h-5" />
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#494E6B]/25 text-[#c28190] border border-[#494E6B]/35">
                      {feat.tag}
                    </span>
                  </div>

                  <h4 className="text-base font-bold text-white group-hover:text-[#c28190] transition-colors mb-2">
                    {feat.title}
                  </h4>
                  <p className="text-xs text-[#98878F] leading-relaxed">
                    {feat.desc}
                  </p>
                </div>

                <div className="pt-5 mt-4 border-t border-[#494E6B]/25 flex items-center justify-between text-xs font-semibold text-[#98878F] group-hover:text-white transition-colors">
                  <span>Launch Inspection</span>
                  <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform text-[#985E6D]" />
                </div>
              </Link>
            );
          })}
        </div>
      </section>
    </div>
  );
};

