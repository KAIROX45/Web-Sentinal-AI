import React, { useState, useEffect, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  MailWarning,
  Sparkles,
  Cpu,
  AlertTriangle,
  Link as LinkIcon,
  Building,
  ArrowRight,
  AlertOctagon
} from 'lucide-react';
import { analyzeMessage } from '../services/api';
import { MessageScanResponse } from '../types';
import { ThreatSeverityCard } from '../components/ThreatSeverityCard';
import { EvidencePanel } from '../components/EvidencePanel';
import { VerificationBadge } from '../components/VerificationBadge';
import { LoadingSkeleton } from '../components/LoadingSkeleton';

export const MessageAnalysis: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [content, setContent] = useState(() => searchParams.get('target') || '');
  const [messageType, setMessageType] = useState('auto');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<MessageScanResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const runAnalyze = useCallback(async (textToScan?: string) => {
    const text = (textToScan || content).trim();
    if (!text) return;

    setLoading(true);
    setErrorMsg(null);

    try {
      const data = await analyzeMessage(text, messageType);
      setResult(data);
    } catch (err: any) {
      setErrorMsg(err?.response?.data?.detail || err.message || 'Message analysis failed');
    } finally {
      setLoading(false);
    }
  }, [content, messageType]);

  useEffect(() => {
    const targetParam = searchParams.get('target');
    if (targetParam) {
      runAnalyze(targetParam);
    }
  }, [searchParams, runAnalyze]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    runAnalyze();
  };

  return (
    <div className="space-y-8 pb-12">
      <div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          AI Phishing & Scam Message Analyzer
        </h1>
        <p className="text-xs sm:text-sm text-[#98878F] mt-1">
          Deep behavioral analysis of social engineering lures, artificial urgency, brand impersonation, and deceptive URLs.
        </p>
      </div>

      {/* Input Textarea Form */}
      <form onSubmit={handleSubmit} className="p-5 sm:p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <label className="text-xs font-mono uppercase tracking-wider text-[#98878F] flex items-center gap-2">
            <MailWarning className="w-4 h-4 text-[#985E6D]" />
            <span>Message Content / Email Headers</span>
          </label>

          <div className="flex items-center gap-2">
            <select
              value={messageType}
              onChange={(e) => setMessageType(e.target.value)}
              className="bg-[#192034] border border-[#494E6B]/40 rounded-xl px-3 py-1.5 text-xs text-white focus:outline-none focus:border-[#985E6D]"
            >
              <option value="auto">Auto-Detect Type</option>
              <option value="email">Email</option>
              <option value="sms">SMS / Smishing</option>
              <option value="chat">Chat / Instant Message</option>
            </select>
          </div>
        </div>

        <textarea
          rows={5}
          value={content}
          onChange={(e) => setContent(e.target.value)}
          placeholder="Paste email headers, SMS notification, or suspicious chat message here..."
          className="w-full bg-[#192034]/90 border border-[#494E6B]/40 focus:border-[#985E6D] rounded-xl p-4 text-sm text-white placeholder-[#98878F] focus:outline-none font-mono resize-y"
        />

        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
          {/* Quick presets */}
          <div className="flex flex-wrap items-center gap-1.5 text-xs">
            <span className="text-[#98878F]">Demo Presets:</span>
            <button
              type="button"
              onClick={() => {
                const sample = 'URGENT: Your PayPal account has been suspended within 24 hours due to unauthorized transactions. Click here to confirm your password: http://paypa1-security-verify.com/login';
                setContent(sample);
                runAnalyze(sample);
              }}
              className="px-2 py-0.5 rounded bg-[#192034] hover:bg-[#494E6B]/30 text-[#e58a9d] border border-[#985E6D]/40 text-[11px]"
            >
              Urgent Suspension Scam
            </button>
            <button
              type="button"
              onClick={() => {
                const sample = 'USPS Notification: Your package delivery has been put on hold due to missing address details. Pay $1.99 fee: https://usps-redelivery-tracking.xyz';
                setContent(sample);
                runAnalyze(sample);
              }}
              className="px-2 py-0.5 rounded bg-[#192034] hover:bg-[#494E6B]/30 text-[#e58a9d] border border-[#985E6D]/40 text-[11px]"
            >
              Postal Smishing
            </button>
            <button
              type="button"
              onClick={() => {
                const sample = 'Hi Alex, attached is the revised Q4 infrastructure budget spreadsheet. Let me know if you have any questions before the meeting.';
                setContent(sample);
                runAnalyze(sample);
              }}
              className="px-2 py-0.5 rounded bg-[#192034] hover:bg-[#494E6B]/30 text-[#85c9b7] border border-[#3f6e62]/40 text-[11px]"
            >
              Benign Team Message
            </button>
          </div>

          <button
            type="submit"
            disabled={loading || !content.trim()}
            className="w-full sm:w-auto px-6 py-3 rounded-xl bg-[#985E6D] hover:bg-[#ad6d7d] text-white font-semibold text-xs shadow-[0_0_16px_rgba(152,94,109,0.35)] disabled:opacity-40 transition-all cursor-pointer flex items-center justify-center gap-2 whitespace-nowrap"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                <span>Analyzing AI Signals...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-4 h-4" />
                <span>Analyze Message</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>
      </form>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-[#985E6D]/20 border border-[#985E6D]/50 text-[#e58a9d] text-xs flex items-center gap-3">
          <AlertOctagon className="w-5 h-5 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {loading && <LoadingSkeleton label="AI Reasoning: Evaluating Psychological Lures and Brand Impersonation..." />}

      {result && !loading && (
        <div className="space-y-6">
          <ThreatSeverityCard
            target={result.attack_category}
            scanType="AI Phishing Analysis"
            riskLevel={result.risk_level}
            riskScore={result.risk_score}
            summary={result.explanation}
            canonicalHash={result.canonical_hash}
            timestamp={result.timestamp}
          />

          {/* AI vs Verified Threat Feed Disclaimer */}
          <div className="p-4 rounded-xl bg-[#202740]/60 border border-[#494E6B]/40 flex items-center justify-between gap-3 text-xs text-[#c2b5bc]">
            <div className="flex items-center gap-2.5">
              <Cpu className="w-4 h-4 text-[#985E6D] shrink-0" />
              <span>
                <strong className="text-white">Analysis Source: </strong>
                {result.source === 'gemini_ai' ? 'Google Gemini 2.5 Multi-Modal Reasoning' : 'WebSentinel Cybersecurity Heuristic Engine'}
              </span>
            </div>
            <div className="flex items-center gap-3 font-mono text-[11px]">
              <span className="px-2 py-0.5 rounded bg-[#192034] text-[#85c9b7] border border-[#85c9b7]/30">
                Model Confidence: {result.confidence_score}%
              </span>
              <span className="px-2 py-0.5 rounded bg-[#192034] text-[#c28190] border border-[#985E6D]/30 hidden sm:inline">
                Risk Score: {result.risk_score}/100
              </span>
            </div>
          </div>

          {/* Psychological Manipulation Techniques Identified */}
          {result.manipulation_techniques.length > 0 && (
            <div className="p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl space-y-3">
              <h3 className="text-sm font-bold text-white tracking-wide">
                Detected Social Engineering Patterns
              </h3>

              <div className="flex flex-wrap gap-2">
                {result.manipulation_techniques.map((tech, idx) => (
                  <span
                    key={idx}
                    className="px-3 py-1.5 rounded-xl bg-[#985E6D]/20 text-[#e58a9d] border border-[#985E6D]/40 text-xs font-mono font-medium flex items-center gap-1.5"
                  >
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>{tech}</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Extracted Deceptive URLs & Suspicious Entities Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Extracted URLs */}
            <div className="p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
                  <LinkIcon className="w-4 h-4 text-[#985E6D]" />
                  <span>Extracted Embedded Links</span>
                </h3>
                <span className="text-xs font-mono text-[#98878F]">
                  {result.extracted_urls.length} Found
                </span>
              </div>

              {result.extracted_urls.length === 0 ? (
                <p className="text-xs text-[#98878F] py-3">No embedded hyperlinks detected in content.</p>
              ) : (
                <div className="space-y-2">
                  {result.extracted_urls.map((u, i) => (
                    <div
                      key={i}
                      className="p-3 rounded-xl bg-[#192034]/70 border border-[#494E6B]/30 flex flex-col gap-1 text-xs font-mono"
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-white font-semibold truncate max-w-xs">{u.domain}</span>
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                          u.is_suspicious ? 'bg-[#985E6D]/30 text-[#e58a9d]' : 'bg-[#3f6e62]/30 text-[#85c9b7]'
                        }`}>
                          {u.is_suspicious ? 'SUSPICIOUS' : 'CLEAN'}
                        </span>
                      </div>
                      <span className="text-[11px] text-[#98878F] truncate">{u.url}</span>
                      {u.risk_indicator && (
                        <span className="text-[10px] text-[#e58a9d]">{u.risk_indicator}</span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Suspicious Entities */}
            <div className="p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
                  <Building className="w-4 h-4 text-[#985E6D]" />
                  <span>Impersonated Entities & Targets</span>
                </h3>
                <span className="text-xs font-mono text-[#98878F]">
                  {result.suspicious_entities.length} Detected
                </span>
              </div>

              {result.suspicious_entities.length === 0 ? (
                <p className="text-xs text-[#98878F] py-3">No specific corporate brands or callback contacts flagged.</p>
              ) : (
                <div className="space-y-2">
                  {result.suspicious_entities.map((ent, i) => (
                    <div
                      key={i}
                      className="p-3 rounded-xl bg-[#192034]/70 border border-[#494E6B]/30 text-xs font-mono space-y-0.5"
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-white font-bold">{ent.entity}</span>
                        <span className="text-[10px] text-[#c28190] uppercase">{ent.entity_type}</span>
                      </div>
                      <p className="text-[11px] text-[#98878F] leading-normal">{ent.context}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Evidence Breakdown */}
          <EvidencePanel evidence={result.evidence} />

          {/* Recommended User Actions */}
          {result.recommended_actions && result.recommended_actions.length > 0 && (
            <div className="p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl space-y-4">
              <h3 className="text-sm font-bold text-white tracking-wide">
                Recommended Defensive Steps
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {result.recommended_actions.map((rec, i) => (
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
            target={result.attack_category}
            threatType="message"
            riskLevel={result.risk_level}
            riskScore={result.confidence_score}
            findingsDigest={`${result.attack_category} (${result.source}) - ${result.evidence.length} evidence indicators`}
            canonicalHash={result.canonical_hash}
          />
        </div>
      )}
    </div>
  );
};

