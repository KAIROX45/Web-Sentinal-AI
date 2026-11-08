import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Globe, Network, MailWarning, ArrowRight, Sparkles } from 'lucide-react';
import { classifyInput } from '../services/api';
import { UnifiedClassification } from '../types';

interface UnifiedSearchBarProps {
  onScanComplete?: (scanResult: unknown) => void;
  autoFocus?: boolean;
}

export const UnifiedSearchBar: React.FC<UnifiedSearchBarProps> = ({ autoFocus = false }) => {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [classification, setClassification] = useState<UnifiedClassification | null>(null);
  const [isClassifying, setIsClassifying] = useState(false);

  // Auto classify on typing debounce
  useEffect(() => {
    if (!query.trim()) return;

    const timer = setTimeout(async () => {
      setIsClassifying(true);
      try {
        const res = await classifyInput(query);
        setClassification(res);
      } catch {
        // Fallback local heuristic classifier
        const clean = query.trim();
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(clean)) {
          setClassification({
            type: 'ip',
            confidence: 1.0,
            target: clean,
            label: 'IPv4 Address',
            route: '/ip'
          });
        } else if (clean.startsWith('http') || clean.includes('.com') || clean.includes('.org') || clean.includes('.io') || clean.includes('.xyz') || clean.includes('/')) {
          setClassification({
            type: 'url',
            confidence: 0.95,
            target: clean,
            label: 'Website URL',
            route: '/url'
          });
        } else {
          setClassification({
            type: 'message',
            confidence: 0.85,
            target: clean,
            label: 'Suspicious Message / Email',
            route: '/message'
          });
        }
      } finally {
        setIsClassifying(false);
      }
    }, 250);

    return () => clearTimeout(timer);
  }, [query]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;

    if (classification) {
      navigate(`${classification.route}?target=${encodeURIComponent(query)}`);
    } else {
      navigate(`/url?target=${encodeURIComponent(query)}`);
    }
  };

  const handleQuickDemo = (text: string) => {
    setQuery(text);
  };

  return (
    <div className="w-full max-w-4xl mx-auto">
      <form onSubmit={handleSubmit} className="relative group">
        <div className="relative flex items-center bg-[#202740]/90 border-2 border-[#494E6B]/50 hover:border-[#985E6D]/70 focus-within:border-[#985E6D] rounded-2xl shadow-[0_12px_36px_-8px_rgba(25,32,52,0.8)] backdrop-blur-xl transition-all duration-300 p-2">
          {/* Target Icon */}
          <div className="pl-4 pr-3 text-[#98878F] group-focus-within:text-[#985E6D] transition-colors">
            {classification?.type === 'url' ? (
              <Globe className="w-6 h-6" />
            ) : classification?.type === 'ip' ? (
              <Network className="w-6 h-6" />
            ) : classification?.type === 'message' ? (
              <MailWarning className="w-6 h-6" />
            ) : (
              <Search className="w-6 h-6" />
            )}
          </div>

          {/* Input text / multiline auto */}
          <input
            type="text"
            value={query}
            onChange={(e) => {
              const val = e.target.value;
              setQuery(val);
              if (!val.trim()) setClassification(null);
            }}
            autoFocus={autoFocus}
            placeholder="Enter URL, IP address, or paste suspicious email / SMS message..."
            className="w-full bg-transparent text-white placeholder-[#98878F] text-base focus:outline-none py-3 px-2 font-mono"
          />

          {/* Classification indicator pill */}
          {isClassifying ? (
            <div className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#494E6B]/20 text-xs text-[#98878F] mr-3 whitespace-nowrap">
              <span className="w-2.5 h-2.5 border-2 border-[#985E6D] border-t-transparent rounded-full animate-spin" />
              <span className="text-[11px]">Classifying...</span>
            </div>
          ) : classification && query.trim() ? (
            <div className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#494E6B]/30 border border-[#494E6B]/50 text-xs text-[#c2b5bc] mr-3 whitespace-nowrap">
              <span className="w-1.5 h-1.5 rounded-full bg-[#985E6D] animate-ping" />
              <span className="text-[11px] text-[#98878F]">Routing to:</span>
              <span className="font-semibold text-white">{classification.label}</span>
            </div>
          ) : null}

          {/* Action button */}
          <button
            type="submit"
            disabled={!query.trim()}
            className="flex items-center gap-2 px-6 py-3.5 rounded-xl bg-gradient-to-r from-[#985E6D] to-[#784754] hover:from-[#ad6d7d] hover:to-[#985E6D] text-white font-semibold text-sm shadow-[0_0_20px_rgba(152,94,109,0.4)] disabled:opacity-40 disabled:cursor-not-allowed transition-all cursor-pointer whitespace-nowrap"
          >
            <span>Investigate</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </form>

      {/* Quick Scenario Preset Pills */}
      <div className="mt-4 flex flex-wrap items-center gap-2 text-xs">
        <span className="text-[#98878F] flex items-center gap-1 font-medium mr-1">
          <Sparkles className="w-3.5 h-3.5 text-[#985E6D]" /> Demo Scenarios:
        </span>

        {/* 3 Benign Scenarios */}
        <button
          type="button"
          onClick={() => handleQuickDemo('https://example.com')}
          className="px-2.5 py-1 rounded-lg bg-[#202740] hover:bg-[#494E6B]/30 text-[#85c9b7] border border-[#3f6e62]/40 text-[11px] font-mono transition-colors"
        >
          ✓ Benign URL: example.com
        </button>

        <button
          type="button"
          onClick={() => handleQuickDemo('8.8.8.8')}
          className="px-2.5 py-1 rounded-lg bg-[#202740] hover:bg-[#494E6B]/30 text-[#85c9b7] border border-[#3f6e62]/40 text-[11px] font-mono transition-colors"
        >
          ✓ Clean IP: 8.8.8.8
        </button>

        <button
          type="button"
          onClick={() => handleQuickDemo('Hi team, our cybersecurity sprint retrospective has been scheduled for Friday at 14:00 UTC.')}
          className="px-2.5 py-1 rounded-lg bg-[#202740] hover:bg-[#494E6B]/30 text-[#85c9b7] border border-[#3f6e62]/40 text-[11px] transition-colors"
        >
          ✓ Clean Message
        </button>

        {/* 3 Suspicious/Malicious Scenarios */}
        <button
          type="button"
          onClick={() => handleQuickDemo('http://paypa1-security-verification.com/login')}
          className="px-2.5 py-1 rounded-lg bg-[#202740] hover:bg-[#494E6B]/30 text-[#e58a9d] border border-[#985E6D]/40 text-[11px] font-mono transition-colors"
        >
          ⚠ Typosquat URL
        </button>

        <button
          type="button"
          onClick={() => handleQuickDemo('45.154.255.89')}
          className="px-2.5 py-1 rounded-lg bg-[#202740] hover:bg-[#494E6B]/30 text-[#e58a9d] border border-[#985E6D]/40 text-[11px] font-mono transition-colors"
        >
          ⚠ Malicious C2 IP
        </button>

        <button
          type="button"
          onClick={() => handleQuickDemo('URGENT: Your PayPal account has been suspended within 24 hours due to suspicious activity. Verify credentials immediately: http://paypa1-security-login.xyz')}
          className="px-2.5 py-1 rounded-lg bg-[#202740] hover:bg-[#494E6B]/30 text-[#e58a9d] border border-[#985E6D]/40 text-[11px] transition-colors"
        >
          ⚠ Phishing SMS
        </button>
      </div>
    </div>
  );
};

