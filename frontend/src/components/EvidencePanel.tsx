import React, { useState } from 'react';
import { ChevronDown, ChevronUp, ShieldAlert, CheckCircle2 } from 'lucide-react';
import { EvidenceItem } from '../types';
import { getRiskLevelBadge } from '../utils/formatters';

interface EvidencePanelProps {
  evidence: EvidenceItem[];
  title?: string;
}

export const EvidencePanel: React.FC<EvidencePanelProps> = ({
  evidence,
  title = 'Technical Evidence & Security Indicators',
}) => {
  const [isOpen, setIsOpen] = useState(true);

  if (!evidence || evidence.length === 0) {
    return (
      <div className="p-6 rounded-2xl bg-[#202740]/60 border border-[#494E6B]/30 text-center">
        <CheckCircle2 className="w-8 h-8 text-[#85c9b7] mx-auto mb-2 opacity-80" />
        <h4 className="text-sm font-semibold text-white">No Threat Indicators Triggered</h4>
        <p className="text-xs text-[#98878F] mt-1">
          Zero active heuristics, malicious signatures, or threat feed entries were identified during inspection.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 overflow-hidden backdrop-blur-xl">
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="w-full px-6 py-4 flex items-center justify-between bg-[#192034]/40 hover:bg-[#192034]/70 border-b border-[#494E6B]/30 transition-colors cursor-pointer text-left"
      >
        <div className="flex items-center gap-3">
          <ShieldAlert className="w-5 h-5 text-[#985E6D]" />
          <div>
            <h3 className="text-sm font-bold text-white tracking-wide">{title}</h3>
            <p className="text-xs text-[#98878F]">
              {evidence.length} evidence {evidence.length === 1 ? 'item' : 'items'} identified
            </p>
          </div>
        </div>
        <div className="text-[#98878F]">
          {isOpen ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
        </div>
      </button>

      {isOpen && (
        <div className="divide-y divide-[#494E6B]/25">
          {evidence.map((item, idx) => {
            const badge = getRiskLevelBadge(item.severity);
            return (
              <div
                key={idx}
                className="p-4 sm:px-6 hover:bg-[#192034]/30 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] font-mono uppercase tracking-wider text-[#98878F] px-2 py-0.5 rounded bg-[#494E6B]/25 border border-[#494E6B]/30">
                      {item.category}
                    </span>
                    <span className="text-xs font-semibold text-white font-mono">
                      {item.indicator}
                    </span>
                  </div>
                  <p className="text-xs text-[#c2b5bc] leading-relaxed pt-0.5">
                    {item.description}
                  </p>
                  <span className="text-[10px] text-[#98878F] font-mono">
                    Source: {item.source}
                  </span>
                </div>

                <div className="self-start sm:self-center">
                  <span
                    className={`inline-flex items-center px-2.5 py-1 rounded-lg text-xs font-bold font-mono border ${badge.bg} ${badge.border} ${badge.text}`}
                  >
                    {item.severity}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

