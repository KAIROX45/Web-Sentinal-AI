import React from 'react';
import { Lock, ShieldCheck, AlertTriangle, Key } from 'lucide-react';
import { CertificateChainNode } from '../types';

interface CertificateChainTreeProps {
  nodes: CertificateChainNode[];
  isExpired: boolean;
  isSelfSigned: boolean;
}

export const CertificateChainTree: React.FC<CertificateChainTreeProps> = ({
  nodes,
  isExpired,
  isSelfSigned,
}) => {
  if (!nodes || nodes.length === 0) {
    return (
      <div className="p-6 rounded-2xl bg-[#202740]/60 border border-[#494E6B]/30 text-center text-[#98878F] text-xs">
        No certificate chain data available.
      </div>
    );
  }

  // Reverse so Root is at top, Leaf at bottom
  const orderedNodes = [...nodes].reverse();

  return (
    <div className="p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl">
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-2">
          <Lock className="w-4 h-4 text-[#985E6D]" />
          <h3 className="text-sm font-bold text-white tracking-wide">
            Certificate Trust Hierarchy
          </h3>
        </div>
        <span className="text-xs font-mono text-[#98878F]">
          {isSelfSigned ? 'Self-Signed (No External Chain)' : `${nodes.length} Chain Levels`}
        </span>
      </div>

      <div className="space-y-4 relative before:absolute before:left-5 before:top-4 before:bottom-4 before:w-0.5 before:bg-[#494E6B]/50">
        {orderedNodes.map((node, index) => {
          const isLeaf = index === orderedNodes.length - 1;
          const isRoot = index === 0 && !isLeaf;

          return (
            <div key={index} className="relative flex items-start gap-4 group">
              {/* Node Icon Indicator */}
              <div
                className={`relative z-10 w-10 h-10 rounded-xl flex items-center justify-center border transition-all ${
                  isLeaf
                    ? isExpired
                      ? 'bg-[#985E6D]/20 border-[#985E6D] text-[#e58a9d]'
                      : 'bg-[#3f6e62]/20 border-[#3f6e62] text-[#85c9b7]'
                    : isRoot
                    ? 'bg-[#494E6B]/30 border-[#494E6B] text-[#c2b5bc]'
                    : 'bg-[#202740] border-[#494E6B]/60 text-[#98878F]'
                }`}
              >
                {isLeaf ? (
                  isExpired ? <AlertTriangle className="w-5 h-5" /> : <Lock className="w-5 h-5" />
                ) : isRoot ? (
                  <ShieldCheck className="w-5 h-5" />
                ) : (
                  <Key className="w-5 h-5" />
                )}
              </div>

              {/* Node Content Card */}
              <div className="flex-1 p-4 rounded-xl bg-[#192034]/60 border border-[#494E6B]/30 group-hover:border-[#985E6D]/40 transition-colors">
                <div className="flex flex-wrap items-center justify-between gap-2 mb-1">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-[#494E6B]/30 text-[#c2b5bc]">
                      {isLeaf ? 'Leaf Certificate (Server)' : isRoot ? 'Root CA' : 'Intermediate CA'}
                    </span>
                    <h4 className="text-xs font-bold text-white font-mono">{node.subject}</h4>
                  </div>
                  <span className="text-[11px] text-[#98878F] font-mono">
                    Alg: {node.signature_algorithm}
                  </span>
                </div>

                <div className="text-[11px] text-[#98878F] flex flex-wrap gap-x-4 gap-y-1 mt-2 font-mono">
                  <span>Issued By: <span className="text-[#c2b5bc]">{node.issuer}</span></span>
                  <span>Valid: <span className="text-[#c2b5bc]">{node.valid_from}</span> to <span className="text-[#c2b5bc]">{node.valid_to}</span></span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

