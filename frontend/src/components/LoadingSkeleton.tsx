import React from 'react';
import { Shield, Sparkles } from 'lucide-react';

interface LoadingSkeletonProps {
  label?: string;
}

export const LoadingSkeleton: React.FC<LoadingSkeletonProps> = ({
  label = 'Performing Deep Security Analysis...',
}) => {
  return (
    <div className="w-full p-8 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl relative overflow-hidden text-center space-y-6">
      {/* Animated glowing scanning beam */}
      <div className="absolute inset-0 bg-gradient-to-r from-transparent via-[#985E6D]/15 to-transparent -translate-x-full animate-[shimmer_2s_infinite]" />

      <div className="relative z-10 flex flex-col items-center justify-center">
        <div className="relative mb-4">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-[#985E6D] to-[#494E6B] p-0.5 shadow-[0_0_25px_rgba(152,94,109,0.5)] flex items-center justify-center animate-pulse">
            <div className="w-full h-full bg-[#192034] rounded-[14px] flex items-center justify-center">
              <Shield className="w-8 h-8 text-[#985E6D]" />
            </div>
          </div>
          <Sparkles className="w-5 h-5 text-[#c28190] absolute -top-1 -right-1 animate-bounce" />
        </div>

        <h3 className="text-base font-bold text-white tracking-wide font-mono">
          {label}
        </h3>
        <p className="text-xs text-[#98878F] max-w-md mt-1">
          Evaluating DNS records, typosquatting vectors, homograph lookalikes, SSL/TLS handshake, and verified threat feeds...
        </p>
      </div>

      {/* Placeholder wireframe blocks */}
      <div className="space-y-3 max-w-xl mx-auto pt-2">
        <div className="h-4 bg-[#494E6B]/25 rounded-lg w-3/4 mx-auto animate-pulse" />
        <div className="h-4 bg-[#494E6B]/20 rounded-lg w-1/2 mx-auto animate-pulse" />
        <div className="h-20 bg-[#192034]/70 rounded-xl w-full border border-[#494E6B]/20 animate-pulse" />
      </div>
    </div>
  );
};

