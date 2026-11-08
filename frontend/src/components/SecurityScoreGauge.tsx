import React from 'react';
import { ShieldCheck, AlertCircle } from 'lucide-react';
import { SecurityScore } from '../types';
import { getScoreColor } from '../utils/formatters';

interface SecurityScoreGaugeProps {
  scoreData?: SecurityScore;
}

export const SecurityScoreGauge: React.FC<SecurityScoreGaugeProps> = ({ scoreData }) => {
  const score = scoreData?.score ?? 85;
  const grade = scoreData?.grade ?? 'B';
  const label = scoreData?.label ?? 'Security Posture Assessed';
  const color = getScoreColor(score);

  // SVG circular gauge calculations
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl flex items-center justify-between gap-6">
      <div className="space-y-1">
        <span className="text-xs font-mono uppercase tracking-wider text-[#98878F]">
          Security Health Grade
        </span>
        <div className="flex items-baseline gap-2">
          <span className="text-3xl font-extrabold text-white font-mono">{score}</span>
          <span className="text-sm font-medium text-[#98878F]">/ 100</span>
        </div>
        <p className="text-xs text-[#c2b5bc] font-medium flex items-center gap-1.5 pt-1">
          {score >= 70 ? (
            <ShieldCheck className="w-3.5 h-3.5 text-[#85c9b7]" />
          ) : (
            <AlertCircle className="w-3.5 h-3.5 text-[#e58a9d]" />
          )}
          <span>{label}</span>
        </p>
      </div>

      {/* Radial Meter */}
      <div className="relative flex items-center justify-center w-28 h-28">
        <svg className="w-full h-full -rotate-90 transform" viewBox="0 0 100 100">
          <circle
            cx="50"
            cy="50"
            r={radius}
            stroke="#2d3553"
            strokeWidth="8"
            fill="transparent"
          />
          <circle
            cx="50"
            cy="50"
            r={radius}
            stroke={color}
            strokeWidth="8"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Grade text inside ring */}
        <div className="absolute flex flex-col items-center justify-center">
          <span className="text-2xl font-black font-mono" style={{ color }}>
            {grade}
          </span>
          <span className="text-[9px] uppercase tracking-wider text-[#98878F]">GRADE</span>
        </div>
      </div>
    </div>
  );
};

