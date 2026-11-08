import React, { useState, useEffect } from 'react';
import { useLocation, Link } from 'react-router-dom';
import { Menu, Cpu, Link2, Clock } from 'lucide-react';
import { getBlockchainStatus, getHealth } from '../services/api';

interface HeaderProps {
  setMobileOpen: (open: boolean) => void;
}

export const Header: React.FC<HeaderProps> = ({ setMobileOpen }) => {
  const location = useLocation();
  const [utcTime, setUtcTime] = useState<string>('');
  const [blockchainNet, setBlockchainNet] = useState<string>('Local Ledger');
  const [aiStatus, setAiStatus] = useState<boolean>(false);

  useEffect(() => {
    const updateClock = () => {
      const now = new Date();
      setUtcTime(now.toUTCString().replace('GMT', 'UTC'));
    };
    updateClock();
    const timer = setInterval(updateClock, 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    getBlockchainStatus()
      .then((data) => {
        setBlockchainNet(data.network.includes('Sepolia') ? 'Sepolia Testnet' : 'EVM Ledger');
      })
      .catch(() => {});

    getHealth()
      .then((data) => {
        setAiStatus(Boolean(data?.integrations?.gemini_ai));
      })
      .catch(() => {});
  }, []);

  const getBreadcrumb = () => {
    switch (location.pathname) {
      case '/':
        return 'Unified Threat Scanner';
      case '/dashboard':
        return 'Cybersecurity Intelligence Dashboard';
      case '/url':
        return 'URL Security Analysis';
      case '/tls':
        return 'TLS Certificate Inspection';
      case '/headers':
        return 'HTTP Security Headers';
      case '/message':
        return 'AI Phishing & Scam Analyzer';
      case '/ip':
        return 'IP Address Intelligence';
      case '/threats':
        return 'Threat Intelligence Center';
      case '/blockchain':
        return 'Blockchain Threat Verification';
      case '/history':
        return 'Investigation History';
      case '/settings':
        return 'Platform Settings';
      default:
        return 'Threat Investigation';
    }
  };

  return (
    <header className="sticky top-0 z-30 h-20 bg-[#192034]/85 backdrop-blur-md border-b border-[#494E6B]/30 px-6 flex items-center justify-between">
      <div className="flex items-center gap-4">
        <button
          onClick={() => setMobileOpen(true)}
          className="lg:hidden p-2 rounded-lg bg-[#202740] text-[#98878F] hover:text-white border border-[#494E6B]/40"
        >
          <Menu className="w-5 h-5" />
        </button>

        <div>
          <div className="flex items-center gap-2 text-xs text-[#98878F]">
            <Link to="/" className="hover:text-white transition-colors">WebSentinel AI</Link>
            <span>/</span>
            <span className="text-[#c28190] font-medium">{getBreadcrumb()}</span>
          </div>
          <h1 className="text-base font-bold text-white tracking-tight mt-0.5">
            {getBreadcrumb()}
          </h1>
        </div>
      </div>

      {/* System pills */}
      <div className="flex items-center gap-3">
        {/* UTC Time */}
        <div className="hidden md:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#202740]/80 border border-[#494E6B]/35 text-xs font-mono text-[#98878F]">
          <Clock className="w-3.5 h-3.5 text-[#98878F]" />
          <span>{utcTime || 'Synchronizing...'}</span>
        </div>

        {/* AI Engine Status */}
        <div className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#202740]/80 border border-[#494E6B]/35 text-xs text-[#98878F]">
          <Cpu className="w-3.5 h-3.5 text-[#985E6D]" />
          <span>AI Engine:</span>
          <span className="font-semibold text-white">
            {aiStatus ? 'Gemini 2.5' : 'Heuristic Core'}
          </span>
        </div>

        {/* Blockchain Status */}
        <Link
          to="/blockchain"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#985E6D]/15 border border-[#985E6D]/40 text-xs font-medium text-[#e58a9d] hover:bg-[#985E6D]/25 transition-colors"
        >
          <Link2 className="w-3.5 h-3.5 text-[#985E6D]" />
          <span className="hidden sm:inline">Ledger:</span>
          <span className="font-mono">{blockchainNet}</span>
        </Link>
      </div>
    </header>
  );
};

