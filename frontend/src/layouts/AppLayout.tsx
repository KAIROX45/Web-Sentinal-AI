import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from '../components/Sidebar';
import { Header } from '../components/Header';
import { Shield } from 'lucide-react';

export const AppLayout: React.FC = () => {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="min-h-screen bg-[#192034] text-white flex flex-col font-sans selection:bg-[#985E6D] selection:text-white">
      {/* Sidebar */}
      <Sidebar mobileOpen={mobileOpen} setMobileOpen={setMobileOpen} />

      {/* Main Wrapper */}
      <div className="flex-1 lg:pl-72 flex flex-col min-h-screen">
        <Header setMobileOpen={setMobileOpen} />

        <main className="flex-1 p-4 sm:p-6 lg:p-8 subtle-grid relative overflow-x-hidden">
          {/* Subtle atmospheric radial gradient */}
          <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full max-w-5xl h-96 radial-glow pointer-events-none -z-0" />

          <div className="relative z-10 max-w-7xl mx-auto space-y-6">
            <Outlet />
          </div>
        </main>

        {/* Global Footer */}
        <footer className="border-t border-[#494E6B]/30 bg-[#121726]/80 px-6 py-4 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-[#98878F]">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-[#985E6D]" />
            <span className="font-mono font-semibold text-white">WebSentinel AI</span>
            <span>— AI-Powered Cyber Threat Intelligence Platform</span>
          </div>

          <div className="flex items-center gap-4 text-[11px]">
            <span>TLP:AMBER Security Strict</span>
            <span className="text-[#494E6B]">•</span>
            <span>SSRF Guard Enforced</span>
            <span className="text-[#494E6B]">•</span>
            <span>EVM Cryptographic Integrity</span>
          </div>
        </footer>
      </div>
    </div>
  );
};

