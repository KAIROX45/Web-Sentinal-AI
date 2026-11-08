import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  Globe,
  Lock,
  FileCode2,
  MailWarning,
  Network,
  Database,
  Link2,
  History,
  Settings as SettingsIcon,
  Search,
  CheckCircle2
} from 'lucide-react';

interface SidebarProps {
  mobileOpen: boolean;
  setMobileOpen: (open: boolean) => void;
}

const navItems = [
  { name: 'Threat Scanner', path: '/', icon: Search, badge: 'Unified' },
  { name: 'Investigation Dashboard', path: '/dashboard', icon: LayoutDashboard },
  { name: 'URL Investigation', path: '/url', icon: Globe },
  { name: 'TLS Certificate Inspection', path: '/tls', icon: Lock },
  { name: 'HTTP Security Headers', path: '/headers', icon: FileCode2 },
  { name: 'AI Phishing & Scam Analyzer', path: '/message', icon: MailWarning, badge: 'AI' },
  { name: 'IP Address Intelligence', path: '/ip', icon: Network },
  { name: 'Threat Intelligence Center', path: '/threats', icon: Database, badge: 'IOC' },
  { name: 'Blockchain Verification', path: '/blockchain', icon: Link2, badge: 'Web3' },
  { name: 'Investigation History', path: '/history', icon: History },
  { name: 'Platform Settings', path: '/settings', icon: SettingsIcon },
];

export const Sidebar: React.FC<SidebarProps> = ({ mobileOpen, setMobileOpen }) => {
  return (
    <>
      {/* Mobile backdrop */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Sidebar container */}
      <aside
        className={`fixed top-0 bottom-0 left-0 z-50 w-72 bg-[#192034]/95 border-r border-[#494E6B]/35 backdrop-blur-xl flex flex-col transition-transform duration-300 ease-in-out lg:translate-x-0 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Brand header */}
        <div className="h-20 flex items-center px-6 border-b border-[#494E6B]/30 gap-3">
          <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-[#985E6D] to-[#494E6B] p-0.5 shadow-[0_0_15px_rgba(152,94,109,0.4)] flex items-center justify-center">
            <div className="w-full h-full bg-[#192034] rounded-[10px] flex items-center justify-center">
              <Shield className="w-6 h-6 text-[#985E6D]" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="text-lg font-bold tracking-tight text-white font-mono">WEBSENTINEL</span>
              <span className="text-lg font-extrabold tracking-tight text-[#985E6D] font-mono">AI</span>
              <span className="text-[10px] font-semibold tracking-wider uppercase px-1.5 py-0.5 rounded bg-[#985E6D]/20 text-[#c28190] border border-[#985E6D]/30 ml-1">
                v1.0
              </span>
            </div>
            <p className="text-[11px] text-[#98878F] font-medium tracking-wide">
              Cyber Threat Intelligence
            </p>
          </div>
        </div>

        {/* Navigation list */}
        <div className="flex-1 overflow-y-auto px-4 py-4 space-y-1">
          <div className="px-3 pb-2 text-[10px] font-semibold uppercase tracking-wider text-[#98878F]">
            Threat Investigation
          </div>
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                end={item.path === '/'}
                onClick={() => setMobileOpen(false)}
                className={({ isActive }) =>
                  `flex items-center justify-between px-3.5 py-2.5 rounded-xl text-sm font-medium transition-all duration-200 group ${
                    isActive
                      ? 'bg-[#985E6D] text-white shadow-[0_0_18px_rgba(152,94,109,0.45)] border border-[#c28190]/30'
                      : 'text-[#98878F] hover:text-white hover:bg-[#494E6B]/25 border border-transparent'
                  }`
                }
              >
                {({ isActive }) => (
                  <>
                    <div className="flex items-center gap-3">
                      <Icon
                        className={`w-4 h-4 transition-colors ${
                          isActive ? 'text-white' : 'text-[#98878F] group-hover:text-[#c28190]'
                        }`}
                      />
                      <span>{item.name}</span>
                    </div>
                    {item.badge && (
                      <span
                        className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${
                          isActive
                            ? 'bg-white/20 text-white'
                            : 'bg-[#494E6B]/40 text-[#c28190] border border-[#494E6B]/60'
                        }`}
                      >
                        {item.badge}
                      </span>
                    )}
                  </>
                )}
              </NavLink>
            );
          })}
        </div>

        {/* Security status panel */}
        <div className="p-4 border-t border-[#494E6B]/30 bg-[#121726]/60">
          <div className="bg-[#202740]/80 border border-[#494E6B]/40 rounded-xl p-3">
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-[#4a7568] animate-pulse" />
                <span className="text-xs font-semibold text-white">Defense Core</span>
              </div>
              <span className="text-[10px] text-[#4a7568] font-mono font-medium">ONLINE</span>
            </div>
            <p className="text-[11px] text-[#98878F] leading-relaxed">
              SSRF boundary enforced. Cryptographic tamper checks active.
            </p>
            <div className="mt-2.5 pt-2 border-t border-[#494E6B]/30 flex items-center justify-between text-[10px] text-[#98878F]">
              <span>Threat DB: Curated</span>
              <span className="flex items-center gap-1 text-[#985E6D]">
                <CheckCircle2 className="w-3 h-3" /> Ready
              </span>
            </div>
          </div>
        </div>
      </aside>
    </>
  );
};

