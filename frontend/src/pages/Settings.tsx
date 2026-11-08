import React, { useState, useEffect } from 'react';
import {
  Key,
  Database,
  Cpu,
  Link2,
  CheckCircle2,
  Save,
  Shield
} from 'lucide-react';
import { getSettings, updateSettings } from '../services/api';

export const SettingsPage: React.FC = () => {
  const [settingsData, setSettingsData] = useState<any>(null);
  const [geminiKey, setGeminiKey] = useState('');
  const [gsbKey, setGsbKey] = useState('');
  const [vtKey, setVtKey] = useState('');
  const [ethRpc, setEthRpc] = useState('');
  const [contractAddr, setContractAddr] = useState('');
  const [saving, setSaving] = useState(false);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  useEffect(() => {
    getSettings()
      .then((data) => {
        setSettingsData(data);
        if (data.ethereum_rpc_url && !data.ethereum_rpc_url.includes('Not configured')) {
          setEthRpc(data.ethereum_rpc_url);
        }
        if (data.contract_address) {
          setContractAddr(data.contract_address);
        }
      })
      .catch((err) => console.error('Failed to get settings:', err));
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setSuccessMsg(null);

    try {
      await updateSettings({
        gemini_api_key: geminiKey || undefined,
        google_safe_browsing_api_key: gsbKey || undefined,
        virustotal_api_key: vtKey || undefined,
        ethereum_rpc_url: ethRpc || undefined,
        contract_address: contractAddr || undefined,
      });

      setSuccessMsg('Settings updated successfully. Active threat engines refreshed.');
      const updated = await getSettings();
      setSettingsData(updated);
      setGeminiKey('');
      setGsbKey('');
      setVtKey('');
    } catch (err: any) {
      console.error('Update settings failed:', err);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-8 pb-12">
      <div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          Platform Configuration & Integrations
        </h1>
        <p className="text-xs sm:text-sm text-[#98878F] mt-1">
          Configure API credentials, inspect defense boundaries, and toggle blockchain testnet endpoints.
        </p>
      </div>

      {successMsg && (
        <div className="p-4 rounded-xl bg-[#3f6e62]/20 border border-[#3f6e62]/50 text-[#85c9b7] text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Integration Status Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/35">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono uppercase text-[#98878F]">Google Gemini AI</span>
            <Cpu className="w-4 h-4 text-[#985E6D]" />
          </div>
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${settingsData?.gemini_api_key_configured ? 'bg-[#85c9b7]' : 'bg-[#b5834f]'}`} />
            <span className="text-sm font-bold text-white font-mono">
              {settingsData?.gemini_api_key_configured ? 'Gemini 2.5 Active' : 'Heuristic Engine'}
            </span>
          </div>
          <span className="text-[11px] text-[#98878F] mt-1 block">
            {settingsData?.gemini_api_key_configured ? `Masked: ${settingsData.gemini_api_key_masked}` : 'Local fallback operational'}
          </span>
        </div>

        <div className="p-4 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/35">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono uppercase text-[#98878F]">Safe Browsing Feed</span>
            <Shield className="w-4 h-4 text-[#985E6D]" />
          </div>
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${settingsData?.google_safe_browsing_configured ? 'bg-[#85c9b7]' : 'bg-[#494E6B]'}`} />
            <span className="text-sm font-bold text-white font-mono">
              {settingsData?.google_safe_browsing_configured ? 'API Connected' : 'Not Configured'}
            </span>
          </div>
          <span className="text-[11px] text-[#98878F] mt-1 block">Optional feed provider</span>
        </div>

        <div className="p-4 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/35">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono uppercase text-[#98878F]">VirusTotal API</span>
            <Database className="w-4 h-4 text-[#985E6D]" />
          </div>
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${settingsData?.virustotal_configured ? 'bg-[#85c9b7]' : 'bg-[#494E6B]'}`} />
            <span className="text-sm font-bold text-white font-mono">
              {settingsData?.virustotal_configured ? 'API Connected' : 'Not Configured'}
            </span>
          </div>
          <span className="text-[11px] text-[#98878F] mt-1 block">Vendor intelligence lookup</span>
        </div>

        <div className="p-4 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/35">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono uppercase text-[#98878F]">EVM Threat Ledger</span>
            <Link2 className="w-4 h-4 text-[#985E6D]" />
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#85c9b7]" />
            <span className="text-sm font-bold text-white font-mono">Cryptographic State</span>
          </div>
          <span className="text-[11px] text-[#85c9b7] mt-1 block font-mono">
            SHA-256 Anchoring Active
          </span>
        </div>
      </div>

      {/* API Key Form */}
      <form onSubmit={handleSave} className="p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl space-y-5">
        <h3 className="text-sm font-bold text-white tracking-wide border-b border-[#494E6B]/30 pb-3 flex items-center gap-2">
          <Key className="w-4 h-4 text-[#985E6D]" />
          <span>Credential Settings</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5 text-xs">
          <div>
            <label className="block text-[#98878F] mb-1 font-mono uppercase text-[10px]">
              Google Gemini API Key
            </label>
            <input
              type="password"
              value={geminiKey}
              onChange={(e) => setGeminiKey(e.target.value)}
              placeholder="Paste new GEMINI_API_KEY..."
              className="w-full bg-[#192034] border border-[#494E6B]/40 focus:border-[#985E6D] rounded-xl px-3.5 py-2.5 text-white placeholder-[#98878F] focus:outline-none font-mono"
            />
            <span className="text-[10px] text-[#98878F] mt-1 block">
              Enables Gemini multi-modal behavioral reasoning for phishing messages.
            </span>
          </div>

          <div>
            <label className="block text-[#98878F] mb-1 font-mono uppercase text-[10px]">
              Google Safe Browsing API Key
            </label>
            <input
              type="password"
              value={gsbKey}
              onChange={(e) => setGsbKey(e.target.value)}
              placeholder="Paste GOOGLE_SAFE_BROWSING_API_KEY..."
              className="w-full bg-[#192034] border border-[#494E6B]/40 focus:border-[#985E6D] rounded-xl px-3.5 py-2.5 text-white placeholder-[#98878F] focus:outline-none font-mono"
            />
            <span className="text-[10px] text-[#98878F] mt-1 block">
              Optional feed querying Google malware and social engineering registries.
            </span>
          </div>

          <div>
            <label className="block text-[#98878F] mb-1 font-mono uppercase text-[10px]">
              VirusTotal API Key
            </label>
            <input
              type="password"
              value={vtKey}
              onChange={(e) => setVtKey(e.target.value)}
              placeholder="Paste VIRUSTOTAL_API_KEY..."
              className="w-full bg-[#192034] border border-[#494E6B]/40 focus:border-[#985E6D] rounded-xl px-3.5 py-2.5 text-white placeholder-[#98878F] focus:outline-none font-mono"
            />
            <span className="text-[10px] text-[#98878F] mt-1 block">
              Optional multi-scanner domain reputation check.
            </span>
          </div>

          <div>
            <label className="block text-[#98878F] mb-1 font-mono uppercase text-[10px]">
              Ethereum Sepolia RPC Endpoint URL
            </label>
            <input
              type="text"
              value={ethRpc}
              onChange={(e) => setEthRpc(e.target.value)}
              placeholder="https://sepolia.infura.io/v3/..."
              className="w-full bg-[#192034] border border-[#494E6B]/40 focus:border-[#985E6D] rounded-xl px-3.5 py-2.5 text-white placeholder-[#98878F] focus:outline-none font-mono"
            />
            <span className="text-[10px] text-[#98878F] mt-1 block">
              Defaults to internal cryptographic ledger if left blank.
            </span>
          </div>
        </div>

        <div className="flex justify-end pt-3 border-t border-[#494E6B]/30">
          <button
            type="submit"
            disabled={saving}
            className="px-6 py-2.5 rounded-xl bg-[#985E6D] hover:bg-[#ad6d7d] text-white font-semibold text-xs shadow-[0_0_12px_rgba(152,94,109,0.35)] disabled:opacity-50 transition-all cursor-pointer flex items-center gap-2"
          >
            <Save className="w-3.5 h-3.5" />
            <span>{saving ? 'Saving...' : 'Save Configuration'}</span>
          </button>
        </div>
      </form>

      {/* Defensive Boundary Architecture */}
      <div className="p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl space-y-3 text-xs">
        <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
          <Shield className="w-4 h-4 text-[#985E6D]" />
          <span>Active Defensive Guardrails & RFC Parameters</span>
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 font-mono pt-1 text-[11px]">
          <div className="p-3 rounded-xl bg-[#192034]/70 border border-[#494E6B]/30 space-y-1">
            <span className="text-[#98878F] block">SSRF Protection</span>
            <span className="text-[#85c9b7] font-bold">STRICT ENFORCEMENT</span>
            <p className="text-[10px] text-[#98878F]">Loops, private subnets (10/8, 172.16/12, 192.168/16, fc00::/7) blocked.</p>
          </div>

          <div className="p-3 rounded-xl bg-[#192034]/70 border border-[#494E6B]/30 space-y-1">
            <span className="text-[#98878F] block">Max Response Size</span>
            <span className="text-white font-bold">1,048,576 Bytes (1 MB)</span>
            <p className="text-[10px] text-[#98878F]">Stream cap prevents memory exhaustion DOS.</p>
          </div>

          <div className="p-3 rounded-xl bg-[#192034]/70 border border-[#494E6B]/30 space-y-1">
            <span className="text-[#98878F] block">Outbound Timeout</span>
            <span className="text-white font-bold">6.0 Seconds Max</span>
            <p className="text-[10px] text-[#98878F]">Enforced across all HTTP, DNS, and TLS sockets.</p>
          </div>
        </div>
      </div>
    </div>
  );
};

