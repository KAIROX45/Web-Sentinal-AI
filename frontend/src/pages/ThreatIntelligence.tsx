import React, { useState, useEffect } from 'react';
import { Database, Plus } from 'lucide-react';
import { getThreatIOCs, createThreatIOC } from '../services/api';
import { ThreatIOC } from '../types';
import { ThreatIntelTable } from '../components/ThreatIntelTable';

export const ThreatIntelligence: React.FC = () => {
  const [iocs, setIocs] = useState<ThreatIOC[]>([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);

  // New IOC Form State
  const [newVal, setNewVal] = useState('');
  const [newType, setNewType] = useState('domain');
  const [newCategory, setNewCategory] = useState('phishing');
  const [newSeverity, setNewSeverity] = useState('HIGH');
  const [newDesc, setNewDesc] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const fetchIOCs = async (query?: string, type?: string, severity?: string) => {
    setLoading(true);
    try {
      const data = await getThreatIOCs({
        query: query || undefined,
        ioc_type: type === 'all' ? undefined : type,
        severity: severity === 'all' ? undefined : severity,
        limit: 100,
      });
      setIocs(data);
    } catch (err) {
      console.error('Failed to load IOCs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIOCs();
  }, []);

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newVal.trim()) return;

    setIsSubmitting(true);
    try {
      await createThreatIOC({
        ioc_value: newVal.trim(),
        ioc_type: newType,
        threat_category: newCategory,
        severity: newSeverity,
        description: newDesc.trim() || undefined,
        source: 'Analyst Submission',
      });
      setIsModalOpen(false);
      setNewVal('');
      setNewDesc('');
      fetchIOCs();
    } catch (err) {
      console.error('Failed to add IOC:', err);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-8 pb-12">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Threat Intelligence Center
          </h1>
          <p className="text-xs sm:text-sm text-[#98878F] mt-1">
            Curated Indicators of Compromise (IOCs), verified threat signatures, and active malicious campaigns.
          </p>
        </div>

        <button
          type="button"
          onClick={() => setIsModalOpen(true)}
          className="px-4 py-2 rounded-xl bg-[#985E6D] hover:bg-[#ad6d7d] text-white text-xs font-semibold shadow-[0_0_14px_rgba(152,94,109,0.35)] transition-all cursor-pointer flex items-center gap-1.5 self-start sm:self-auto"
        >
          <Plus className="w-4 h-4" />
          <span>Register New IOC</span>
        </button>
      </div>

      {/* IOC Table with Integrated Filtering */}
      <ThreatIntelTable
        iocs={iocs}
        loading={loading}
        onFilterChange={(q, t, s) => fetchIOCs(q, t, s)}
      />

      {/* Add IOC Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="w-full max-w-lg rounded-2xl bg-[#202740] border border-[#494E6B]/60 p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-[#494E6B]/30 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Database className="w-4 h-4 text-[#985E6D]" />
                <span>Register Indicator of Compromise (IOC)</span>
              </h3>
              <button
                type="button"
                onClick={() => setIsModalOpen(false)}
                className="text-[#98878F] hover:text-white text-sm"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateSubmit} className="space-y-3.5 text-xs">
              <div>
                <label className="block text-[#98878F] mb-1 font-mono uppercase text-[10px]">
                  IOC Value (Domain, IP, URL, or Hash)
                </label>
                <input
                  type="text"
                  required
                  value={newVal}
                  onChange={(e) => setNewVal(e.target.value)}
                  placeholder="e.g., suspicious-login-portal.xyz"
                  className="w-full bg-[#192034] border border-[#494E6B]/40 focus:border-[#985E6D] rounded-xl px-3.5 py-2.5 text-white placeholder-[#98878F] focus:outline-none font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[#98878F] mb-1 font-mono uppercase text-[10px]">
                    Type
                  </label>
                  <select
                    value={newType}
                    onChange={(e) => setNewType(e.target.value)}
                    className="w-full bg-[#192034] border border-[#494E6B]/40 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-[#985E6D]"
                  >
                    <option value="domain">Domain</option>
                    <option value="ip">IP Address</option>
                    <option value="url">URL</option>
                    <option value="hash">File Hash</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[#98878F] mb-1 font-mono uppercase text-[10px]">
                    Severity Tier
                  </label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value)}
                    className="w-full bg-[#192034] border border-[#494E6B]/40 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-[#985E6D]"
                  >
                    <option value="CONFIRMED MALICIOUS">Confirmed Malicious</option>
                    <option value="HIGH">High</option>
                    <option value="SUSPICIOUS">Suspicious</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-[#98878F] mb-1 font-mono uppercase text-[10px]">
                  Threat Category
                </label>
                <select
                  value={newCategory}
                  onChange={(e) => setNewCategory(e.target.value)}
                  className="w-full bg-[#192034] border border-[#494E6B]/40 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-[#985E6D]"
                >
                  <option value="phishing">Phishing & Credential Theft</option>
                  <option value="brand_impersonation">Brand Impersonation</option>
                  <option value="malware_c2">Malware C2 Command Infrastructure</option>
                  <option value="crypto_scam">Web3 / Wallet Drainer</option>
                  <option value="payment_fraud">Financial Payment Fraud</option>
                  <option value="package_smishing">Delivery / SMS Smishing</option>
                </select>
              </div>

              <div>
                <label className="block text-[#98878F] mb-1 font-mono uppercase text-[10px]">
                  Technical Description / Campaign Context
                </label>
                <textarea
                  rows={2}
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  placeholder="Notes regarding attack vector, targeted brand, or payload behavior..."
                  className="w-full bg-[#192034] border border-[#494E6B]/40 focus:border-[#985E6D] rounded-xl px-3.5 py-2 text-white placeholder-[#98878F] focus:outline-none font-mono resize-none"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-[#494E6B]/30">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 rounded-xl bg-[#192034] hover:bg-[#494E6B]/30 text-[#98878F] hover:text-white transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting || !newVal.trim()}
                  className="px-5 py-2 rounded-xl bg-[#985E6D] hover:bg-[#ad6d7d] text-white font-semibold shadow-[0_0_12px_rgba(152,94,109,0.35)] disabled:opacity-50 transition-all cursor-pointer"
                >
                  {isSubmitting ? 'Registering...' : 'Save to Intelligence Registry'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

