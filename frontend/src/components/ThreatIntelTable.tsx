import React, { useState } from 'react';
import { Search } from 'lucide-react';
import { ThreatIOC } from '../types';
import { getRiskLevelBadge, formatDate } from '../utils/formatters';

interface ThreatIntelTableProps {
  iocs: ThreatIOC[];
  loading?: boolean;
  onFilterChange?: (search: string, type: string, severity: string) => void;
}

export const ThreatIntelTable: React.FC<ThreatIntelTableProps> = ({
  iocs,
  loading = false,
  onFilterChange,
}) => {
  const [search, setSearch] = useState('');
  const [iocType, setIocType] = useState('all');
  const [severity, setSeverity] = useState('all');

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value;
    setSearch(val);
    onFilterChange?.(val, iocType, severity);
  };

  const handleTypeChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const val = e.target.value;
    setIocType(val);
    onFilterChange?.(search, val, severity);
  };

  const handleSeverityChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const val = e.target.value;
    setSeverity(val);
    onFilterChange?.(search, iocType, val);
  };

  return (
    <div className="rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl overflow-hidden">
      {/* Search & Filter Toolbar */}
      <div className="p-4 sm:p-5 border-b border-[#494E6B]/30 flex flex-col sm:flex-row gap-3 items-stretch sm:items-center justify-between">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-[#98878F] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={handleSearchChange}
            placeholder="Search indicator, source, or campaign..."
            className="w-full bg-[#192034]/70 border border-[#494E6B]/40 rounded-xl pl-9 pr-3 py-2 text-xs text-white placeholder-[#98878F] focus:outline-none focus:border-[#985E6D]"
          />
        </div>

        <div className="flex items-center gap-2">
          {/* IOC Type filter */}
          <select
            value={iocType}
            onChange={handleTypeChange}
            className="bg-[#192034]/70 border border-[#494E6B]/40 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-[#985E6D]"
          >
            <option value="all">All Types</option>
            <option value="domain">Domain</option>
            <option value="ip">IP Address</option>
            <option value="url">URL</option>
          </select>

          {/* Severity filter */}
          <select
            value={severity}
            onChange={handleSeverityChange}
            className="bg-[#192034]/70 border border-[#494E6B]/40 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-[#985E6D]"
          >
            <option value="all">All Severities</option>
            <option value="CONFIRMED MALICIOUS">Confirmed Malicious</option>
            <option value="HIGH">High</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {/* Table view */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-[#192034]/60 text-[#98878F] uppercase font-mono tracking-wider border-b border-[#494E6B]/30">
            <tr>
              <th className="py-3.5 px-5">Indicator (IOC)</th>
              <th className="py-3.5 px-4">Type</th>
              <th className="py-3.5 px-4">Threat Category</th>
              <th className="py-3.5 px-4">Severity</th>
              <th className="py-3.5 px-4">Confidence</th>
              <th className="py-3.5 px-4">Feed Source</th>
              <th className="py-3.5 px-5 text-right">Last Verified</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#494E6B]/20 text-[#c2b5bc]">
            {loading ? (
              <tr>
                <td colSpan={7} className="text-center py-12 text-[#98878F]">
                  <div className="inline-block w-6 h-6 border-2 border-[#985E6D] border-t-transparent rounded-full animate-spin mb-2" />
                  <div>Loading threat intelligence indicators...</div>
                </td>
              </tr>
            ) : iocs.length === 0 ? (
              <tr>
                <td colSpan={7} className="text-center py-12 text-[#98878F]">
                  No threat indicators matching your filter query.
                </td>
              </tr>
            ) : (
              iocs.map((ioc) => {
                const badge = getRiskLevelBadge(ioc.severity);
                return (
                  <tr key={ioc.id} className="hover:bg-[#192034]/40 transition-colors">
                    <td className="py-3.5 px-5 font-mono text-white font-medium">
                      {ioc.ioc_value}
                    </td>
                    <td className="py-3.5 px-4 font-mono uppercase text-[11px] text-[#98878F]">
                      {ioc.ioc_type}
                    </td>
                    <td className="py-3.5 px-4 capitalize">
                      {ioc.threat_category.replace(/_/g, ' ')}
                    </td>
                    <td className="py-3.5 px-4">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold font-mono border ${badge.bg} ${badge.border} ${badge.text}`}>
                        {badge.label}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 rounded-full bg-[#192034] overflow-hidden">
                          <div
                            className="h-full bg-gradient-to-r from-[#b5834f] to-[#985E6D]"
                            style={{ width: `${ioc.confidence}%` }}
                          />
                        </div>
                        <span className="font-mono text-[11px] text-[#98878F]">{ioc.confidence}%</span>
                      </div>
                    </td>
                    <td className="py-3.5 px-4 text-[#98878F]">
                      <div className="flex items-center gap-1.5">
                        <span>{ioc.source}</span>
                        {ioc.is_demo && (
                          <span
                            className="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-mono font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20"
                            title="Pre-seeded demonstration indicator (not from external live feed)"
                          >
                            DEMO
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-3.5 px-5 text-right font-mono text-[11px] text-[#98878F]">
                      {formatDate(ioc.last_seen)}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

