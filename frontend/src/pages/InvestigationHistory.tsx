import React, { useState, useEffect, useCallback } from 'react';
import {
  History,
  Search,
  FileJson,
  FileText,
  Eye,
  Globe,
  Network,
  MailWarning,
  Lock,
  FileCode2
} from 'lucide-react';
import { getInvestigationHistory, getReportDetail, getExportJsonUrl, getExportPdfUrl } from '../services/api';
import { InvestigationHistoryItem } from '../types';
import { getRiskLevelBadge, formatDate, truncateHash } from '../utils/formatters';

export const InvestigationHistoryPage: React.FC = () => {
  const [history, setHistory] = useState<InvestigationHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [scanType, setScanType] = useState('all');
  const [riskLevel, setRiskLevel] = useState('all');
  const [selectedRecord, setSelectedRecord] = useState<any | null>(null);

  const fetchHistory = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getInvestigationHistory({
        scan_type: scanType === 'all' ? undefined : scanType,
        risk_level: riskLevel === 'all' ? undefined : riskLevel,
        search: search || undefined,
      });
      setHistory(data);
    } catch (err) {
      console.error('Failed to load history:', err);
    } finally {
      setLoading(false);
    }
  }, [scanType, riskLevel, search]);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchHistory();
  };

  const handleViewDetail = async (id: string) => {
    try {
      const detail = await getReportDetail(id);
      setSelectedRecord(detail);
    } catch (err) {
      console.error('Failed to get report detail:', err);
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'url':
        return Globe;
      case 'ip':
        return Network;
      case 'message':
        return MailWarning;
      case 'tls':
        return Lock;
      case 'headers':
        return FileCode2;
      default:
        return History;
    }
  };

  return (
    <div className="space-y-8 pb-12">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Investigation History & Evidence Archive
          </h1>
          <p className="text-xs sm:text-sm text-[#98878F] mt-1">
            Historical audit logs of scanned URLs, IPs, and messages with exportable intelligence briefs.
          </p>
        </div>
      </div>

      {/* Filter Toolbar */}
      <form onSubmit={handleSearchSubmit} className="p-4 sm:p-5 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl flex flex-col sm:flex-row gap-3 items-stretch sm:items-center justify-between">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-[#98878F] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search target or summary..."
            className="w-full bg-[#192034]/70 border border-[#494E6B]/40 rounded-xl pl-9 pr-3 py-2 text-xs text-white placeholder-[#98878F] focus:outline-none focus:border-[#985E6D] font-mono"
          />
        </div>

        <div className="flex items-center gap-2">
          <select
            value={scanType}
            onChange={(e) => setScanType(e.target.value)}
            className="bg-[#192034]/70 border border-[#494E6B]/40 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-[#985E6D]"
          >
            <option value="all">All Vectors</option>
            <option value="url">URL Analysis</option>
            <option value="ip">IP Intelligence</option>
            <option value="message">Phishing Message</option>
            <option value="tls">TLS Handshake</option>
            <option value="headers">HTTP Headers</option>
          </select>

          <select
            value={riskLevel}
            onChange={(e) => setRiskLevel(e.target.value)}
            className="bg-[#192034]/70 border border-[#494E6B]/40 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-[#985E6D]"
          >
            <option value="all">All Severities</option>
            <option value="CONFIRMED MALICIOUS">Confirmed Malicious</option>
            <option value="HIGH">High</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="LOW">Low</option>
          </select>

          <button
            type="submit"
            className="px-4 py-2 rounded-xl bg-[#985E6D] hover:bg-[#ad6d7d] text-white text-xs font-semibold shadow-sm transition-colors cursor-pointer"
          >
            Filter
          </button>
        </div>
      </form>

      {/* History Table */}
      <div className="rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#192034]/60 text-[#98878F] uppercase font-mono tracking-wider border-b border-[#494E6B]/30">
              <tr>
                <th className="py-3.5 px-5">Target Entity</th>
                <th className="py-3.5 px-4">Type</th>
                <th className="py-3.5 px-4">Assessed Risk</th>
                <th className="py-3.5 px-4">Threat Score</th>
                <th className="py-3.5 px-4">Blockchain Hash</th>
                <th className="py-3.5 px-4">Timestamp</th>
                <th className="py-3.5 px-5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#494E6B]/20 text-[#c2b5bc]">
              {loading ? (
                <tr>
                  <td colSpan={7} className="text-center py-12 text-[#98878F]">
                    Loading investigation history...
                  </td>
                </tr>
              ) : history.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-12 text-[#98878F]">
                    No investigation records found matching criteria.
                  </td>
                </tr>
              ) : (
                history.map((item) => {
                  const badge = getRiskLevelBadge(item.risk_level);
                  const Icon = getTypeIcon(item.scan_type);
                  return (
                    <tr key={item.id} className="hover:bg-[#192034]/40 transition-colors">
                      <td className="py-3.5 px-5 font-mono text-white font-medium max-w-xs truncate">
                        <div className="flex items-center gap-2">
                          <Icon className="w-4 h-4 text-[#985E6D] shrink-0" />
                          <span className="truncate">{item.target}</span>
                        </div>
                      </td>

                      <td className="py-3.5 px-4 uppercase font-mono text-[11px] text-[#98878F]">
                        {item.scan_type}
                      </td>

                      <td className="py-3.5 px-4">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold font-mono border ${badge.bg} ${badge.border} ${badge.text}`}>
                          {badge.label}
                        </span>
                      </td>

                      <td className="py-3.5 px-4 font-mono font-bold text-white">
                        {item.risk_score}
                      </td>

                      <td className="py-3.5 px-4 font-mono text-[11px] text-[#c28190]">
                        {item.blockchain_hash ? truncateHash(item.blockchain_hash, 6) : <span className="text-[#98878F] italic">Local</span>}
                      </td>

                      <td className="py-3.5 px-4 font-mono text-[11px] text-[#98878F]">
                        {formatDate(item.created_at)}
                      </td>

                      <td className="py-3.5 px-5 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => handleViewDetail(item.id)}
                            className="p-1.5 rounded-lg bg-[#192034] hover:bg-[#494E6B]/40 text-[#c2b5bc] hover:text-white transition-colors cursor-pointer"
                            title="View Full Briefing"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                          <a
                            href={getExportJsonUrl(item.id)}
                            download
                            className="p-1.5 rounded-lg bg-[#192034] hover:bg-[#494E6B]/40 text-[#c2b5bc] hover:text-white transition-colors cursor-pointer"
                            title="Export JSON"
                          >
                            <FileJson className="w-3.5 h-3.5" />
                          </a>
                          <a
                            href={getExportPdfUrl(item.id)}
                            download
                            className="p-1.5 rounded-lg bg-[#985E6D]/20 hover:bg-[#985E6D]/40 text-[#e58a9d] hover:text-white transition-colors cursor-pointer"
                            title="Download PDF Brief"
                          >
                            <FileText className="w-3.5 h-3.5" />
                          </a>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Investigation Detail Modal */}
      {selectedRecord && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
          <div className="w-full max-w-2xl max-h-[85vh] overflow-y-auto rounded-2xl bg-[#202740] border border-[#494E6B]/60 p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-[#494E6B]/30 pb-3">
              <div>
                <span className="text-[10px] font-mono uppercase text-[#98878F] block">
                  {selectedRecord.scan_type} Investigation Brief
                </span>
                <h3 className="text-base font-bold text-white font-mono break-all">
                  {selectedRecord.target}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setSelectedRecord(null)}
                className="text-[#98878F] hover:text-white text-sm"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="p-3.5 rounded-xl bg-[#192034] border border-[#494E6B]/30 flex justify-between items-center">
                <div>
                  <span className="text-[#98878F] block text-[10px] uppercase font-mono">Assessed Severity</span>
                  <span className="font-bold text-sm text-white">{selectedRecord.risk_level} ({selectedRecord.risk_score}/100)</span>
                </div>
                <div className="text-right">
                  <span className="text-[#98878F] block text-[10px] uppercase font-mono">Investigated UTC</span>
                  <span className="font-mono text-white">{formatDate(selectedRecord.created_at)}</span>
                </div>
              </div>

              {selectedRecord.summary && (
                <div>
                  <span className="text-[#98878F] font-bold block mb-1 uppercase text-[10px]">Executive Summary</span>
                  <p className="text-[#c2b5bc] leading-relaxed p-3 rounded-xl bg-[#192034]/60 border border-[#494E6B]/25">
                    {selectedRecord.summary}
                  </p>
                </div>
              )}

              {selectedRecord.evidence && selectedRecord.evidence.length > 0 && (
                <div>
                  <span className="text-[#98878F] font-bold block mb-1 uppercase text-[10px]">
                    Technical Evidence ({selectedRecord.evidence.length})
                  </span>
                  <div className="space-y-1.5 max-h-48 overflow-y-auto">
                    {selectedRecord.evidence.map((ev: any, i: number) => (
                      <div key={i} className="p-2.5 rounded-lg bg-[#192034]/60 border border-[#494E6B]/20 flex justify-between gap-2">
                        <div>
                          <span className="font-bold text-white block">{ev.indicator}</span>
                          <span className="text-[#98878F]">{ev.description}</span>
                        </div>
                        <span className="text-[10px] font-mono text-[#c28190] shrink-0">{ev.severity}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {selectedRecord.blockchain_hash && (
                <div className="p-3 rounded-xl bg-[#192034] border border-[#494E6B]/30 font-mono text-[11px]">
                  <span className="text-[#98878F] block text-[10px] uppercase">Canonical SHA-256 Fingerprint</span>
                  <span className="text-[#c28190] break-all">{selectedRecord.blockchain_hash}</span>
                </div>
              )}
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-[#494E6B]/30">
              <div className="flex items-center gap-2">
                <a
                  href={getExportJsonUrl(selectedRecord.id)}
                  download
                  className="px-3 py-1.5 rounded-lg bg-[#192034] hover:bg-[#494E6B]/30 border border-[#494E6B]/40 text-xs text-white flex items-center gap-1.5"
                >
                  <FileJson className="w-3.5 h-3.5" />
                  <span>Download JSON</span>
                </a>
                <a
                  href={getExportPdfUrl(selectedRecord.id)}
                  download
                  className="px-3 py-1.5 rounded-lg bg-[#985E6D]/20 hover:bg-[#985E6D]/30 border border-[#985E6D]/40 text-xs text-[#e58a9d] flex items-center gap-1.5"
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>Download PDF Report</span>
                </a>
              </div>

              <button
                type="button"
                onClick={() => setSelectedRecord(null)}
                className="px-4 py-1.5 rounded-xl bg-[#494E6B]/40 hover:bg-[#494E6B]/60 text-white text-xs"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

