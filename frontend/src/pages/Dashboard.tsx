import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Activity,
  ArrowUpRight,
  Clock,
  ExternalLink
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar
} from 'recharts';
import { getThreatStats, getInvestigationHistory } from '../services/api';
import { ThreatStats, InvestigationHistoryItem } from '../types';
import { getRiskLevelBadge, formatDate } from '../utils/formatters';
import { LoadingSkeleton } from '../components/LoadingSkeleton';

export const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<ThreatStats | null>(null);
  const [history, setHistory] = useState<InvestigationHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([getThreatStats(), getInvestigationHistory({ limit: 8 })])
      .then(([statsData, historyData]) => {
        setStats(statsData);
        setHistory(historyData);
        setErrorMsg(null);
      })
      .catch((err) => {
        console.error('Dashboard load error:', err);
        setErrorMsg('Unable to retrieve real-time telemetry from backend. Please ensure the WebSentinel AI API is operational.');
      })
      .finally(() => setLoading(false));
  }, []);

  // Palette colors for Recharts
  const SEVERITY_COLORS = ['#3f6e62', '#b5834f', '#a34e5a', '#985E6D'];

  const severityPieData = stats?.severity_distribution
    ? Object.entries(stats.severity_distribution)
        .map(([name, value]) => ({ name, value }))
        .filter((item) => item.value > 0)
    : [];

  const categoryBarData = stats?.threat_categories
    ? Object.entries(stats.threat_categories)
        .map(([category, count]) => ({ category, count }))
        .filter((item) => item.count > 0)
    : [];

  const trendData = stats?.recent_activity_trends || [];

  const getDefenseGrade = (score: number) => {
    if (score >= 90) return 'GRADE A+';
    if (score >= 80) return 'GRADE A';
    if (score >= 70) return 'GRADE B';
    if (score >= 50) return 'GRADE C';
    return 'GRADE D';
  };

  if (loading && !stats) {
    return (
      <div className="space-y-6 pb-10">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Security Intelligence Dashboard
          </h1>
          <p className="text-xs sm:text-sm text-[#98878F] mt-1">
            Loading real-time telemetry from database...
          </p>
        </div>
        <LoadingSkeleton />
      </div>
    );
  }

  return (
    <div className="space-y-8 pb-10">
      {/* Top Banner / Headline */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Security Intelligence Dashboard
          </h1>
          <p className="text-xs sm:text-sm text-[#98878F] mt-1">
            Real-time telemetry, threat severity distribution, and verified IOC telemetry.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Link
            to="/url"
            className="px-4 py-2 rounded-xl bg-[#985E6D] hover:bg-[#ad6d7d] text-white text-xs font-semibold shadow-[0_0_14px_rgba(152,94,109,0.35)] transition-all flex items-center gap-1.5"
          >
            <span>New Investigation</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      </div>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-[#985E6D]/20 border border-[#985E6D]/50 text-[#e58a9d] text-xs flex items-center gap-3">
          <ShieldAlert className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Metric Cards Row */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="p-5 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/35 backdrop-blur-xl">
          <div className="flex items-center justify-between text-[#98878F] text-xs font-mono mb-2">
            <span>TOTAL SCANNED</span>
            <Activity className="w-4 h-4 text-[#985E6D]" />
          </div>
          <div className="text-2xl font-extrabold text-white font-mono">
            {stats ? stats.total_scans : 0}
          </div>
          <div className="text-[11px] text-[#85c9b7] mt-1">Multi-vector scans</div>
        </div>

        <div className="p-5 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/35 backdrop-blur-xl">
          <div className="flex items-center justify-between text-[#98878F] text-xs font-mono mb-2">
            <span>CONFIRMED MALICIOUS</span>
            <ShieldAlert className="w-4 h-4 text-[#985E6D]" />
          </div>
          <div className="text-2xl font-extrabold text-[#e58a9d] font-mono">
            {stats ? stats.malicious_detected : 0}
          </div>
          <div className="text-[11px] text-[#98878F] mt-1">Verified IOC matches</div>
        </div>

        <div className="p-5 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/35 backdrop-blur-xl">
          <div className="flex items-center justify-between text-[#98878F] text-xs font-mono mb-2">
            <span>SUSPICIOUS TARGETS</span>
            <AlertTriangle className="w-4 h-4 text-[#b5834f]" />
          </div>
          <div className="text-2xl font-extrabold text-[#eac498] font-mono">
            {stats ? stats.suspicious_detected : 0}
          </div>
          <div className="text-[11px] text-[#98878F] mt-1">Anomalous heuristics</div>
        </div>

        <div className="p-5 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/35 backdrop-blur-xl">
          <div className="flex items-center justify-between text-[#98878F] text-xs font-mono mb-2">
            <span>THREATS MITIGATED</span>
            <ShieldCheck className="w-4 h-4 text-[#85c9b7]" />
          </div>
          <div className="text-2xl font-extrabold text-white font-mono">
            {stats ? stats.threats_blocked : 0}
          </div>
          <div className="text-[11px] text-[#85c9b7] mt-1">Proactively blocked</div>
        </div>

        <div className="p-5 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/35 backdrop-blur-xl col-span-2 lg:col-span-1">
          <div className="flex items-center justify-between text-[#98878F] text-xs font-mono mb-2">
            <span>PLATFORM HEALTH</span>
            <span className="text-[10px] font-bold text-[#85c9b7] font-mono">
              {stats ? getDefenseGrade(stats.security_score) : 'GRADE A+'}
            </span>
          </div>
          <div className="text-2xl font-extrabold text-[#85c9b7] font-mono">
            {stats ? stats.security_score : 100}<span className="text-xs text-[#98878F]">/100</span>
          </div>
          <div className="text-[11px] text-[#98878F] mt-1">System operational</div>
        </div>
      </div>

      {/* Interactive Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Trend Area Chart (2 Cols) */}
        <div className="lg:col-span-2 p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white tracking-wide">
                Detection & Activity Trends
              </h3>
              <p className="text-xs text-[#98878F]">
                Weekly volume of scanned indicators vs detected threat signals.
              </p>
            </div>
            <div className="flex items-center gap-3 text-[11px] font-mono">
              <span className="flex items-center gap-1.5 text-white">
                <span className="w-2.5 h-2.5 rounded-full bg-[#985E6D]" /> Scanned
              </span>
              <span className="flex items-center gap-1.5 text-[#e58a9d]">
                <span className="w-2.5 h-2.5 rounded-full bg-[#a34e5a]" /> Threats
              </span>
            </div>
          </div>

          <div className="h-64 w-full pt-4">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="scannedGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#494E6B" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#494E6B" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="threatsGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#985E6D" stopOpacity={0.5} />
                    <stop offset="95%" stopColor="#985E6D" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" stroke="#98878F" fontSize={11} tickLine={false} />
                <YAxis stroke="#98878F" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#192034',
                    border: '1px solid #494E6B',
                    borderRadius: '12px',
                    fontSize: '11px',
                    color: '#fff'
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="scanned"
                  stroke="#5f658b"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#scannedGradient)"
                />
                <Area
                  type="monotone"
                  dataKey="threats"
                  stroke="#985E6D"
                  strokeWidth={2.5}
                  fillOpacity={1}
                  fill="url(#threatsGradient)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Distribution Donut Chart (1 Col) */}
        <div className="p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-white tracking-wide">
              Threat Severity Distribution
            </h3>
            <p className="text-xs text-[#98878F] mt-0.5">
              Breakdown by assessed risk tier.
            </p>
          </div>

          {severityPieData.length > 0 ? (
            <>
              <div className="h-48 w-full my-auto flex items-center justify-center">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityPieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={75}
                      paddingAngle={4}
                      dataKey="value"
                    >
                      {severityPieData.map((_, index) => (
                        <Cell
                          key={`cell-${index}`}
                          fill={SEVERITY_COLORS[index % SEVERITY_COLORS.length]}
                        />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#192034',
                        border: '1px solid #494E6B',
                        borderRadius: '8px',
                        fontSize: '11px',
                        color: '#fff'
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              <div className="grid grid-cols-2 gap-2 pt-3 border-t border-[#494E6B]/30 text-[11px] font-mono">
                {severityPieData.map((entry, index) => (
                  <div key={entry.name} className="flex items-center gap-1.5">
                    <span
                      className="w-2 h-2 rounded-full"
                      style={{ backgroundColor: SEVERITY_COLORS[index % SEVERITY_COLORS.length] }}
                    />
                    <span className="text-[#98878F] truncate">{entry.name}:</span>
                    <span className="text-white font-bold">{entry.value}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="h-48 flex items-center justify-center text-xs text-[#98878F] font-mono">
              No severity distribution recorded yet.
            </div>
          )}
        </div>
      </div>

      {/* Threat Categories Bar Chart */}
      <div className="p-6 rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-white tracking-wide">
              Threat Category Prevalence
            </h3>
            <p className="text-xs text-[#98878F]">
              Distribution across common attack vectors and malicious campaigns.
            </p>
          </div>
          <Link
            to="/threats"
            className="text-xs text-[#c28190] hover:text-white transition-colors flex items-center gap-1 font-mono"
          >
            <span>View IOC Database</span>
            <ExternalLink className="w-3 h-3" />
          </Link>
        </div>

        {categoryBarData.length > 0 ? (
          <div className="h-52 w-full pt-2">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={categoryBarData}>
                <XAxis dataKey="category" stroke="#98878F" fontSize={11} tickLine={false} />
                <YAxis stroke="#98878F" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#192034',
                    border: '1px solid #494E6B',
                    borderRadius: '10px',
                    fontSize: '11px',
                    color: '#fff'
                  }}
                />
                <Bar dataKey="count" fill="#985E6D" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="h-40 flex items-center justify-center text-xs text-[#98878F] font-mono">
            No threat categories registered yet.
          </div>
        )}
      </div>

      {/* Recent Investigations Table */}
      <div className="rounded-2xl bg-[#202740]/80 border border-[#494E6B]/40 backdrop-blur-xl overflow-hidden">
        <div className="p-5 border-b border-[#494E6B]/30 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-[#985E6D]" />
            <h3 className="text-sm font-bold text-white tracking-wide">
              Recent Threat Investigations
            </h3>
          </div>
          <Link
            to="/history"
            className="text-xs text-[#c28190] hover:text-white transition-colors font-medium flex items-center gap-1"
          >
            <span>All History</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#192034]/60 text-[#98878F] uppercase font-mono tracking-wider border-b border-[#494E6B]/30">
              <tr>
                <th className="py-3 px-5">Target Identifier</th>
                <th className="py-3 px-4">Vector</th>
                <th className="py-3 px-4">Severity Tier</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Findings</th>
                <th className="py-3 px-5 text-right">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#494E6B]/20 text-[#c2b5bc]">
              {history.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-8 text-[#98878F]">
                    No previous investigations recorded yet. Run a scan from the search bar!
                  </td>
                </tr>
              ) : (
                history.map((item) => {
                  const badge = getRiskLevelBadge(item.risk_level);
                  return (
                    <tr key={item.id} className="hover:bg-[#192034]/40 transition-colors">
                      <td className="py-3 px-5 font-mono text-white font-medium max-w-xs truncate">
                        {item.target}
                      </td>
                      <td className="py-3 px-4 uppercase font-mono text-[11px] text-[#98878F]">
                        {item.scan_type}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold font-mono border ${badge.bg} ${badge.border} ${badge.text}`}>
                          {badge.label}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono font-bold text-white">
                        {item.risk_score}
                      </td>
                      <td className="py-3 px-4 text-[#98878F]">
                        {item.evidence_count} evidence items
                      </td>
                      <td className="py-3 px-5 text-right font-mono text-[11px] text-[#98878F]">
                        {formatDate(item.created_at)}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

