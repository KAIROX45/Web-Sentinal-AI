import axios from 'axios';
import {
  URLScanResponse,
  TLSScanResponse,
  HeaderScanResponse,
  MessageScanResponse,
  IPScanResponse,
  ThreatIOC,
  ThreatStats,
  BlockchainVerification,
  BlockchainStatus,
  InvestigationHistoryItem,
  UnifiedClassification,
} from '../types';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// System & Health
export const getHealth = async () => {
  const res = await api.get('/health/');
  return res.data;
};

// URL Analysis
export const scanURL = async (url: string, deepScan: boolean = true): Promise<URLScanResponse> => {
  const res = await api.post('/url/scan', { url, deep_scan: deepScan });
  return res.data;
};

// TLS Certificate Inspection
export const inspectTLS = async (hostname: string, port: number = 443): Promise<TLSScanResponse> => {
  const res = await api.post('/tls/inspect', { hostname, port });
  return res.data;
};

// HTTP Security Headers Inspection
export const inspectHeaders = async (url: string): Promise<HeaderScanResponse> => {
  const res = await api.post('/headers/inspect', { url });
  return res.data;
};

// AI Phishing & Scam Message Analysis
export const analyzeMessage = async (content: string, messageType: string = 'auto'): Promise<MessageScanResponse> => {
  const res = await api.post('/message/analyze', { content, message_type: messageType });
  return res.data;
};

// IP Address Investigation
export const scanIP = async (ipAddress: string): Promise<IPScanResponse> => {
  const res = await api.post('/ip/scan', { ip_address: ipAddress });
  return res.data;
};

// Threat Intelligence Center
export const getThreatIOCs = async (params?: {
  query?: string;
  ioc_type?: string;
  category?: string;
  severity?: string;
  limit?: number;
}): Promise<ThreatIOC[]> => {
  const res = await api.get('/threats/iocs', { params });
  return res.data;
};

export const createThreatIOC = async (data: {
  ioc_value: string;
  ioc_type: string;
  threat_category: string;
  severity: string;
  source?: string;
  description?: string;
}): Promise<ThreatIOC> => {
  const res = await api.post('/threats/iocs', data);
  return res.data;
};

export const getThreatStats = async (): Promise<ThreatStats> => {
  const res = await api.get('/threats/stats');
  return res.data;
};

// Investigation History & Reports
export const getInvestigationHistory = async (params?: {
  scan_type?: string;
  risk_level?: string;
  search?: string;
  limit?: number;
}): Promise<InvestigationHistoryItem[]> => {
  const res = await api.get('/reports/history', { params });
  return res.data;
};

export const getReportDetail = async (scanId: string) => {
  const res = await api.get(`/reports/${scanId}`);
  return res.data;
};

export const getExportJsonUrl = (scanId: string) => `${API_BASE_URL}/reports/${scanId}/export/json`;
export const getExportPdfUrl = (scanId: string) => `${API_BASE_URL}/reports/${scanId}/export/pdf`;

// Blockchain Threat Verification
export const getBlockchainStatus = async (): Promise<BlockchainStatus> => {
  const res = await api.get('/blockchain/status');
  return res.data;
};

export const recordThreatOnChain = async (data: {
  scan_id: string;
  target: string;
  threat_type: string;
  risk_level: string;
  risk_score: number;
  findings_digest: string;
}): Promise<BlockchainVerification> => {
  const res = await api.post('/blockchain/record', data);
  return res.data;
};

export const verifyReportOnChain = async (
  reportHash: string,
  payloadToVerify?: Record<string, unknown>
): Promise<BlockchainVerification> => {
  const res = await api.post('/blockchain/verify', {
    report_hash: reportHash,
    payload_to_verify: payloadToVerify,
  });
  return res.data;
};

export const getBlockchainRecords = async () => {
  const res = await api.get('/blockchain/records');
  return res.data;
};

// Unified Classifier & Scan
export const classifyInput = async (query: string): Promise<UnifiedClassification> => {
  const res = await api.post('/unified/classify', { query });
  return res.data;
};

export const executeUnifiedScan = async (query: string, forcedType: string = 'auto') => {
  const res = await api.post('/unified/scan', { query, forced_type: forcedType });
  return res.data;
};

// Settings
export const getSettings = async () => {
  const res = await api.get('/settings/');
  return res.data;
};

export const updateSettings = async (data: {
  gemini_api_key?: string;
  google_safe_browsing_api_key?: string;
  virustotal_api_key?: string;
  ethereum_rpc_url?: string;
  contract_address?: string;
}) => {
  const res = await api.post('/settings/update', data);
  return res.data;
};

export default api;
