export type RiskLevel = 'LOW' | 'SUSPICIOUS' | 'HIGH' | 'CONFIRMED MALICIOUS';

export interface EvidenceItem {
  category: string;
  indicator: string;
  description: string;
  severity: RiskLevel;
  source: string;
}

export interface RecommendedAction {
  title: string;
  priority: 'Critical' | 'High' | 'Medium' | 'Informational';
  action: string;
  target_audience?: string;
}

export interface SecurityScore {
  score: number;
  grade: string;
  risk_level: RiskLevel;
  label: string;
}

export interface DomainInfo {
  raw_domain: string;
  subdomain: string;
  domain: string;
  suffix: string;
  registered_domain: string;
  is_ip: boolean;
  entropy: number;
  length: number;
  tld_risk_tier: string;
  domain_age_days?: number | null;
  registrar?: string | null;
}

export interface TyposquattingFinding {
  is_typosquat: boolean;
  targeted_brand?: string | null;
  similarity_score: number;
  technique?: string | null;
  explanation?: string | null;
}

export interface HomographFinding {
  has_homograph: boolean;
  punycode?: string | null;
  scripts_detected: string[];
  spoofed_characters: string[];
  explanation?: string | null;
}

export interface DNSRecords {
  a_records: string[];
  aaaa_records: string[];
  mx_records: string[];
  ns_records: string[];
  txt_records: string[];
  resolved_ip?: string | null;
  lookup_status: string;
}

export interface RedirectHop {
  hop_number: number;
  url: string;
  status_code: number;
  resolved_ip: string;
  response_time_ms: number;
  is_safe: boolean;
}

export interface ThreatIntelSource {
  source_name: string;
  checked: boolean;
  is_flagged: boolean;
  category?: string | null;
  details?: string | null;
  status_note: string;
}

export interface URLScanResponse {
  id: string;
  submitted_url: string;
  normalized_url: string;
  scheme: string;
  risk_level: RiskLevel;
  risk_score: number;
  security_score: SecurityScore;
  domain_info: DomainInfo;
  typosquatting: TyposquattingFinding;
  homograph: HomographFinding;
  suspicious_patterns: string[];
  dns: DNSRecords;
  redirect_chain: RedirectHop[];
  threat_intel: ThreatIntelSource[];
  evidence: EvidenceItem[];
  recommendations: RecommendedAction[];
  canonical_hash: string;
  timestamp: string;
}

export interface CertificateChainNode {
  level: number;
  subject: string;
  issuer: string;
  is_root: boolean;
  is_leaf: boolean;
  valid_from: string;
  valid_to: string;
  signature_algorithm: string;
}

export interface TLSScanResponse {
  id?: string;
  canonical_hash?: string;
  hostname: string;
  port: number;
  connected_ip?: string | null;
  protocol_version: string;
  cipher_suite: string;
  subject_cn?: string | null;
  subject_org?: string | null;
  issuer_cn?: string | null;
  issuer_org?: string | null;
  sans: string[];
  valid_from: string;
  valid_to: string;
  days_remaining: number;
  is_valid: boolean;
  is_expired: boolean;
  is_self_signed: boolean;
  is_ca_trusted?: boolean;
  hostname_matches: boolean;
  serial_number: string;
  signature_algorithm: string;
  key_type: string;
  key_bits: number;
  certificate_chain: CertificateChainNode[];
  revocation_status: string;
  warnings: string[];
  risk_level: RiskLevel;
  risk_score: number;
  timestamp: string;
}

export interface HeaderItem {
  name: string;
  status: 'PRESENT_OPTIMAL' | 'PRESENT_WEAK' | 'MISSING' | 'INSECURE';
  actual_value?: string | null;
  importance: 'HIGH' | 'MEDIUM' | 'LOW';
  recommended_value: string;
  purpose: string;
  security_impact: string;
}

export interface HeaderScanResponse {
  id?: string;
  canonical_hash?: string;
  url: string;
  final_url: string;
  status_code: number;
  headers_table: HeaderItem[];
  security_score: number;
  missing_count: number;
  optimal_count: number;
  weak_count: number;
  server_banner?: string | null;
  information_disclosure: string[];
  disclaimer: string;
  timestamp: string;
}

export interface ExtractedUrlItem {
  url: string;
  domain: string;
  is_suspicious: boolean;
  risk_indicator?: string | null;
}

export interface SuspiciousEntity {
  entity: string;
  entity_type: string;
  context: string;
}

export interface MessageScanResponse {
  id: string;
  message_type: string;
  risk_level: RiskLevel;
  risk_score: number;
  confidence_score: number;
  attack_category: string;
  extracted_urls: ExtractedUrlItem[];
  suspicious_entities: SuspiciousEntity[];
  manipulation_techniques: string[];
  explanation: string;
  evidence: EvidenceItem[];
  recommended_actions: RecommendedAction[];
  source: 'gemini_ai' | 'heuristic_engine';
  ai_disclaimer: string;
  canonical_hash: string;
  timestamp: string;
}

export interface GeolocationInfo {
  country: string;
  country_code: string;
  city: string;
  region: string;
  latitude: number;
  longitude: number;
  timezone: string;
}

export interface NetworkInfo {
  asn?: string | null;
  asn_org?: string | null;
  isp?: string | null;
  reverse_dns?: string | null;
  is_hosting: boolean;
  is_vpn_tor: boolean;
}

export interface IPScanResponse {
  id: string;
  ip_address: string;
  ip_version: string;
  is_private: boolean;
  is_loopback: boolean;
  is_reserved: boolean;
  classification: string;
  network_info: NetworkInfo;
  geo_info: GeolocationInfo;
  reputation_score: number;
  risk_level: RiskLevel;
  abuse_categories: string[];
  associated_domains: string[];
  threat_intel_matches: string[];
  evidence: EvidenceItem[];
  recommendations: RecommendedAction[];
  canonical_hash: string;
  timestamp: string;
}

export interface ThreatIOC {
  id: string;
  ioc_value: string;
  ioc_type: string;
  threat_category: string;
  severity: RiskLevel;
  source: string;
  description?: string | null;
  confidence: number;
  is_demo?: boolean;
  first_seen: string;
  last_seen: string;
  is_active: boolean;
}

export interface ThreatStats {
  total_scans: number;
  malicious_detected: number;
  suspicious_detected: number;
  threats_blocked: number;
  security_score: number;
  threat_categories: Record<string, number>;
  severity_distribution: Record<string, number>;
  recent_activity_trends: Array<{
    date: string;
    scanned: number;
    threats: number;
    blocked: number;
  }>;
}

export interface BlockchainVerification {
  is_verified: boolean;
  is_simulated?: boolean;
  report_hash: string;
  reporter_address: string;
  threat_type: string;
  risk_level: string;
  timestamp_utc: string;
  block_number: number;
  tx_hash: string;
  network: string;
  gas_used: number;
  smart_contract_address?: string | null;
  is_tamper_free: boolean;
  verification_message: string;
}

export interface BlockchainStatus {
  network: string;
  is_live_sepolia: boolean;
  is_simulated?: boolean;
  connection_status?: string;
  status_detail?: string;
  contract_bytecode_verified?: boolean;
  smart_contract_address?: string | null;
  chain_id: number;
  total_reports_anchored: number;
  verification_mechanism: string;
  privacy_guarantee: string;
}

export interface InvestigationHistoryItem {
  id: string;
  target: string;
  scan_type: string;
  risk_level: RiskLevel;
  risk_score: number;
  summary: string;
  evidence_count: number;
  recommendations_count: number;
  blockchain_hash?: string | null;
  blockchain_tx?: string | null;
  created_at: string;
}

export interface UnifiedClassification {
  type: 'url' | 'ip' | 'message';
  subtype?: string;
  confidence: number;
  target: string;
  label: string;
  route: string;
}

