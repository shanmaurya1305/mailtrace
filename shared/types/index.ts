/**
 * MAILTRACE 2.0 - Shared TypeScript Type Contracts
 */

export interface HealthCheckResponse {
  status: string;
  service: string;
}

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL' | 'UNKNOWN';

export interface SystemStatus {
  apiConnected: boolean;
  serviceName?: string;
  serviceStatus?: string;
  lastChecked?: string;
  error?: string;
}

export interface ForensicAnalysisRequest {
  raw_headers: string;
}

export interface HeaderDetails {
  from_address?: string;
  to_addresses: string[];
  cc_addresses: string[];
  reply_to?: string;
  return_path?: string;
  subject?: string;
  message_id?: string;
  date?: string;
  raw_headers_dict: Record<string, string[]>;
}

export interface AuthMechanismStatus {
  available: boolean;
  status: string; // pass, fail, softfail, neutral, none, temperror, permerror, policy, unavailable
  source?: string;
  raw_details?: string;
  signature_present?: boolean;
  verification_performed: boolean;
}

export interface AuthenticationSummary {
  spf: AuthMechanismStatus;
  dkim: AuthMechanismStatus;
  dmarc: AuthMechanismStatus;
}

export interface ReceivedHop {
  hop_index: number;
  from_host?: string;
  by_host?: string;
  with_protocol?: string;
  id_string?: string;
  timestamp?: string;
  source_ip?: string;
  raw_header: string;
}

export interface ExtractedIP {
  type: string;
  value: string;
  source: string;
  validated: boolean;
}

export interface ExtractedDomain {
  type: string;
  value: string;
  source: string;
}

export interface ExtractedInfrastructure {
  ip_addresses: ExtractedIP[];
  domains: ExtractedDomain[];
}

export interface ForensicEvidence {
  evidence_id: string;
  type: string;
  severity: 'info' | 'low' | 'medium' | 'high' | string;
  title: string;
  description: string;
  source: string;
  observed_value?: string;
}

export interface ForensicAnalysisResponse {
  analysis_id: string;
  status: string;
  headers: HeaderDetails;
  authentication: AuthenticationSummary;
  received_chain: ReceivedHop[];
  infrastructure: ExtractedInfrastructure;
  evidence: ForensicEvidence[];
  warnings: string[];
}

export interface ThreatClassificationInput {
  subject?: string;
  body: string;
  headers_snippet?: string;
}

export interface ThreatClassificationResult {
  model_available: boolean;
  status: string; // "model_available" | "model_unavailable" | "completed"
  primary_label?: 'phishing' | 'business_email_compromise' | 'suspicious' | 'benign' | string;
  confidence?: number;
  probabilities: Record<string, number>;
  device_used: string;
  model_name_or_path?: string;
  details?: string;
  explanation?: string;
}

export interface ExtractedURL {
  type: string;
  value: string;
  source: string;
}

export interface ExtractedEmailAddress {
  type: string;
  value: string;
  source: string;
}

export interface InvestigationIOCs {
  ip_addresses: ExtractedIP[];
  domains: ExtractedDomain[];
  urls: ExtractedURL[];
  email_addresses: ExtractedEmailAddress[];
  suspicious_header_indicators: string[];
}

export interface InvestigationRequest {
  subject?: string;
  body?: string;
  raw_headers: string;
}

export interface InvestigationSummary {
  analysis_id: string;
  status: string;
  timestamp_utc: string;
  threat_model_status: string;
  threat_model_prediction?: string;
}

export interface InvestigationRouting {
  sender?: string;
  sender_domain?: string;
  reply_to?: string;
  reply_to_domain?: string;
  return_path?: string;
  return_path_domain?: string;
  received_hops: ReceivedHop[];
}

export interface InvestigationResponse {
  analysis_id: string;
  status: string;
  summary: InvestigationSummary;
  authentication: AuthenticationSummary;
  routing: InvestigationRouting;
  indicators: InvestigationIOCs;
  evidence: ForensicEvidence[];
  threat_analysis: ThreatClassificationResult;
  warnings: string[];
}

