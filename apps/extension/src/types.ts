/**
 * MAILTRACE 2.0 - Extension Message & Investigation Types
 */

export interface ExtractedEmailData {
  subject: string;
  sender: string;
  recipient: string;
  body: string;
  urls: string[];
  extractionTimestamp: string;
  sourceUrl: string;
}

export type ExtensionMessageType =
  | 'GET_EMAIL_CONTENT'
  | 'EMAIL_CONTENT_RESULT'
  | 'ANALYZE_EMAIL'
  | 'ANALYSIS_RESULT'
  | 'ANALYSIS_ERROR';

export interface GetEmailContentMessage {
  type: 'GET_EMAIL_CONTENT';
}

export interface EmailContentResultMessage {
  type: 'EMAIL_CONTENT_RESULT';
  success: boolean;
  data?: ExtractedEmailData;
  error?: string;
}

export interface AnalyzeEmailMessage {
  type: 'ANALYZE_EMAIL';
  data: ExtractedEmailData;
}

export interface AuthMechanismStatus {
  available: boolean;
  status: string; // pass, fail, softfail, neutral, none, unavailable
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

export interface ForensicEvidence {
  evidence_id: string;
  type: string;
  severity: 'info' | 'low' | 'medium' | 'high' | string;
  title: string;
  description: string;
  source: string;
  observed_value?: string;
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
