import { API_BASE_URL } from '../config';
import type { ExtractedEmailData, InvestigationResponse } from '../types';

/**
 * Reconstructs a valid RFC 822 email header block from extracted DOM metadata.
 * Ensures the forensic header parser receives a standard, parseable header structure.
 */
export function buildHeadersFromMetadata(email: ExtractedEmailData): string {
  const dateStr = email.extractionTimestamp
    ? new Date(email.extractionTimestamp).toUTCString()
    : new Date().toUTCString();
  const safeId = `mailtrace-ext-${Date.now()}`;

  const headerLines = [
    `From: ${email.sender || 'unknown@example.org'}`,
    `To: ${email.recipient || 'recipient@example.org'}`,
    `Subject: ${email.subject || 'No Subject'}`,
    `Date: ${dateStr}`,
    `Message-ID: <${safeId}@mailtrace.local>`,
    `X-Mailer: Gmail Web Interface`,
    `X-Analyzed-By: MAILTRACE 2.0 Browser Extension`,
  ];

  return headerLines.join('\r\n');
}

/**
 * Sends extracted email information to the real MAILTRACE FastAPI investigation endpoint.
 * POST /api/v1/investigation/analyze
 */
export async function analyzeEmailInvestigation(email: ExtractedEmailData): Promise<InvestigationResponse> {
  const headers = buildHeadersFromMetadata(email);

  const payload = {
    subject: email.subject || undefined,
    body: email.body || '',
    raw_headers: headers,
  };

  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/investigation/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const errBody = await response.json().catch(() => ({}));
      const detail = errBody.detail || `HTTP ${response.status} error from backend`;
      throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
    }

    return await response.json();
  } catch (err: any) {
    if (err.name === 'TypeError' && err.message === 'Failed to fetch') {
      throw new Error(`MailTrace API unavailable. Start the FastAPI backend at ${API_BASE_URL} and try again.`);
    }
    throw err;
  }
}
