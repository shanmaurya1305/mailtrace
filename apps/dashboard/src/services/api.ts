import {
  HealthCheckResponse,
  ForensicAnalysisResponse,
  InvestigationRequest,
  InvestigationResponse
} from '../../../../shared/types';

/**
 * API Base URL configured via environment variables.
 * Automatically normalizes trailing slashes.
 * Falls back to http://localhost:8000 if VITE_API_BASE_URL is not set.
 */
const rawBaseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
export const API_BASE_URL = rawBaseUrl.replace(/\/+$/, '');

export async function fetchHealth(): Promise<HealthCheckResponse> {
  try {
    const response = await fetch(`${API_BASE_URL}/api/health`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return await response.json();
  } catch (err: any) {
    if (err.name === 'TypeError' && err.message === 'Failed to fetch') {
      throw new Error(`Failed to connect to API at ${API_BASE_URL}/api/health. Ensure backend is running and CORS origin is allowed.`);
    }
    throw err;
  }
}

export async function analyzeHeaders(rawHeaders: string): Promise<ForensicAnalysisResponse> {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/forensics/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({ raw_headers: rawHeaders }),
    });

    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      const detail = errorBody.detail || `HTTP error! status: ${response.status}`;
      throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
    }

    return await response.json();
  } catch (err: any) {
    if (err.name === 'TypeError' && err.message === 'Failed to fetch') {
      throw new Error(`Failed to reach API at ${API_BASE_URL}/api/v1/forensics/analyze. Check backend server and CORS origin configuration.`);
    }
    throw err;
  }
}

export async function analyzeInvestigation(request: InvestigationRequest): Promise<InvestigationResponse> {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/investigation/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      const detail = errorBody.detail || `HTTP error! status: ${response.status}`;
      throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
    }

    return await response.json();
  } catch (err: any) {
    if (err.name === 'TypeError' && err.message === 'Failed to fetch') {
      throw new Error(`Failed to reach API at ${API_BASE_URL}/api/v1/investigation/analyze. Check backend server and CORS origin configuration.`);
    }
    throw err;
  }
}
