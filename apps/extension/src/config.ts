/**
 * MAILTRACE 2.0 - Browser Extension Configuration
 * Normalizes trailing slashes.
 * Local development defaults to http://127.0.0.1:8000 (FastAPI) and http://localhost:5174 (Dashboard).
 */

const rawApiBaseUrl = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';
export const API_BASE_URL = rawApiBaseUrl.replace(/\/+$/, '');

const rawDashboardUrl = import.meta.env.VITE_DASHBOARD_URL || 'http://localhost:5173';
export const DASHBOARD_URL = rawDashboardUrl.replace(/\/+$/, '');
