import React, { useState, useEffect } from 'react';
import {
  Shield,
  CheckCircle2,
  AlertCircle,
  Cpu,
  Globe,
  Server,
  Fingerprint,
  ExternalLink,
  ShieldAlert,
  ShieldX,
  Play,
  RotateCw,
  Mail,
  AlertTriangle,
} from 'lucide-react';
import { analyzeEmailInvestigation, buildHeadersFromMetadata } from './services/api';
import { DASHBOARD_URL } from './config';
import type {
  ExtractedEmailData,
  InvestigationResponse,
  GetEmailContentMessage,
  EmailContentResultMessage,
} from './types';

// Safe demo fixtures for quick hackathon review when not on a live Gmail page
const DEMO_PRESETS: Record<string, ExtractedEmailData> = {
  spearPhishing: {
    subject: 'CRITICAL: Immediate Password Expiration Notice for Corporate SSO',
    sender: 'IT Support Desk <support@example.com>',
    recipient: 'analyst@example.org',
    body: 'Your single-sign-on credentials will expire in 2 hours. Verify at https://portal-sso-verify.example.net/auth/login?user=analyst@example.org',
    urls: ['https://portal-sso-verify.example.net/auth/login?user=analyst@example.org'],
    extractionTimestamp: new Date().toISOString(),
    sourceUrl: 'https://mail.google.com/mail/u/0/#inbox/demo-phish-1',
  },
  becWire: {
    subject: 'Confidential: Urgent Acquisition Wire Settlement - Reroute Instructions',
    sender: 'Chief Executive Officer <ceo@example.com>',
    recipient: 'finance@example.org',
    body: 'Escrow vendor hold this morning. Reroute wire ($142,500.00) immediately to Apex Settlement Holdings LLC routing 021000021.',
    urls: [],
    extractionTimestamp: new Date().toISOString(),
    sourceUrl: 'https://mail.google.com/mail/u/0/#inbox/demo-bec-1',
  },
};

type AnalysisState = 'idle' | 'extracting' | 'analyzing' | 'completed' | 'api_unavailable' | 'extract_failed';

export const Popup: React.FC = () => {
  const [emailData, setEmailData] = useState<ExtractedEmailData | null>(null);
  const [analysisState, setAnalysisState] = useState<AnalysisState>('idle');
  const [statusMessage, setStatusMessage] = useState<string>('Ready to analyze this email.');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [result, setResult] = useState<InvestigationResponse | null>(null);
  const [isGmailTab, setIsGmailTab] = useState<boolean>(false);

  // Request visible email information from active tab content script
  const extractFromActiveTab = () => {
    setAnalysisState('extracting');
    setStatusMessage('Reading visible email content from Gmail...');
    setErrorMessage(null);

    if (typeof chrome === 'undefined' || !chrome.tabs) {
      // Running in browser dev mode without Chrome extension APIs
      setEmailData(DEMO_PRESETS.spearPhishing);
      setIsGmailTab(true);
      setAnalysisState('idle');
      setStatusMessage('Demo environment active. Ready to analyze.');
      return;
    }

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const activeTab = tabs[0];
      if (!activeTab || !activeTab.id) {
        setAnalysisState('extract_failed');
        setStatusMessage('No active browser tab found.');
        return;
      }

      const url = activeTab.url || '';
      const onGmail = url.includes('mail.google.com');
      setIsGmailTab(onGmail);

      if (!onGmail) {
        setAnalysisState('extract_failed');
        setStatusMessage('Active tab is not Gmail.');
        return;
      }

      const message: GetEmailContentMessage = { type: 'GET_EMAIL_CONTENT' };
      chrome.tabs.sendMessage(activeTab.id, message, (response: EmailContentResultMessage) => {
        if (chrome.runtime.lastError) {
          setAnalysisState('extract_failed');
          setStatusMessage('Could not connect to Gmail tab. Ensure page is loaded.');
          return;
        }

        if (response && response.success && response.data) {
          setEmailData(response.data);
          setAnalysisState('idle');
          setStatusMessage('Email detected. Ready to analyze.');
        } else {
          setAnalysisState('extract_failed');
          setStatusMessage(response?.error || 'No open email thread detected in Gmail.');
        }
      });
    });
  };

  useEffect(() => {
    extractFromActiveTab();
  }, []);

  // Trigger real FastAPI investigation analysis
  const handleAnalyze = async () => {
    if (!emailData) {
      setErrorMessage('No email content available to analyze.');
      return;
    }

    setAnalysisState('analyzing');
    setStatusMessage('Running MailTrace forensic analysis...');
    setErrorMessage(null);

    try {
      const investigationResult = await analyzeEmailInvestigation(emailData);
      setResult(investigationResult);
      setAnalysisState('completed');
      setStatusMessage('Forensic analysis completed.');

      // Save analysis reference in temporary extension storage for dashboard
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({
          mailtrace_latest_analysis: {
            analysis_id: investigationResult.analysis_id,
            timestamp: investigationResult.summary.timestamp_utc,
            subject: emailData.subject,
          },
        });
      }
    } catch (err: any) {
      setAnalysisState('api_unavailable');
      setErrorMessage(err?.message || 'MailTrace API unavailable. Start the FastAPI backend and try again.');
      setStatusMessage('Analysis failed.');
    }
  };

  const handleOpenDashboard = () => {
    let targetUrl = `${DASHBOARD_URL}/investigation`;
    if (emailData) {
      try {
        const payload = {
          subject: emailData.subject || '',
          body: emailData.body || '',
          rawHeaders: buildHeadersFromMetadata(emailData),
          result: result || null,
        };
        const encoded = encodeURIComponent(JSON.stringify(payload));
        targetUrl = `${DASHBOARD_URL}/investigation#import=${encoded}`;
      } catch (err) {
        console.error('Failed to encode email payload for dashboard:', err);
      }
    }
    if (typeof chrome !== 'undefined' && chrome.tabs) {
      chrome.tabs.create({ url: targetUrl });
    } else {
      window.open(targetUrl, '_blank');
    }
  };

  const loadPreset = (presetKey: keyof typeof DEMO_PRESETS) => {
    setEmailData(DEMO_PRESETS[presetKey]);
    setResult(null);
    setAnalysisState('idle');
    setStatusMessage('Demo preset loaded. Ready to analyze.');
    setErrorMessage(null);
  };

  return (
    <div className="w-[390px] min-h-[480px] max-h-[580px] bg-[#0a0d14] text-gray-100 flex flex-col justify-between border border-[#1e2638] font-sans overflow-y-auto">
      {/* Extension Header */}
      <div>
        <div className="p-3.5 bg-[#121722] border-b border-[#1e2638] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-blue-600/10 border border-blue-500/20 text-blue-400">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <div className="font-bold text-xs text-white tracking-wide font-mono flex items-center gap-1.5">
                <span>MAILTRACE</span>
                <span className="text-[9px] px-1.5 py-0.2 rounded bg-blue-500/20 text-blue-400 font-semibold">2.0</span>
              </div>
              <p className="text-[10px] text-gray-400">Email Forensics & Security</p>
            </div>
          </div>
          <button
            onClick={extractFromActiveTab}
            title="Re-extract from Gmail tab"
            className="p-1.5 rounded bg-[#1a2130] hover:bg-[#252f44] text-gray-400 hover:text-gray-200 transition-colors"
          >
            <RotateCw className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-3.5 space-y-3.5">
          {/* Current Email Section */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase tracking-wider text-gray-400 font-semibold">
                Target Email
              </span>
              {isGmailTab && (
                <span className="text-[9px] font-mono text-emerald-400 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                  Gmail Active
                </span>
              )}
            </div>

            {emailData ? (
              <div className="p-2.5 rounded-lg bg-[#121722] border border-[#1e2638] space-y-1.5">
                <div className="text-xs font-semibold text-white truncate" title={emailData.subject}>
                  {emailData.subject}
                </div>
                <div className="text-[11px] font-mono text-gray-400 truncate" title={emailData.sender}>
                  From: <span className="text-gray-300">{emailData.sender}</span>
                </div>
                {emailData.urls.length > 0 && (
                  <div className="text-[10px] font-mono text-cyan-400">
                    {emailData.urls.length} external URL(s) detected in body
                  </div>
                )}
              </div>
            ) : (
              <div className="p-3 rounded-lg bg-[#121722]/80 border border-dashed border-[#1e2638] space-y-2">
                <p className="text-[11px] text-gray-400 leading-snug">
                  {statusMessage}
                </p>
                {/* Hackathon Demo Quick Select */}
                <div className="pt-2 border-t border-[#1e2638]/60 space-y-1.5">
                  <span className="text-[9px] font-mono text-gray-500 uppercase">Load Demo Scenario:</span>
                  <div className="flex gap-1.5">
                    <button
                      onClick={() => loadPreset('spearPhishing')}
                      className="flex-1 py-1 px-2 rounded bg-[#1a2130] hover:bg-[#252f44] text-[10px] font-mono text-amber-300 border border-amber-500/20"
                    >
                      Phishing Demo
                    </button>
                    <button
                      onClick={() => loadPreset('becWire')}
                      className="flex-1 py-1 px-2 rounded bg-[#1a2130] hover:bg-[#252f44] text-[10px] font-mono text-rose-300 border border-rose-500/20"
                    >
                      BEC Demo
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Primary Action Button */}
          {emailData && (
            <button
              onClick={handleAnalyze}
              disabled={analysisState === 'analyzing' || analysisState === 'extracting'}
              className="w-full py-2.5 px-3 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-mono text-xs font-semibold flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20 transition-all"
            >
              {analysisState === 'analyzing' ? (
                <>
                  <Cpu className="w-3.5 h-3.5 animate-spin" />
                  <span>Analyzing with MailTrace...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Analyze with MailTrace</span>
                </>
              )}
            </button>
          )}

          {/* Error Banner */}
          {errorMessage && (
            <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-mono flex items-start gap-2">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{errorMessage}</span>
            </div>
          )}

          {/* Investigation Results Display */}
          {result && (
            <div className="space-y-3 pt-1 border-t border-[#1e2638]">
              {/* Authentication Status */}
              <div className="p-2.5 rounded-lg bg-[#121722] border border-[#1e2638] space-y-1.5">
                <div className="flex items-center justify-between text-[10px] font-mono uppercase text-gray-400">
                  <span className="flex items-center gap-1 font-semibold">
                    <Fingerprint className="w-3 h-3 text-emerald-400" />
                    Authentication
                  </span>
                  <span>SPF / DKIM / DMARC</span>
                </div>
                <div className="grid grid-cols-3 gap-1.5 pt-1 text-center font-mono">
                  <div className="p-1 rounded bg-[#0a0d14] border border-[#1e2638]">
                    <div className="text-[8px] text-gray-500">SPF</div>
                    <div className={`text-[10px] font-bold uppercase ${
                      result.authentication.spf.status === 'pass'
                        ? 'text-emerald-400'
                        : result.authentication.spf.status === 'fail'
                        ? 'text-rose-400'
                        : 'text-amber-400'
                    }`}>
                      {result.authentication.spf.status}
                    </div>
                  </div>
                  <div className="p-1 rounded bg-[#0a0d14] border border-[#1e2638]">
                    <div className="text-[8px] text-gray-500">DKIM</div>
                    <div className={`text-[10px] font-bold uppercase ${
                      result.authentication.dkim.status === 'pass'
                        ? 'text-emerald-400'
                        : result.authentication.dkim.status === 'fail'
                        ? 'text-rose-400'
                        : 'text-amber-400'
                    }`}>
                      {result.authentication.dkim.status}
                    </div>
                  </div>
                  <div className="p-1 rounded bg-[#0a0d14] border border-[#1e2638]">
                    <div className="text-[8px] text-gray-500">DMARC</div>
                    <div className={`text-[10px] font-bold uppercase ${
                      result.authentication.dmarc.status === 'pass'
                        ? 'text-emerald-400'
                        : result.authentication.dmarc.status === 'fail'
                        ? 'text-rose-400'
                        : 'text-amber-400'
                    }`}>
                      {result.authentication.dmarc.status}
                    </div>
                  </div>
                </div>
              </div>

              {/* Indicators Counts */}
              <div className="p-2.5 rounded-lg bg-[#121722] border border-[#1e2638] space-y-1.5">
                <div className="flex items-center justify-between text-[10px] font-mono uppercase text-gray-400">
                  <span className="flex items-center gap-1 font-semibold">
                    <Globe className="w-3 h-3 text-cyan-400" />
                    Extracted IOCs
                  </span>
                  <span>Factual Signals</span>
                </div>
                <div className="grid grid-cols-4 gap-1 pt-1 text-center font-mono">
                  <div className="p-1 rounded bg-[#0a0d14] border border-[#1e2638]">
                    <div className="text-[8px] text-gray-500">IPs</div>
                    <div className="text-xs font-bold text-emerald-400">
                      {result.indicators.ip_addresses.length}
                    </div>
                  </div>
                  <div className="p-1 rounded bg-[#0a0d14] border border-[#1e2638]">
                    <div className="text-[8px] text-gray-500">Domains</div>
                    <div className="text-xs font-bold text-blue-400">
                      {result.indicators.domains.length}
                    </div>
                  </div>
                  <div className="p-1 rounded bg-[#0a0d14] border border-[#1e2638]">
                    <div className="text-[8px] text-gray-500">URLs</div>
                    <div className="text-xs font-bold text-cyan-400">
                      {result.indicators.urls.length}
                    </div>
                  </div>
                  <div className="p-1 rounded bg-[#0a0d14] border border-[#1e2638]">
                    <div className="text-[8px] text-gray-500">Emails</div>
                    <div className="text-xs font-bold text-indigo-400">
                      {result.indicators.email_addresses.length}
                    </div>
                  </div>
                </div>
              </div>

              {/* AI Model Status Card */}
              <div className="p-2.5 rounded-lg bg-[#121722] border border-[#1e2638] space-y-1 font-mono text-[11px]">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] text-gray-400 uppercase font-semibold flex items-center gap-1">
                    <Cpu className="w-3 h-3 text-indigo-400" />
                    AI Model Status
                  </span>
                  <span className={`text-[9px] px-1.5 py-0.2 rounded font-bold uppercase ${
                    result.threat_analysis.model_available
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                      : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                  }`}>
                    {result.threat_analysis.status}
                  </span>
                </div>

                {result.threat_analysis.model_available ? (
                  <div className="text-emerald-400 font-bold text-xs pt-1">
                    Prediction: {result.threat_analysis.primary_label}
                  </div>
                ) : (
                  <div className="text-gray-400 text-[10px] leading-relaxed pt-1">
                    <p className="text-amber-300 font-semibold">AI model unavailable</p>
                    <p>No ML prediction was generated.</p>
                    <p className="text-gray-500">Configure a trained MAILTRACE model to enable AI classification.</p>
                  </div>
                )}
              </div>

              {/* Open Full Investigation Button */}
              <button
                onClick={handleOpenDashboard}
                className="w-full py-2 px-3 rounded-lg bg-[#1a2130] hover:bg-[#252f44] border border-blue-500/30 text-blue-400 hover:text-blue-300 font-mono text-xs flex items-center justify-center gap-1.5 transition-all"
              >
                <span>Open Full Investigation</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Extension Footer */}
      <div className="p-2.5 border-t border-[#1e2638] bg-[#0c1018] text-center text-[10px] text-gray-500 font-mono">
        MAILTRACE 2.0 • Manifest V3 • Zero Telemetry Leakage
      </div>
    </div>
  );
};
