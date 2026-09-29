import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  FileSearch,
  Play,
  AlertCircle,
  CheckCircle2,
  ShieldAlert,
  Cpu,
  Globe,
  Server,
  Info,
  Mail,
  Link as LinkIcon,
  Fingerprint,
  Layers,
  ArrowRight,
  ShieldX,
  FileCode,
  AlertTriangle,
  Download,
  RotateCcw,
} from 'lucide-react';
import { analyzeInvestigation } from '../services/api';
import { InvestigationResponse } from '../../../../shared/types';

// Safe demo fixtures using reserved documentation domains and RFC 5737 IP blocks
const DEMO_FIXTURES = {
  spearPhishing: {
    name: 'Spear Phishing / Credential Theft',
    badge: 'Phishing Pattern',
    subject: 'CRITICAL: Immediate Password Expiration Notice for Corporate SSO',
    body: `Dear Employee,

Your corporate single-sign-on (SSO) credentials will expire in 2 hours due to quarterly security policy enforcement.

To retain access to your work inbox, calendar, and ERP tools, verify your account credentials immediately at the secure link below:
https://portal-sso-verify.example.net/auth/login?user=analyst@example.org

Failure to update before 14:00 UTC will trigger an automatic account freeze.

IT Helpdesk Operations
Contact: helpdesk-admin@example.net
Direct verification server: 198.51.100.89`,
    rawHeaders: `From: IT Support Desk <support@example.com>
To: Analyst <analyst@example.org>
Subject: CRITICAL: Immediate Password Expiration Notice for Corporate SSO
Date: Sun, 27 Sep 2026 12:15:00 +0000
Message-ID: <sso-alert-9912@example.com>
Reply-To: credential-collector@example.net
Return-Path: <bounce-daemon@example.net>
Received: from mail-relay-ext.example.net (mail-relay-ext.example.net [198.51.100.44])
    by mx.example.org (Postfix) with SMTP id 8Xabc45678
    for <analyst@example.org>; Sun, 27 Sep 2026 12:15:02 +0000
Authentication-Results: mx.example.org;
    spf=softfail smtp.mailfrom=bounce-daemon@example.net;
    dkim=none;
    dmarc=fail header.from=example.com`
  },

  becFraud: {
    name: 'Business Email Compromise (BEC)',
    badge: 'BEC Pattern',
    subject: 'Confidential: Urgent Acquisition Wire Settlement - Reroute Instructions',
    body: `Good morning,

I am in confidential meetings all morning closing the Q3 regional acquisition. 

Our primary escrow vendor experienced a banking routing hold this morning. To avoid acquisition penalties, please immediately reroute today's outstanding settlement wire ($142,500.00) to our designated secondary capital account:

Beneficiary: Apex Settlement Holdings LLC
Bank: Global Escrow Trust Bank
Account: 9812-4412-0012
Routing: 021000021
Reference: ACQ-2026-SETTLE

Please process this wire transfer immediately via SWIFT and confirm the tracking reference by reply email. Do not call my office line as I cannot take calls during negotiations.

Regards,
Executive Leadership
Mobile: +1-555-0199
Notice: Banking details updated under protocol 192.0.2.77`,
    rawHeaders: `From: Chief Executive Officer <ceo@example.com>
To: Finance Controller <finance@example.org>
Subject: Confidential: Urgent Acquisition Wire Settlement - Reroute Instructions
Date: Sun, 27 Sep 2026 12:30:00 +0000
Message-ID: <wire-req-2026@example.com>
Reply-To: executive-finance@example.biz
Return-Path: <spoofed-return@example.biz>
Received: from untrusted-gateway.example.biz (untrusted-gateway.example.biz [192.0.2.77])
    by mx.example.org (Postfix) with ESMTP id 9Zqwerty123
    for <finance@example.org>; Sun, 27 Sep 2026 12:30:05 +0000
Authentication-Results: mx.example.org;
    spf=fail (sender IP 192.0.2.77 is not authorized for example.com);
    dkim=fail;
    dmarc=fail (p=REJECT header.from=example.com)`
  },

  legitimateCorporate: {
    name: 'Legitimate Corporate Communication',
    badge: 'Benign Pattern',
    subject: 'Quarterly Infrastructure Engineering Review & Security Roadmap',
    body: `Hello Team,

Attached is the agenda for our upcoming quarterly engineering review. We will cover:
1. Multi-region redundancy milestones
2. Postfix routing cluster metrics
3. SOC SIEM integration updates

Please review the architectural notes in our internal documentation wiki before Thursday's meeting:
https://wiki.example.com/engineering/roadmap-2026

Documentation maintained by systems-team@example.com.
Internal gateway node: 203.0.113.10.

Best regards,
Engineering Operations Team`,
    rawHeaders: `From: Engineering Operations <systems-team@example.com>
To: Core Engineering <engineers@example.org>
Subject: Quarterly Infrastructure Engineering Review & Security Roadmap
Date: Sun, 27 Sep 2026 11:00:00 +0000
Message-ID: <infra-eng-20260927@example.com>
Reply-To: systems-team@example.com
Return-Path: <bounces@example.com>
Received: from mx-outbound.example.com (mx-outbound.example.com [203.0.113.10])
    by mx.example.org (Postfix) with ESMTPS id 4Sxyz90123
    for <engineers@example.org>; Sun, 27 Sep 2026 11:00:01 +0000
Authentication-Results: mx.example.org;
    spf=pass (example.org: domain of systems-team@example.com designates 203.0.113.10 as permitted sender) smtp.mailfrom=bounces@example.com;
    dkim=pass header.i=@example.com header.s=202609 header.b=XyZ789;
    dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com`
  }
};

export const ForensicWorkbench: React.FC = () => {
  const [subject, setSubject] = useState<string>(DEMO_FIXTURES.spearPhishing.subject);
  const [body, setBody] = useState<string>(DEMO_FIXTURES.spearPhishing.body);
  const [rawHeaders, setRawHeaders] = useState<string>(DEMO_FIXTURES.spearPhishing.rawHeaders);

  const [result, setResult] = useState<InvestigationResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'summary' | 'auth' | 'routing' | 'iocs' | 'evidence' | 'ai'>('summary');

  const handleAnalyze = async () => {
    if (!rawHeaders.trim()) {
      setError('Please provide raw RFC 822 email headers.');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const data = await analyzeInvestigation({
        subject: subject.trim() || undefined,
        body: body.trim() || '',
        raw_headers: rawHeaders.trim(),
      });
      setResult(data);
    } catch (err: any) {
      setError(err?.message || 'Email investigation request failed.');
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  // Check if email data was forwarded from the Chrome Extension via URL hash
  useEffect(() => {
    if (window.location.hash && window.location.hash.includes('import=')) {
      try {
        const hashContent = window.location.hash.split('import=')[1];
        if (hashContent) {
          const decoded = decodeURIComponent(hashContent);
          const imported = JSON.parse(decoded);
          if (imported.subject !== undefined) setSubject(imported.subject);
          if (imported.body !== undefined) setBody(imported.body);
          if (imported.rawHeaders !== undefined) setRawHeaders(imported.rawHeaders);
          if (imported.result) setResult(imported.result);
          setError(null);
          // Clean hash from address bar without page reload
          window.history.replaceState(null, '', window.location.pathname + window.location.search);
        }
      } catch (err) {
        console.error('Failed to parse imported email data from extension:', err);
      }
    }
  }, []);

  const loadFixture = (key: keyof typeof DEMO_FIXTURES) => {
    const fix = DEMO_FIXTURES[key];
    setSubject(fix.subject);
    setBody(fix.body);
    setRawHeaders(fix.rawHeaders);
    setError(null);
  };

  const clearWorkbench = () => {
    setSubject('');
    setBody('');
    setRawHeaders('');
    setResult(null);
    setError(null);
  };

  const handleDownloadReport = () => {
    if (!result) return;
    const jsonContent = JSON.stringify(result, null, 2);
    const blob = new Blob([jsonContent], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const downloadAnchor = document.createElement('a');
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    downloadAnchor.href = url;
    downloadAnchor.download = `forensic-report-${timestamp}.json`;
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    document.body.removeChild(downloadAnchor);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Page Title & Intro Card */}
      <div className="p-6 rounded-xl bg-[#121722] border border-[#1e2638] space-y-4 shadow-xl">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
              <FileSearch className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white tracking-tight">Threat Investigation Workbench</h1>
              <p className="text-xs text-gray-400">
                Unified email forensics, authentication verification, IOC extraction & AI threat model status audit
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="px-3 py-1 text-xs font-mono font-semibold rounded-md bg-blue-500/10 text-blue-400 border border-blue-500/20">
              POST /api/v1/investigation/analyze
            </span>
          </div>
        </div>

        {/* Demo Preset Fixtures */}
        <div className="pt-3 border-t border-[#1e2638] flex flex-wrap items-center gap-2 text-xs">
          <span className="text-gray-400 font-mono text-[11px] mr-1">Demo Scenarios:</span>
          <button
            onClick={() => loadFixture('spearPhishing')}
            className="px-3 py-1 rounded bg-[#1a2130] hover:bg-[#252f44] text-amber-300 font-mono border border-amber-500/30 transition-all flex items-center gap-1.5"
          >
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            <span>Spear Phishing</span>
          </button>
          <button
            onClick={() => loadFixture('becFraud')}
            className="px-3 py-1 rounded bg-[#1a2130] hover:bg-[#252f44] text-rose-300 font-mono border border-rose-500/30 transition-all flex items-center gap-1.5"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            <span>BEC Wire Fraud</span>
          </button>
          <button
            onClick={() => loadFixture('legitimateCorporate')}
            className="px-3 py-1 rounded bg-[#1a2130] hover:bg-[#252f44] text-emerald-300 font-mono border border-emerald-500/30 transition-all flex items-center gap-1.5"
          >
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>Legitimate Email</span>
          </button>
          <button
            onClick={clearWorkbench}
            className="px-3 py-1 rounded bg-[#1a2130] hover:bg-[#252f44] text-gray-300 hover:text-white font-mono border border-gray-600/30 transition-all flex items-center gap-1.5 ml-auto"
            title="Clear all fields to paste a custom email from your inbox"
          >
            <RotateCcw className="w-3.5 h-3.5 text-gray-400" />
            <span>Clear / Custom Email</span>
          </button>
        </div>
      </div>

      {/* Input Form Section */}
      <div className="p-6 rounded-xl bg-[#121722] border border-[#1e2638] space-y-4 shadow-xl">
        <div className="grid grid-cols-1 gap-4">
          {/* Subject Line */}
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-gray-300 font-mono mb-1.5">
              Email Subject Line
            </label>
            <input
              type="text"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              placeholder="e.g. Urgent Invoice Payment Required"
              className="w-full px-3.5 py-2.5 rounded-lg bg-[#0a0d14] border border-[#1e2638] font-mono text-xs text-gray-200 focus:outline-none focus:border-blue-500 transition-colors"
            />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Raw Headers */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold uppercase tracking-wider text-gray-300 font-mono">
                  Raw RFC 822 Email Headers <span className="text-rose-400">*</span>
                </label>
                <span className="text-[10px] text-gray-500 font-mono">Max size: 500 KB</span>
              </div>
              <textarea
                rows={8}
                value={rawHeaders}
                onChange={(e) => setRawHeaders(e.target.value)}
                placeholder="Paste RFC 822 email headers here (From, To, Received, Authentication-Results)..."
                className="w-full p-3 rounded-lg bg-[#0a0d14] border border-[#1e2638] font-mono text-xs text-gray-200 focus:outline-none focus:border-blue-500 transition-colors resize-y selection:bg-blue-500/30"
              />
            </div>

            {/* Email Body */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold uppercase tracking-wider text-gray-300 font-mono">
                  Email Body Content (Optional)
                </label>
                <span className="text-[10px] text-gray-500 font-mono">IOC URL/IP extraction</span>
              </div>
              <textarea
                rows={8}
                value={body}
                onChange={(e) => setBody(e.target.value)}
                placeholder="Paste plain email body text for URL, domain, and entity extraction..."
                className="w-full p-3 rounded-lg bg-[#0a0d14] border border-[#1e2638] font-mono text-xs text-gray-200 focus:outline-none focus:border-blue-500 transition-colors resize-y selection:bg-blue-500/30"
              />
            </div>
          </div>
        </div>

        {/* Action bar */}
        <div className="flex flex-wrap items-center justify-between pt-2 border-t border-[#1e2638] gap-3">
          {error ? (
            <div className="flex items-center gap-2 text-xs text-rose-400 font-mono bg-rose-500/10 border border-rose-500/20 px-3 py-1.5 rounded-lg">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          ) : (
            <div className="text-[11px] text-gray-400 font-mono flex items-center gap-1.5">
              <Info className="w-3.5 h-3.5 text-blue-400" />
              <span>Factual forensic signal analysis • Zero external telemetry leakage</span>
            </div>
          )}

          <button
            onClick={handleAnalyze}
            disabled={loading}
            className="px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-medium text-xs flex items-center gap-2 shadow-lg shadow-blue-600/20 transition-all font-mono"
          >
            {loading ? (
              <>
                <Cpu className="w-4 h-4 animate-spin text-white" />
                <span>Running Investigation...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current text-white" />
                <span>Analyze Email</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Investigation Results Section */}
      {result && (
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-6"
        >
          {/* Quick Stats Banner */}
          <div className="p-4 rounded-xl bg-[#121722] border border-[#1e2638] flex flex-wrap items-center justify-between gap-4 shadow-lg">
            <div className="space-y-1">
              <div className="text-[10px] font-mono uppercase text-gray-400">Investigation UUID</div>
              <div className="font-mono text-xs text-blue-400 font-semibold">{result.analysis_id}</div>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <div className="px-3 py-1.5 rounded-lg bg-[#0a0d14] border border-[#1e2638] text-center">
                <div className="text-[9px] text-gray-500 font-mono uppercase">Forensic Status</div>
                <div className="text-xs font-mono text-emerald-400 font-bold uppercase">{result.status}</div>
              </div>
              <div className="px-3 py-1.5 rounded-lg bg-[#0a0d14] border border-[#1e2638] text-center">
                <div className="text-[9px] text-gray-500 font-mono uppercase">AI Threat Engine</div>
                <div className={`text-xs font-mono font-bold uppercase ${
                  result.threat_analysis.model_available ? 'text-emerald-400' : 'text-amber-400'
                }`}>
                  {result.threat_analysis.status}
                </div>
              </div>
              <div className="px-3 py-1.5 rounded-lg bg-[#0a0d14] border border-[#1e2638] text-center">
                <div className="text-[9px] text-gray-500 font-mono uppercase">Evidence Items</div>
                <div className="text-xs font-mono text-cyan-400 font-bold">{result.evidence.length}</div>
              </div>
              <div className="px-3 py-1.5 rounded-lg bg-[#0a0d14] border border-[#1e2638] text-center">
                <div className="text-[9px] text-gray-500 font-mono uppercase">Extracted IOCs</div>
                <div className="text-xs font-mono text-indigo-400 font-bold">
                  {result.indicators.ip_addresses.length + result.indicators.domains.length + result.indicators.urls.length}
                </div>
              </div>
              <button
                onClick={handleDownloadReport}
                className="px-3.5 py-1.5 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 border border-emerald-500/40 text-emerald-400 hover:text-emerald-300 font-mono text-xs font-semibold flex items-center gap-2 transition-all shadow-sm cursor-pointer"
                title="Download complete forensic analysis as formatted JSON"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download Forensic JSON Report</span>
              </button>
            </div>
          </div>

          {/* Navigation Tabs */}
          <div className="flex flex-wrap gap-2 border-b border-[#1e2638] pb-2">
            {[
              { id: 'summary', label: 'Summary', icon: Layers },
              { id: 'auth', label: 'Authentication', icon: Fingerprint },
              { id: 'routing', label: 'Email Routing', icon: Server },
              { id: 'iocs', label: 'Indicators (IOCs)', icon: Globe },
              { id: 'evidence', label: 'Forensic Evidence', icon: ShieldAlert },
              { id: 'ai', label: 'AI Threat Analysis', icon: Cpu },
            ].map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`px-4 py-2 rounded-lg font-mono text-xs flex items-center gap-2 transition-all ${
                    isActive
                      ? 'bg-blue-600 text-white font-bold shadow-md shadow-blue-600/20'
                      : 'bg-[#121722] text-gray-400 hover:text-gray-200 hover:bg-[#1a2130]'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>

          {/* TAB 1: SUMMARY */}
          {activeTab === 'summary' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Routing Overview */}
                <div className="p-5 rounded-xl bg-[#121722] border border-[#1e2638] space-y-3">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-gray-300 font-mono flex items-center gap-2">
                    <Server className="w-4 h-4 text-blue-400" />
                    Routing Summary
                  </h3>
                  <div className="space-y-2 font-mono text-xs">
                    <div className="flex justify-between py-1 border-b border-[#1e2638]/60">
                      <span className="text-gray-400">Sender:</span>
                      <span className="text-gray-200 font-semibold">{result.routing.sender || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-[#1e2638]/60">
                      <span className="text-gray-400">Sender Domain:</span>
                      <span className="text-blue-400 font-semibold">{result.routing.sender_domain || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-[#1e2638]/60">
                      <span className="text-gray-400">Reply-To:</span>
                      <span className="text-gray-200">{result.routing.reply_to || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-[#1e2638]/60">
                      <span className="text-gray-400">Return-Path:</span>
                      <span className="text-gray-200">{result.routing.return_path || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between py-1">
                      <span className="text-gray-400">Received Hops:</span>
                      <span className="text-cyan-400 font-bold">{result.routing.received_hops.length}</span>
                    </div>
                  </div>
                </div>

                {/* Authentication Overview */}
                <div className="p-5 rounded-xl bg-[#121722] border border-[#1e2638] space-y-3">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-gray-300 font-mono flex items-center gap-2">
                    <Fingerprint className="w-4 h-4 text-emerald-400" />
                    Authentication Results
                  </h3>
                  <div className="grid grid-cols-3 gap-3 pt-2">
                    <div className="p-3 rounded-lg bg-[#0a0d14] border border-[#1e2638] text-center">
                      <div className="text-[10px] text-gray-400 font-mono uppercase">SPF</div>
                      <div className={`text-sm font-mono font-bold uppercase mt-1 ${
                        result.authentication.spf.status === 'pass'
                          ? 'text-emerald-400'
                          : result.authentication.spf.status === 'fail'
                          ? 'text-rose-400'
                          : 'text-amber-400'
                      }`}>
                        {result.authentication.spf.status}
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-[#0a0d14] border border-[#1e2638] text-center">
                      <div className="text-[10px] text-gray-400 font-mono uppercase">DKIM</div>
                      <div className={`text-sm font-mono font-bold uppercase mt-1 ${
                        result.authentication.dkim.status === 'pass'
                          ? 'text-emerald-400'
                          : result.authentication.dkim.status === 'fail'
                          ? 'text-rose-400'
                          : 'text-amber-400'
                      }`}>
                        {result.authentication.dkim.status}
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-[#0a0d14] border border-[#1e2638] text-center">
                      <div className="text-[10px] text-gray-400 font-mono uppercase">DMARC</div>
                      <div className={`text-sm font-mono font-bold uppercase mt-1 ${
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
              </div>

              {/* Suspicious Header Indicators List */}
              {result.indicators.suspicious_header_indicators.length > 0 && (
                <div className="p-5 rounded-xl bg-[#121722] border border-amber-500/20 space-y-3">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-amber-400 font-mono flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4" />
                    Suspicious Indicators Detected ({result.indicators.suspicious_header_indicators.length})
                  </h3>
                  <div className="space-y-2">
                    {result.indicators.suspicious_header_indicators.map((ind, i) => (
                      <div key={i} className="p-2.5 rounded-lg bg-[#0a0d14] border border-[#1e2638] text-xs font-mono text-gray-300 flex items-start gap-2">
                        <span className="text-amber-400 shrink-0 font-bold">•</span>
                        <span>{ind}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: AUTHENTICATION */}
          {activeTab === 'auth' && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* SPF */}
              <div className="p-5 rounded-xl bg-[#121722] border border-[#1e2638] space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="font-mono text-xs font-bold text-gray-200">SPF Verification</h4>
                  <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold uppercase ${
                    result.authentication.spf.status === 'pass'
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                      : result.authentication.spf.status === 'fail'
                      ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                      : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                  }`}>
                    {result.authentication.spf.status}
                  </span>
                </div>
                <div className="space-y-1.5 text-xs font-mono text-gray-400">
                  <div>Source: <span className="text-gray-200">{result.authentication.spf.source || 'N/A'}</span></div>
                  <div>Verified: <span className="text-gray-200">{result.authentication.spf.verification_performed ? 'Yes' : 'Parsed from header'}</span></div>
                  {result.authentication.spf.raw_details && (
                    <div className="p-2 rounded bg-[#0a0d14] text-[11px] text-gray-400 font-mono break-all mt-2">
                      {result.authentication.spf.raw_details}
                    </div>
                  )}
                </div>
              </div>

              {/* DKIM */}
              <div className="p-5 rounded-xl bg-[#121722] border border-[#1e2638] space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="font-mono text-xs font-bold text-gray-200">DKIM Verification</h4>
                  <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold uppercase ${
                    result.authentication.dkim.status === 'pass'
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                      : result.authentication.dkim.status === 'fail'
                      ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                      : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                  }`}>
                    {result.authentication.dkim.status}
                  </span>
                </div>
                <div className="space-y-1.5 text-xs font-mono text-gray-400">
                  <div>Signature Header: <span className="text-gray-200">{result.authentication.dkim.signature_present ? 'Present' : 'Not detected'}</span></div>
                  <div>Verified: <span className="text-gray-200">{result.authentication.dkim.verification_performed ? 'Yes' : 'Parsed from header'}</span></div>
                  {result.authentication.dkim.raw_details && (
                    <div className="p-2 rounded bg-[#0a0d14] text-[11px] text-gray-400 font-mono break-all mt-2">
                      {result.authentication.dkim.raw_details}
                    </div>
                  )}
                </div>
              </div>

              {/* DMARC */}
              <div className="p-5 rounded-xl bg-[#121722] border border-[#1e2638] space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="font-mono text-xs font-bold text-gray-200">DMARC Policy</h4>
                  <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold uppercase ${
                    result.authentication.dmarc.status === 'pass'
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                      : result.authentication.dmarc.status === 'fail'
                      ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                      : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                  }`}>
                    {result.authentication.dmarc.status}
                  </span>
                </div>
                <div className="space-y-1.5 text-xs font-mono text-gray-400">
                  <div>Source: <span className="text-gray-200">{result.authentication.dmarc.source || 'N/A'}</span></div>
                  <div>Policy Action: <span className="text-gray-200">{result.authentication.dmarc.status}</span></div>
                  {result.authentication.dmarc.raw_details && (
                    <div className="p-2 rounded bg-[#0a0d14] text-[11px] text-gray-400 font-mono break-all mt-2">
                      {result.authentication.dmarc.raw_details}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: EMAIL ROUTING */}
          {activeTab === 'routing' && (
            <div className="p-5 rounded-xl bg-[#121722] border border-[#1e2638] space-y-4">
              <h3 className="text-xs font-bold uppercase tracking-wider text-gray-300 font-mono flex items-center gap-2">
                <Server className="w-4 h-4 text-blue-400" />
                Received Hop Routing Chain ({result.routing.received_hops.length})
              </h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead>
                    <tr className="border-b border-[#1e2638] text-gray-400">
                      <th className="py-2.5 px-3">Hop</th>
                      <th className="py-2.5 px-3">From Host</th>
                      <th className="py-2.5 px-3">Source IP</th>
                      <th className="py-2.5 px-3">By Host</th>
                      <th className="py-2.5 px-3">Protocol</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.routing.received_hops.map((hop) => (
                      <tr key={hop.hop_index} className="border-b border-[#1e2638]/50 hover:bg-[#1a2130]">
                        <td className="py-2.5 px-3 text-blue-400 font-bold">#{hop.hop_index}</td>
                        <td className="py-2.5 px-3 text-gray-300">{hop.from_host || 'N/A'}</td>
                        <td className="py-2.5 px-3 text-emerald-400 font-bold">{hop.source_ip || 'N/A'}</td>
                        <td className="py-2.5 px-3 text-gray-300">{hop.by_host || 'N/A'}</td>
                        <td className="py-2.5 px-3 text-gray-400">{hop.with_protocol || 'N/A'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 4: INDICATORS (IOCs) */}
          {activeTab === 'iocs' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* IP Addresses */}
              <div className="p-5 rounded-xl bg-[#121722] border border-[#1e2638] space-y-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-gray-300 font-mono flex items-center justify-between">
                  <span>IP Addresses ({result.indicators.ip_addresses.length})</span>
                  <span className="text-[10px] text-gray-500 font-normal">Validated IPv4/IPv6</span>
                </h4>
                <div className="space-y-1.5 max-h-60 overflow-y-auto pr-1">
                  {result.indicators.ip_addresses.length === 0 ? (
                    <div className="text-xs text-gray-500 font-mono py-2">No IP indicators extracted.</div>
                  ) : (
                    result.indicators.ip_addresses.map((ip, i) => (
                      <div key={i} className="p-2 rounded bg-[#0a0d14] border border-[#1e2638] text-xs font-mono flex items-center justify-between">
                        <span className="text-emerald-400 font-bold">{ip.value}</span>
                        <span className="text-[10px] text-gray-500">{ip.source}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Domains */}
              <div className="p-5 rounded-xl bg-[#121722] border border-[#1e2638] space-y-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-gray-300 font-mono flex items-center justify-between">
                  <span>Domains ({result.indicators.domains.length})</span>
                  <span className="text-[10px] text-gray-500 font-normal">Normalized Netlocs</span>
                </h4>
                <div className="space-y-1.5 max-h-60 overflow-y-auto pr-1">
                  {result.indicators.domains.length === 0 ? (
                    <div className="text-xs text-gray-500 font-mono py-2">No domain indicators extracted.</div>
                  ) : (
                    result.indicators.domains.map((dom, i) => (
                      <div key={i} className="p-2 rounded bg-[#0a0d14] border border-[#1e2638] text-xs font-mono flex items-center justify-between">
                        <span className="text-blue-400 font-bold">{dom.value}</span>
                        <span className="text-[10px] text-gray-500">{dom.source}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* URLs */}
              <div className="p-5 rounded-xl bg-[#121722] border border-[#1e2638] space-y-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-gray-300 font-mono flex items-center justify-between">
                  <span>URLs ({result.indicators.urls.length})</span>
                  <span className="text-[10px] text-gray-500 font-normal">Zero-network extraction</span>
                </h4>
                <div className="space-y-1.5 max-h-60 overflow-y-auto pr-1">
                  {result.indicators.urls.length === 0 ? (
                    <div className="text-xs text-gray-500 font-mono py-2">No URLs discovered in payload.</div>
                  ) : (
                    result.indicators.urls.map((u, i) => (
                      <div key={i} className="p-2 rounded bg-[#0a0d14] border border-[#1e2638] text-xs font-mono space-y-1">
                        <div className="text-cyan-400 break-all">{u.value}</div>
                        <div className="text-[10px] text-gray-500">{u.source}</div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Email Addresses */}
              <div className="p-5 rounded-xl bg-[#121722] border border-[#1e2638] space-y-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-gray-300 font-mono flex items-center justify-between">
                  <span>Email Addresses ({result.indicators.email_addresses.length})</span>
                  <span className="text-[10px] text-gray-500 font-normal">Extracted Entities</span>
                </h4>
                <div className="space-y-1.5 max-h-60 overflow-y-auto pr-1">
                  {result.indicators.email_addresses.length === 0 ? (
                    <div className="text-xs text-gray-500 font-mono py-2">No email addresses discovered.</div>
                  ) : (
                    result.indicators.email_addresses.map((em, i) => (
                      <div key={i} className="p-2 rounded bg-[#0a0d14] border border-[#1e2638] text-xs font-mono flex items-center justify-between">
                        <span className="text-indigo-400">{em.value}</span>
                        <span className="text-[10px] text-gray-500">{em.source}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: FORENSIC EVIDENCE */}
          {activeTab === 'evidence' && (
            <div className="space-y-3">
              {result.evidence.map((ev) => (
                <div
                  key={ev.evidence_id}
                  className="p-4 rounded-xl bg-[#121722] border border-[#1e2638] space-y-2 hover:border-gray-700 transition-colors"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                        ev.severity === 'high'
                          ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                          : ev.severity === 'medium'
                          ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                          : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                      }`}>
                        {ev.severity}
                      </span>
                      <span className="font-mono text-xs font-bold text-gray-200">{ev.title}</span>
                    </div>
                    <span className="text-[10px] font-mono text-gray-500">{ev.evidence_id}</span>
                  </div>

                  <p className="text-xs text-gray-300 font-mono">{ev.description}</p>

                  <div className="flex flex-wrap items-center justify-between text-[11px] font-mono text-gray-400 pt-2 border-t border-[#1e2638]/50">
                    <span>Source: <span className="text-gray-300">{ev.source}</span></span>
                    {ev.observed_value && (
                      <span className="text-gray-400">
                        Observed: <code className="text-blue-300 bg-[#0a0d14] px-1 py-0.5 rounded">{ev.observed_value}</code>
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* TAB 6: AI THREAT ANALYSIS */}
          {activeTab === 'ai' && (
            <div className="p-6 rounded-xl bg-[#121722] border border-[#1e2638] space-y-6 shadow-xl">
              <div className="flex items-center justify-between border-b border-[#1e2638] pb-4">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
                    <Cpu className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-white font-mono">RoBERTa Threat Classifier Engine</h3>
                    <p className="text-xs text-gray-400 font-mono">4-Class Sequence Classification (Benign, Suspicious, Phishing, BEC)</p>
                  </div>
                </div>
                <div className="px-3 py-1 rounded-md text-xs font-mono font-bold uppercase bg-[#0a0d14] border border-[#1e2638] text-gray-300">
                  Device: {result.threat_analysis.device_used}
                </div>
              </div>

              {/* Status Display: Real Model vs Unavailable */}
              {result.threat_analysis.model_available ? (
                <div className="space-y-4">
                  <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-between">
                    <div>
                      <div className="text-xs font-mono text-emerald-400 uppercase font-semibold">Predicted Threat Class</div>
                      <div className="text-lg font-mono font-bold text-white uppercase mt-0.5">
                        {result.threat_analysis.primary_label}
                      </div>
                    </div>
                    {result.threat_analysis.confidence !== undefined && (
                      <div className="text-right">
                        <div className="text-xs font-mono text-emerald-400 uppercase font-semibold">Model Confidence</div>
                        <div className="text-lg font-mono font-bold text-emerald-300">
                          {(result.threat_analysis.confidence * 100).toFixed(1)}%
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Probabilities Breakdown */}
                  {Object.keys(result.threat_analysis.probabilities).length > 0 && (
                    <div className="space-y-2 pt-2">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-gray-300 font-mono">
                        Class Probabilities Distribution
                      </h4>
                      <div className="space-y-2">
                        {Object.entries(result.threat_analysis.probabilities).map(([cName, pVal]) => (
                          <div key={cName} className="space-y-1">
                            <div className="flex justify-between text-xs font-mono">
                              <span className="text-gray-300 uppercase">{cName}</span>
                              <span className="text-blue-400 font-bold">{(pVal * 100).toFixed(1)}%</span>
                            </div>
                            <div className="w-full h-1.5 rounded-full bg-[#0a0d14] overflow-hidden">
                              <div
                                className="h-full bg-blue-500 rounded-full"
                                style={{ width: `${Math.min(pVal * 100, 100)}%` }}
                              />
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                /* Explicit Model Unavailable Banner Per Step 7 */
                <div className="p-5 rounded-xl bg-amber-500/10 border border-amber-500/30 space-y-3">
                  <div className="flex items-center gap-2.5 text-amber-400 font-mono font-bold text-sm">
                    <ShieldX className="w-5 h-5 shrink-0" />
                    <span>AI model unavailable</span>
                  </div>
                  <div className="text-xs text-gray-300 font-mono space-y-1">
                    <p>No ML prediction was generated.</p>
                    <p className="text-gray-400">
                      Configure a trained MAILTRACE model to enable AI classification.
                    </p>
                  </div>
                  <div className="pt-2 border-t border-amber-500/20 text-[11px] font-mono text-gray-400">
                    Engine status details: <span className="text-amber-300">{result.threat_analysis.details}</span>
                  </div>
                </div>
              )}
            </div>
          )}
        </motion.div>
      )}
    </div>
  );
};
