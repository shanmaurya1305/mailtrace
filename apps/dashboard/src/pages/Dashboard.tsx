import React from 'react';
import { motion } from 'framer-motion';
import { Server, ShieldCheck, AlertCircle, CheckCircle2, RefreshCw, Code2, Cpu } from 'lucide-react';
import { HealthCheckResponse } from '../../../../shared/types';
import { API_BASE_URL } from '../services/api';

interface DashboardOverviewProps {
  health: HealthCheckResponse | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
}

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({
  health,
  loading,
  error,
  onRefresh,
}) => {
  const isConnected = !!health && health.status === 'ok';

  return (
    <div className="space-y-6">
      {/* Hero Banner */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="p-6 rounded-xl bg-gradient-to-r from-blue-950/40 via-[#121722] to-[#121722] border border-blue-500/20 relative overflow-hidden"
      >
        <div className="max-w-3xl relative z-10 space-y-2">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-xs text-blue-400 font-mono font-medium">
            <ShieldCheck className="w-3.5 h-3.5" />
            Phase 1 Foundation Complete
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            MAILTRACE 2.0
          </h1>
          <p className="text-sm text-gray-300 leading-relaxed">
            AI-Powered Email Forensics & Threat Intelligence Platform. Active email header parser, Received routing chain analyzer, SPF/DKIM/DMARC authentication evaluator, and deterministic evidence engine.
          </p>
        </div>
      </motion.div>

      {/* Backend API Connection Status Card */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="p-5 rounded-xl bg-[#121722] border border-[#1e2638] space-y-4"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm font-semibold text-white">
              <Server className="w-4 h-4 text-blue-400" />
              <span>FastAPI Service Health</span>
            </div>
            <button
              onClick={onRefresh}
              disabled={loading}
              className="p-1.5 rounded-lg bg-[#1a2130] hover:bg-[#232c3f] text-gray-400 hover:text-white transition-colors disabled:opacity-50"
              title="Re-check health"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>

          <div className="p-4 rounded-lg bg-[#0a0d14] border border-[#1b2233] space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs text-gray-400 font-mono">Configured Target URL:</span>
              <span className="text-xs text-blue-400 font-mono font-semibold">{API_BASE_URL}</span>
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-[#1e2638]">
              <span className="text-xs text-gray-400 font-mono">Connection Status:</span>
              {loading ? (
                <span className="inline-flex items-center gap-1.5 text-xs text-blue-400 font-mono">
                  <RefreshCw className="w-3 h-3 animate-spin" /> Checking endpoint...
                </span>
              ) : isConnected ? (
                <span className="inline-flex items-center gap-1.5 text-xs text-emerald-400 font-mono font-semibold px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20">
                  <CheckCircle2 className="w-3.5 h-3.5" /> Connected ({health?.service})
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 text-xs text-amber-400 font-mono font-semibold px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/20">
                  <AlertCircle className="w-3.5 h-3.5" /> API connection pending
                </span>
              )}
            </div>

            {error && !isConnected && (
              <div className="text-xs text-rose-400 font-mono pt-1">
                Notice: Start backend service using <code className="bg-[#151c2a] px-1 py-0.5 rounded text-rose-300">uvicorn main:app --reload</code>
              </div>
            )}
          </div>
        </motion.div>

        {/* Project Architecture & Status Card */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="p-5 rounded-xl bg-[#121722] border border-[#1e2638] space-y-4"
        >
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span>Platform Status & Phase Roadmap</span>
          </div>

          <div className="space-y-2 text-xs font-mono">
            <div className="flex items-center justify-between p-2 rounded bg-[#0a0d14] border border-[#1b2233]">
              <span className="text-gray-400">Phase 0: Monorepo Foundation</span>
              <span className="text-emerald-400 font-bold">COMPLETED</span>
            </div>
            <div className="flex items-center justify-between p-2 rounded bg-[#0a0d14] border border-[#1b2233]">
              <span className="text-gray-400">Phase 1: Header Forensics & Evidence</span>
              <span className="text-emerald-400 font-bold">COMPLETED</span>
            </div>
            <div className="flex items-center justify-between p-2 rounded bg-[#0a0d14] border border-[#1b2233]">
              <span className="text-gray-400">Phase 2: RoBERTa AI Threat Classifier</span>
              <span className="text-cyan-400 font-bold">NEXT</span>
            </div>
            <div className="flex items-center justify-between p-2 rounded bg-[#0a0d14] border border-[#1b2233]">
              <span className="text-gray-400">Phase 3: Extension Webmail Ingestion</span>
              <span className="text-gray-500">PLANNED</span>
            </div>
            <div className="flex items-center justify-between p-2 rounded bg-[#0a0d14] border border-[#1b2233]">
              <span className="text-gray-400">Phase 4: VirusTotal & MaxMind Intelligence</span>
              <span className="text-gray-500">PLANNED</span>
            </div>
            <div className="flex items-center justify-between p-2 rounded bg-[#0a0d14] border border-[#1b2233]">
              <span className="text-gray-400">Phase 5: Case Management & Reports</span>
              <span className="text-gray-500">PLANNED</span>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Security Principles & Design Guarantee */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="p-5 rounded-xl bg-[#121722] border border-[#1e2638] space-y-3"
      >
        <div className="flex items-center gap-2 text-sm font-semibold text-white">
          <Code2 className="w-4 h-4 text-blue-400" />
          <span>Security & Engineering Principles</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs text-gray-300">
          <div className="p-3 rounded-lg bg-[#0a0d14] border border-[#1b2233]">
            <div className="font-semibold text-blue-400 mb-1">Untrusted Input Handling</div>
            <p className="text-gray-400">Email bodies & headers parsed safely with sanitization. No eval() or unsafe dynamic HTML.</p>
          </div>
          <div className="p-3 rounded-lg bg-[#0a0d14] border border-[#1b2233]">
            <div className="font-semibold text-cyan-400 mb-1">Decoupled API Base</div>
            <p className="text-gray-400">Target API URL provided dynamically via <code className="text-cyan-300 font-mono">import.meta.env.VITE_API_BASE_URL</code>.</p>
          </div>
          <div className="p-3 rounded-lg bg-[#0a0d14] border border-[#1b2233]">
            <div className="font-semibold text-emerald-400 mb-1">Real Data Integrity</div>
            <p className="text-gray-400">No mock security threat scores or synthetic intelligence metrics generated.</p>
          </div>
        </div>
      </motion.div>
    </div>
  );
};
