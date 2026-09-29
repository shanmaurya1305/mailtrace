import React from 'react';
import { Shield, Radio, Terminal } from 'lucide-react';

interface HeaderProps {
  apiStatus: 'connected' | 'pending' | 'checking';
  serviceName?: string;
}

export const Header: React.FC<HeaderProps> = ({ apiStatus, serviceName }) => {
  return (
    <header className="h-16 border-b border-[#1e2638] bg-[#0d121c]/80 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-50">
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg bg-blue-600/10 border border-blue-500/20 text-blue-400">
          <Shield className="w-6 h-6" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="font-bold text-lg tracking-wider text-white">MAILTRACE</h1>
            <span className="px-2 py-0.5 text-[10px] font-mono font-semibold rounded bg-blue-500/10 text-blue-400 border border-blue-500/30">
              v2.0 — Phase 1 Complete
            </span>
          </div>
          <p className="text-xs text-gray-400">AI-Powered Email Forensics & Threat Intelligence Platform</p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        {/* Backend API status badge */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#121722] border border-[#1e2638] text-xs font-mono">
          <Radio className={`w-3.5 h-3.5 ${
            apiStatus === 'connected' ? 'text-emerald-400 animate-pulse' : 'text-amber-400'
          }`} />
          <span className="text-gray-400">API Status:</span>
          {apiStatus === 'connected' ? (
            <span className="text-emerald-400 font-medium">
              Connected ({serviceName || 'mailtrace-api'})
            </span>
          ) : (
            <span className="text-amber-400 font-medium">
              API connection pending
            </span>
          )}
        </div>

        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#121722] border border-[#1e2638] text-xs text-gray-400 font-mono">
          <Terminal className="w-3.5 h-3.5 text-blue-400" />
          <span>Monorepo Architecture</span>
        </div>
      </div>
    </header>
  );
};
