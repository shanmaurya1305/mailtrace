import React from 'react';
import { Settings as SettingsIcon, Globe, Database, Key } from 'lucide-react';
import { API_BASE_URL } from '../services/api';

export const PlatformSettings: React.FC = () => {
  return (
    <div className="space-y-6">
      <div className="p-6 rounded-xl bg-[#121722] border border-[#1e2638] space-y-6">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
            <SettingsIcon className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white">Platform Settings & Environment Configuration</h2>
            <p className="text-xs text-gray-400">Decoupled configuration parameters for cloud and local environments</p>
          </div>
        </div>

        <div className="space-y-4">
          <div className="p-4 rounded-lg bg-[#0a0d14] border border-[#1b2233] space-y-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-white">
              <Globe className="w-4 h-4 text-cyan-400" />
              <span>Vite API Base Endpoint</span>
            </div>
            <div className="text-xs font-mono text-gray-300">
              Variable: <code className="text-cyan-300">VITE_API_BASE_URL</code>
            </div>
            <div className="p-2.5 rounded bg-[#121722] border border-[#1e2638] font-mono text-xs text-emerald-400 font-semibold">
              {API_BASE_URL}
            </div>
          </div>

          <div className="p-4 rounded-lg bg-[#0a0d14] border border-[#1b2233] space-y-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-white">
              <Database className="w-4 h-4 text-blue-400" />
              <span>PostgreSQL Container target</span>
            </div>
            <div className="text-xs font-mono text-gray-300">
              Host: <code className="text-blue-300">localhost:5432</code> | DB: <code className="text-blue-300">mailtrace_db</code>
            </div>
          </div>

          <div className="p-4 rounded-lg bg-[#0a0d14] border border-[#1b2233] space-y-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-white">
              <Key className="w-4 h-4 text-amber-400" />
              <span>Future Threat Intelligence Keys</span>
            </div>
            <div className="text-xs text-gray-400">
              VirusTotal, MaxMind GeoIP, OpenAI, and Gemini key placeholders registered in root <code className="text-amber-300 font-mono">.env.example</code>. No secrets stored in frontend bundles.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
