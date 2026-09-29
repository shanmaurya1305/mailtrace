import React from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, FileSearch, Settings, Database, Cpu, Layers } from 'lucide-react';

export const Navigation: React.FC = () => {
  const navItems = [
    { to: '/', label: 'Overview', icon: LayoutDashboard },
    { to: '/investigation', label: 'Forensic Workbench', icon: FileSearch },
    { to: '/settings', label: 'Platform Config', icon: Settings },
  ];

  const systemModules = [
    { label: 'FastAPI Service', status: 'ACTIVE', icon: Layers },
    { label: 'Header Forensics Engine', status: 'ACTIVE', icon: FileSearch },
    { label: 'RoBERTa Threat Engine', status: 'PHASE 2', icon: Cpu },
    { label: 'PostgreSQL DB', status: 'FOUNDATION READY', icon: Database },
  ];

  return (
    <aside className="w-64 border-r border-[#1e2638] bg-[#0c1018] p-4 flex flex-col justify-between shrink-0">
      <div className="space-y-6">
        <div>
          <h2 className="px-3 text-[10px] font-mono font-semibold uppercase tracking-wider text-gray-500 mb-2">
            Navigation Shell
          </h2>
          <nav className="space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) =>
                    `flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-all ${
                      isActive
                        ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30'
                        : 'text-gray-400 hover:text-white hover:bg-[#151c2a]'
                    }`
                  }
                >
                  <Icon className="w-4 h-4" />
                  <span>{item.label}</span>
                </NavLink>
              );
            })}
          </nav>
        </div>

        <div>
          <h2 className="px-3 text-[10px] font-mono font-semibold uppercase tracking-wider text-gray-500 mb-2">
            Architecture Modules
          </h2>
          <div className="space-y-2 px-1">
            {systemModules.map((mod, idx) => {
              const Icon = mod.icon;
              return (
                <div key={idx} className="flex items-center justify-between p-2.5 rounded-md bg-[#121722] border border-[#1e2638] text-xs">
                  <div className="flex items-center gap-2 text-gray-300">
                    <Icon className="w-3.5 h-3.5 text-blue-400" />
                    <span>{mod.label}</span>
                  </div>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20">
                    {mod.status}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div className="p-3 rounded-lg bg-[#121722] border border-[#1e2638] text-xs text-gray-400 space-y-1 font-mono">
        <div className="text-[10px] text-gray-500 uppercase font-semibold">Environment Base</div>
        <div className="truncate text-blue-400 font-semibold">{import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'}</div>
      </div>
    </aside>
  );
};
