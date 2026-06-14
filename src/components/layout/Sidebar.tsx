import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Bell,
  ShieldAlert,
  Grid3x3,
  FileText,
  Upload,
  ScrollText,
  Shield,
  Brain,
  Globe,
  Play,
} from 'lucide-react';

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/alerts', icon: Bell, label: 'Alert Queue' },
  { to: '/incidents', icon: ShieldAlert, label: 'Incidents' },
  { to: '/ai-assistant', icon: Brain, label: 'AI Assistant' },
  { to: '/mitre', icon: Grid3x3, label: 'MITRE ATT&CK' },
  { to: '/threat-intel', icon: Globe, label: 'Threat Intel' },
  { to: '/playbooks', icon: Play, label: 'Playbooks' },
  { to: '/reports', icon: FileText, label: 'Reports' },
  { to: '/upload', icon: Upload, label: 'Log Upload' },
  { to: '/audit', icon: ScrollText, label: 'Audit Log' },
];

export function Sidebar() {
  return (
    <aside className="flex w-64 flex-col border-r border-slate-800 bg-slate-900">
      <div className="flex h-16 items-center gap-3 border-b border-slate-800 px-6">
        <Shield className="h-8 w-8 text-cyan-400" />
        <div>
          <h1 className="text-lg font-bold text-white tracking-tight">SOC Shield</h1>
          <p className="text-[10px] font-medium uppercase tracking-widest text-cyan-400/70">AI Operations Center</p>
        </div>
      </div>

      <nav className="flex-1 space-y-1 px-3 py-4 overflow-y-auto">
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all duration-200 ${
                isActive
                  ? 'bg-cyan-500/15 text-cyan-400 shadow-sm shadow-cyan-500/5'
                  : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
              }`
            }
          >
            <Icon className="h-4 w-4" />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-slate-800 p-4 space-y-3">
        <div className="rounded-lg bg-gradient-to-br from-blue-500/10 to-cyan-500/10 p-3 border border-blue-500/20">
          <div className="flex items-center gap-2">
            <Brain className="h-4 w-4 text-blue-400" />
            <span className="text-[10px] font-bold text-blue-400">Powered by Foundry IQ</span>
          </div>
          <p className="mt-1 text-[10px] text-slate-500">Reasoning Layer Active</p>
        </div>
        <div className="rounded-lg bg-gradient-to-br from-cyan-500/10 to-blue-500/10 p-3 border border-cyan-500/20">
          <div className="flex items-center gap-2">
            <div className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-xs font-medium text-emerald-400">System Online</span>
          </div>
          <p className="mt-1 text-[10px] text-slate-500">All agents operational</p>
        </div>
      </div>
    </aside>
  );
}
