import { Bell, Search, Shield, Brain } from 'lucide-react';

export function TopBar() {
  return (
    <header className="flex h-16 items-center justify-between border-b border-slate-800 bg-slate-900/80 backdrop-blur-sm px-6">
      <div className="flex items-center gap-4 flex-1">
        <div className="relative max-w-md w-full">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search alerts, incidents, IOCs..."
            className="w-full rounded-lg border border-slate-700 bg-slate-800/50 py-2 pl-10 pr-4 text-sm text-slate-200 placeholder-slate-500 outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/30 transition-colors"
          />
        </div>
      </div>

      <div className="flex items-center gap-3">
        {/* Microsoft Foundry IQ Badge */}
        <div className="flex items-center gap-2 rounded-lg border border-blue-500/30 bg-gradient-to-r from-blue-500/10 to-cyan-500/10 px-3 py-1.5">
          <Brain className="h-4 w-4 text-blue-400" />
          <div className="text-xs">
            <p className="font-semibold text-blue-400">Foundry IQ</p>
            <p className="text-[9px] text-slate-500">Reasoning Layer</p>
          </div>
        </div>

        <button className="relative rounded-lg p-2 text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition-colors">
          <Bell className="h-5 w-5" />
          <span className="absolute right-1 top-1 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[10px] font-bold text-white">
            4
          </span>
        </button>

        <div className="flex items-center gap-3 rounded-lg border border-slate-700 bg-slate-800/50 px-3 py-1.5">
          <Shield className="h-4 w-4 text-cyan-400" />
          <div className="text-xs">
            <p className="font-medium text-slate-200">SOC Analyst</p>
            <p className="text-slate-500">Tier 2</p>
          </div>
        </div>
      </div>
    </header>
  );
}
