import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Bell,
  ChevronDown,
  Shield,
  Search,
  AlertTriangle,
} from 'lucide-react';
import { useStore } from '../lib/store';
import { getSeverityColor, getSeverityBg, getStatusColor, getThreatTypeLabel } from '../lib/seedData';

export function AlertQueue() {
  const navigate = useNavigate();
  const alerts = useStore(s => s.alerts);
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');

  const filtered = alerts.filter(a => {
    if (filterSeverity !== 'all' && a.severity !== filterSeverity) return false;
    if (filterStatus !== 'all' && a.status !== filterStatus) return false;
    if (searchQuery && !a.title.toLowerCase().includes(searchQuery.toLowerCase()) && !a.threat_type.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Alert Queue</h1>
          <p className="text-sm text-slate-400 mt-1">{filtered.length} alerts requiring attention</p>
        </div>
        <div className="flex items-center gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-1.5">
          <Bell className="h-4 w-4 text-cyan-400" />
          <span className="text-sm font-medium text-cyan-400">{alerts.filter(a => a.status === 'new').length} New</span>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search alerts..."
            className="w-full rounded-lg border border-slate-700 bg-slate-800/50 py-2 pl-10 pr-4 text-sm text-slate-200 placeholder-slate-500 outline-none focus:border-cyan-500/50 transition-colors"
          />
        </div>
        <div className="relative">
          <select value={filterSeverity} onChange={e => setFilterSeverity(e.target.value)} className="appearance-none rounded-lg border border-slate-700 bg-slate-800/50 py-2 pl-3 pr-8 text-sm text-slate-200 outline-none focus:border-cyan-500/50 cursor-pointer">
            <option value="all">All Severity</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <ChevronDown className="absolute right-2 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400 pointer-events-none" />
        </div>
        <div className="relative">
          <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)} className="appearance-none rounded-lg border border-slate-700 bg-slate-800/50 py-2 pl-3 pr-8 text-sm text-slate-200 outline-none focus:border-cyan-500/50 cursor-pointer">
            <option value="all">All Status</option>
            <option value="new">New</option>
            <option value="triaged">Triaged</option>
            <option value="escalated">Escalated</option>
            <option value="closed">Closed</option>
          </select>
          <ChevronDown className="absolute right-2 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400 pointer-events-none" />
        </div>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/50">
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Severity</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Alert</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Threat Type</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Source</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Confidence</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Status</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {filtered.map(alert => (
                <tr
                  key={alert.id}
                  onClick={() => navigate(`/alerts/${alert.id}`)}
                  className="cursor-pointer hover:bg-slate-800/40 transition-colors"
                >
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-semibold ${getSeverityBg(alert.severity)} ${getSeverityColor(alert.severity)}`}>
                      {alert.severity === 'critical' && <AlertTriangle className="h-3 w-3" />}
                      {alert.severity.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm font-medium text-slate-200">{alert.title}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="flex items-center gap-1.5 text-xs text-slate-300">
                      <Shield className="h-3 w-3 text-cyan-400" />
                      {getThreatTypeLabel(alert.threat_type)}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-400">{alert.source}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 w-16 rounded-full bg-slate-700">
                        <div className="h-full rounded-full bg-cyan-400 transition-all" style={{ width: `${alert.confidence * 100}%` }} />
                      </div>
                      <span className="text-xs text-slate-400">{(alert.confidence * 100).toFixed(0)}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs font-medium capitalize ${getStatusColor(alert.status)}`}>{alert.status}</span>
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-500">{new Date(alert.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {filtered.length === 0 && (
          <div className="flex flex-col items-center justify-center py-12">
            <Bell className="h-8 w-8 text-slate-600 mb-2" />
            <p className="text-sm text-slate-500">No alerts match your filters</p>
          </div>
        )}
      </div>
    </div>
  );
}

