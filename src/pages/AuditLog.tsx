import { useState } from 'react';
import {
  ScrollText,
  Download,
  ChevronDown,
  Clock,
  Shield,
  FileText,
  Upload,
  AlertTriangle,
} from 'lucide-react';
import { useStore } from '../lib/store';

export function AuditLog() {
  const entries = useStore(s => s.auditLogs);
  const [filterAction, setFilterAction] = useState('all');

  const filtered = entries.filter(e => {
    if (filterAction !== 'all' && !e.action.toLowerCase().includes(filterAction.toLowerCase())) return false;
    return true;
  });

  const handleExport = () => {
    const csv = [
      'Timestamp,Action,Resource Type,Resource ID,Details',
      ...filtered.map(e =>
        `"${new Date(e.created_at).toISOString()}","${e.action}","${e.resource_type}","${e.resource_id || ''}","${JSON.stringify(e.details).replace(/"/g, '""')}"`
      ),
    ].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit-log-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getActionIcon = (action: string) => {
    if (action.includes('ALERT')) return AlertTriangle;
    if (action.includes('INCIDENT')) return Shield;
    if (action.includes('REPORT')) return FileText;
    if (action.includes('UPLOAD') || action.includes('LOG')) return Upload;
    return ScrollText;
  };

  const getActionColor = (action: string) => {
    if (action.includes('CREATED') || action.includes('GENERATED')) return 'text-emerald-400';
    if (action.includes('ESCALATED')) return 'text-red-400';
    if (action.includes('TRIAGED') || action.includes('MAPPED') || action.includes('ENRICHED')) return 'text-cyan-400';
    if (action.includes('CONTAINED') || action.includes('RESOLVED')) return 'text-orange-400';
    if (action.includes('UPDATED') || action.includes('LINKED')) return 'text-blue-400';
    return 'text-slate-400';
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Audit Log</h1>
          <p className="text-sm text-slate-400 mt-1">Tamper-evident record of all SOC actions</p>
        </div>
        <button
          onClick={handleExport}
          className="flex items-center gap-2 rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800 transition-colors"
        >
          <Download className="h-4 w-4" />
          Export CSV
        </button>
      </div>

      <div className="flex items-center gap-3">
        <div className="relative">
          <select value={filterAction} onChange={e => setFilterAction(e.target.value)} className="appearance-none rounded-lg border border-slate-700 bg-slate-800/50 py-2 pl-3 pr-8 text-sm text-slate-200 outline-none focus:border-cyan-500/50 cursor-pointer">
            <option value="all">All Actions</option>
            <option value="alert">Alert Actions</option>
            <option value="incident">Incident Actions</option>
            <option value="mitre">MITRE Mapping</option>
            <option value="upload">Upload/Analysis</option>
            <option value="report">Reports</option>
          </select>
          <ChevronDown className="absolute right-2 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400 pointer-events-none" />
        </div>
        <span className="text-xs text-slate-500">{filtered.length} entries</span>
      </div>

      <div className="relative">
        <div className="space-y-0">
          {filtered.map((entry, i) => {
            const Icon = getActionIcon(entry.action);
            const color = getActionColor(entry.action);
            return (
              <div key={entry.id} className="relative flex gap-4 pb-6">
                <div className="flex flex-col items-center flex-shrink-0">
                  <div className="flex h-8 w-8 items-center justify-center rounded-full border border-slate-700 bg-slate-900">
                    <Icon className={`h-4 w-4 ${color}`} />
                  </div>
                  {i < filtered.length - 1 && <div className="w-px flex-1 bg-slate-800 mt-1" />}
                </div>
                <div className="flex-1 rounded-lg border border-slate-800 bg-slate-900 p-4 hover:bg-slate-900/80 transition-colors">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className={`text-sm font-semibold ${color}`}>{entry.action.replace(/_/g, ' ')}</span>
                      <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-500">{entry.resource_type}</span>
                    </div>
                    <span className="text-xs text-slate-500 flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {new Date(entry.created_at).toLocaleString()}
                    </span>
                  </div>
                  <div className="mt-2 text-xs text-slate-400">
                    Resource ID: <span className="font-mono text-slate-300">{entry.resource_id}</span>
                  </div>
                  {entry.details && Object.keys(entry.details).length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-2">
                      {Object.entries(entry.details).map(([key, value]) => (
                        <span key={key} className="rounded border border-slate-800 bg-slate-800/50 px-2 py-0.5 text-[10px]">
                          <span className="text-slate-500">{key}:</span> <span className="text-slate-300">{String(value)}</span>
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
