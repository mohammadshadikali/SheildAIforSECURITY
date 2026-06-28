import { useState, useMemo } from 'react';
import {
  ScrollText,
  Download,
  ChevronDown,
  Clock,
  Shield,
  FileText,
  Upload,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  LogIn,
  UserCog,
} from 'lucide-react';
import { useStore, type AuditRecord } from '../lib/store';

interface DisplayEntry {
  id: string;
  timestamp: string;
  user: string;
  action: string;
  details: string;
  status: 'Success' | 'Failed';
  resource_type: string;
  resource_id: string;
}

const MOCK_AUDIT: DisplayEntry[] = [
  { id: 'mock-1', timestamp: new Date(Date.now() - 5 * 60 * 1000).toISOString(), user: 'analyst.tier2', action: 'LOGIN', details: 'User authenticated via SSO (Okta)', status: 'Success', resource_type: 'auth', resource_id: 'session-8f2a' },
  { id: 'mock-2', timestamp: new Date(Date.now() - 12 * 60 * 1000).toISOString(), user: 'analyst.tier2', action: 'ALERT_ACKNOWLEDGED', details: 'Acknowledged alert "Suspicious PowerShell Execution" (alert-demo-3)', status: 'Success', resource_type: 'alert', resource_id: 'demo-alert-3' },
  { id: 'mock-3', timestamp: new Date(Date.now() - 28 * 60 * 1000).toISOString(), user: 'analyst.tier1', action: 'ALERT_ESCALATED', details: 'Escalated alert to incident — severity high, threat_type credential_brute_force', status: 'Success', resource_type: 'alert', resource_id: 'demo-alert-1' },
  { id: 'mock-4', timestamp: new Date(Date.now() - 52 * 60 * 1000).toISOString(), user: 'analyst.tier2', action: 'INCIDENT_UPDATED', details: 'Updated incident status from open to investigating — impact_score 8.5', status: 'Success', resource_type: 'incident', resource_id: 'demo-inc-0' },
  { id: 'mock-5', timestamp: new Date(Date.now() - 75 * 60 * 1000).toISOString(), user: 'analyst.tier2', action: 'MITRE_MAPPED', details: 'Mapped technique T1110 (Brute Force) to incident with 92% confidence', status: 'Success', resource_type: 'mitre_mapping', resource_id: 'T1110' },
  { id: 'mock-6', timestamp: new Date(Date.now() - 96 * 60 * 1000).toISOString(), user: 'analyst.tier1', action: 'IOC_ENRICHED', details: 'Enriched IOC 185.220.101.34 — reputation: malicious, country: DE, tor_exit: true', status: 'Success', resource_type: 'ioc', resource_id: 'demo-ioc-0' },
  { id: 'mock-7', timestamp: new Date(Date.now() - 118 * 60 * 1000).toISOString(), user: 'analyst.tier2', action: 'REPORT_GENERATED', details: 'Generated full incident report for "Ransomware Activity Detected"', status: 'Success', resource_type: 'report', resource_id: 'demo-inc-3' },
  { id: 'mock-8', timestamp: new Date(Date.now() - 142 * 60 * 1000).toISOString(), user: 'analyst.tier1', action: 'LOG_UPLOADED', details: 'Uploaded Suricata eve.json (24.3 MB) for threat analysis', status: 'Success', resource_type: 'upload', resource_id: 'upload-3c91' },
  { id: 'mock-9', timestamp: new Date(Date.now() - 165 * 60 * 1000).toISOString(), user: 'analyst.tier2', action: 'INCIDENT_CONTAINED', details: 'Contained incident — isolated 3 endpoints, blocked 2 malicious IPs at perimeter', status: 'Success', resource_type: 'incident', resource_id: 'demo-inc-2' },
  { id: 'mock-10', timestamp: new Date(Date.now() - 190 * 60 * 1000).toISOString(), user: 'system', action: 'LOGIN', details: 'Authentication failed — invalid credentials for admin@soc.local', status: 'Failed', resource_type: 'auth', resource_id: 'session-failed' },
  { id: 'mock-11', timestamp: new Date(Date.now() - 215 * 60 * 1000).toISOString(), user: 'analyst.tier2', action: 'ALERT_ACKNOWLEDGED', details: 'Acknowledged alert "C2 Beacon Traffic" (alert-demo-5)', status: 'Success', resource_type: 'alert', resource_id: 'demo-alert-5' },
  { id: 'mock-12', timestamp: new Date(Date.now() - 240 * 60 * 1000).toISOString(), user: 'analyst.tier1', action: 'INCIDENT_CREATED', details: 'Created incident "Phishing Campaign — Credential Harvesting" from correlated alerts', status: 'Success', resource_type: 'incident', resource_id: 'demo-inc-1' },
];

export function AuditLog() {
  const storeEntries = useStore(s => s.auditLogs);
  const [filterAction, setFilterAction] = useState('all');

  const entries: DisplayEntry[] = useMemo(() => {
    if (storeEntries.length > 0) {
      return storeEntries.map((e: AuditRecord) => ({
        id: e.id,
        timestamp: e.created_at,
        user: (e.details?.user as string) || 'analyst.tier2',
        action: e.action,
        details: JSON.stringify(e.details),
        status: (e.details?.status as 'Success' | 'Failed') || 'Success',
        resource_type: e.resource_type,
        resource_id: e.resource_id || '',
      }));
    }
    return MOCK_AUDIT;
  }, [storeEntries]);

  const filtered = entries.filter(e => {
    if (filterAction !== 'all' && !e.action.toLowerCase().includes(filterAction.toLowerCase())) return false;
    return true;
  });

  const handleExport = () => {
    const csv = [
      'Timestamp,User,Action,Details,Status',
      ...filtered.map(e =>
        `"${new Date(e.timestamp).toISOString()}","${e.user}","${e.action}","${e.details.replace(/"/g, '""')}","${e.status}"`
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
    if (action.includes('LOGIN')) return LogIn;
    if (action.includes('ALERT')) return AlertTriangle;
    if (action.includes('INCIDENT')) return Shield;
    if (action.includes('REPORT')) return FileText;
    if (action.includes('UPLOAD') || action.includes('LOG')) return Upload;
    if (action.includes('IOC') || action.includes('MITRE')) return UserCog;
    return ScrollText;
  };

  const getActionColor = (action: string) => {
    if (action.includes('CREATED') || action.includes('GENERATED') || action.includes('LOGIN')) return 'text-emerald-400';
    if (action.includes('ESCALATED') || action.includes('CONTAINED')) return 'text-red-400';
    if (action.includes('TRIAGED') || action.includes('MAPPED') || action.includes('ENRICHED') || action.includes('ACKNOWLEDGED')) return 'text-cyan-400';
    if (action.includes('RESOLVED')) return 'text-orange-400';
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
            <option value="login">Logins</option>
            <option value="alert">Alert Actions</option>
            <option value="incident">Incident Actions</option>
            <option value="mitre">MITRE Mapping</option>
            <option value="ioc">IOC Enrichment</option>
            <option value="upload">Upload/Analysis</option>
            <option value="report">Reports</option>
          </select>
          <ChevronDown className="absolute right-2 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400 pointer-events-none" />
        </div>
        <span className="text-xs text-slate-500">{filtered.length} entries</span>
      </div>

      <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/80">
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">Timestamp</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">User</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">Action</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">Details</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {filtered.map(entry => {
                const Icon = getActionIcon(entry.action);
                const color = getActionColor(entry.action);
                return (
                  <tr key={entry.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-4 py-3 whitespace-nowrap text-xs text-slate-400">
                      <span className="flex items-center gap-1.5">
                        <Clock className="h-3 w-3 text-slate-600" />
                        {new Date(entry.timestamp).toLocaleString()}
                      </span>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-sm text-slate-300 font-mono">
                      {entry.user}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className="flex items-center gap-2">
                        <Icon className={`h-4 w-4 ${color}`} />
                        <span className={`text-sm font-medium ${color}`}>{entry.action.replace(/_/g, ' ')}</span>
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400 max-w-md">
                      <div className="truncate" title={entry.details}>{entry.details}</div>
                      {entry.resource_id && (
                        <div className="mt-0.5 text-[10px] text-slate-600 font-mono">{entry.resource_type}: {entry.resource_id}</div>
                      )}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      {entry.status === 'Success' ? (
                        <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-xs font-medium text-emerald-400">
                          <CheckCircle2 className="h-3 w-3" />
                          Success
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 rounded-full border border-red-500/30 bg-red-500/10 px-2.5 py-1 text-xs font-medium text-red-400">
                          <XCircle className="h-3 w-3" />
                          Failed
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {filtered.length === 0 && (
          <div className="flex flex-col items-center justify-center py-12">
            <ScrollText className="h-8 w-8 text-slate-600 mb-2" />
            <p className="text-sm text-slate-500">No audit entries found</p>
            <p className="text-xs text-slate-600 mt-1">Try changing the filter or perform a SOC action</p>
          </div>
        )}
      </div>
    </div>
  );
}
