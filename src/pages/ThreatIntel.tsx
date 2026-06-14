import { useState } from 'react';
import {
  Globe,
  Shield,
  Hash,
  Link,
  Mail,
  Bug,
  Search,
  ChevronDown,
  ExternalLink,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
} from 'lucide-react';
import { useStore, type IOCRecord } from '../lib/store';

const TYPE_ICONS: Record<string, React.ElementType> = {
  ip: Globe,
  domain: Link,
  hash: Hash,
  url: Link,
  email: Mail,
  cve: Bug,
  other: Shield,
};

const REP_CONFIG: Record<string, { icon: React.ElementType; color: string; bg: string }> = {
  malicious: { icon: XCircle, color: 'text-red-400', bg: 'bg-red-500/20 border-red-500/30' },
  suspicious: { icon: AlertTriangle, color: 'text-orange-400', bg: 'bg-orange-500/20 border-orange-500/30' },
  clean: { icon: CheckCircle2, color: 'text-emerald-400', bg: 'bg-emerald-500/20 border-emerald-500/30' },
  unknown: { icon: HelpCircle, color: 'text-slate-400', bg: 'bg-slate-500/20 border-slate-500/30' },
};

function getRiskScore(ioc: IOCRecord): number {
  if (ioc.reputation === 'malicious') return Math.floor(Math.random() * 20) + 80;
  if (ioc.reputation === 'suspicious') return Math.floor(Math.random() * 30) + 50;
  if (ioc.reputation === 'clean') return Math.floor(Math.random() * 20) + 5;
  return Math.floor(Math.random() * 30) + 30;
}

export function ThreatIntel() {
  const iocs = useStore(s => s.iocs);
  const [filterType, setFilterType] = useState('all');
  const [filterRep, setFilterRep] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIOC, setSelectedIOC] = useState<IOCRecord | null>(null);

  const filtered = iocs.filter(ioc => {
    if (filterType !== 'all' && ioc.type !== filterType) return false;
    if (filterRep !== 'all' && ioc.reputation !== filterRep) return false;
    if (searchQuery && !ioc.value.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  }).map(ioc => ({ ...ioc, _risk: getRiskScore(ioc) }));

  const typeCounts = iocs.reduce((acc, i) => { acc[i.type] = (acc[i.type] || 0) + 1; return acc; }, {} as Record<string, number>);
  const repCounts = iocs.reduce((acc, i) => { acc[i.reputation] = (acc[i.reputation] || 0) + 1; return acc; }, {} as Record<string, number>);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Threat Intelligence</h1>
          <p className="text-sm text-slate-400 mt-1">{iocs.length} indicators of compromise tracked</p>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded-xl border border-red-500/30 bg-gradient-to-br from-red-500/15 to-red-500/5 p-4">
          <p className="text-xs text-red-400/70">Malicious</p>
          <p className="text-2xl font-bold text-red-400">{repCounts.malicious || 0}</p>
        </div>
        <div className="rounded-xl border border-orange-500/30 bg-gradient-to-br from-orange-500/15 to-orange-500/5 p-4">
          <p className="text-xs text-orange-400/70">Suspicious</p>
          <p className="text-2xl font-bold text-orange-400">{repCounts.suspicious || 0}</p>
        </div>
        <div className="rounded-xl border border-emerald-500/30 bg-gradient-to-br from-emerald-500/15 to-emerald-500/5 p-4">
          <p className="text-xs text-emerald-400/70">Clean</p>
          <p className="text-2xl font-bold text-emerald-400">{repCounts.clean || 0}</p>
        </div>
        <div className="rounded-xl border border-slate-500/30 bg-gradient-to-br from-slate-500/15 to-slate-500/5 p-4">
          <p className="text-xs text-slate-400/70">Unknown</p>
          <p className="text-2xl font-bold text-slate-300">{repCounts.unknown || 0}</p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search IOCs..."
            className="w-full rounded-lg border border-slate-700 bg-slate-800/50 py-2 pl-10 pr-4 text-sm text-slate-200 placeholder-slate-500 outline-none focus:border-cyan-500/50 transition-colors"
          />
        </div>
        <div className="relative">
          <select value={filterType} onChange={e => setFilterType(e.target.value)} className="appearance-none rounded-lg border border-slate-700 bg-slate-800/50 py-2 pl-3 pr-8 text-sm text-slate-200 outline-none focus:border-cyan-500/50 cursor-pointer">
            <option value="all">All Types</option>
            <option value="ip">IP Address</option>
            <option value="domain">Domain</option>
            <option value="hash">File Hash</option>
            <option value="url">URL</option>
            <option value="email">Email</option>
            <option value="cve">CVE</option>
          </select>
          <ChevronDown className="absolute right-2 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400 pointer-events-none" />
        </div>
        <div className="relative">
          <select value={filterRep} onChange={e => setFilterRep(e.target.value)} className="appearance-none rounded-lg border border-slate-700 bg-slate-800/50 py-2 pl-3 pr-8 text-sm text-slate-200 outline-none focus:border-cyan-500/50 cursor-pointer">
            <option value="all">All Reputations</option>
            <option value="malicious">Malicious</option>
            <option value="suspicious">Suspicious</option>
            <option value="clean">Clean</option>
            <option value="unknown">Unknown</option>
          </select>
          <ChevronDown className="absolute right-2 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400 pointer-events-none" />
        </div>
      </div>

      {/* IOC Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/50">
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Type</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Value</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Reputation</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Risk Score</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Enrichment</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">First Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {filtered.map((ioc) => {
                const TypeIcon = TYPE_ICONS[ioc.type] || Shield;
                const rep = REP_CONFIG[ioc.reputation] || REP_CONFIG.unknown;
                const RepIcon = rep.icon;

                return (
                  <tr
                    key={ioc.id}
                    onClick={() => setSelectedIOC(ioc)}
                    className="cursor-pointer hover:bg-slate-800/40 transition-colors"
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <TypeIcon className="h-4 w-4 text-cyan-400" />
                        <span className="text-xs font-semibold text-slate-300 uppercase">{ioc.type}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="font-mono text-sm text-slate-200">{ioc.value}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-semibold ${rep.bg} ${rep.color}`}>
                        <RepIcon className="h-3 w-3" />
                        {ioc.reputation}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 w-16 rounded-full bg-slate-700">
                          <div
                            className={`h-full rounded-full ${
                              (ioc as any)._risk >= 80 ? 'bg-red-500' :
                              (ioc as any)._risk >= 50 ? 'bg-orange-500' :
                              (ioc as any)._risk >= 30 ? 'bg-yellow-500' : 'bg-emerald-500'
                            }`}
                            style={{ width: `${(ioc as any)._risk}%` }}
                          />
                        </div>
                        <span className={`text-xs font-bold ${
                          (ioc as any)._risk >= 80 ? 'text-red-400' :
                          (ioc as any)._risk >= 50 ? 'text-orange-400' :
                          (ioc as any)._risk >= 30 ? 'text-yellow-400' : 'text-emerald-400'
                        }`}>{(ioc as any)._risk}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {Object.entries(ioc.enrichment_data || {}).slice(0, 3).map(([k, v]) => (
                          <span key={k} className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-400">
                            {k}: {String(v)}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-500">
                      {ioc.first_seen ? new Date(ioc.first_seen).toLocaleDateString() : '-'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {filtered.length === 0 && (
          <div className="flex flex-col items-center justify-center py-12">
            <Shield className="h-8 w-8 text-slate-600 mb-2" />
            <p className="text-sm text-slate-500">No IOCs match your filters</p>
          </div>
        )}
      </div>

      {/* IOC Detail Modal */}
      {selectedIOC && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => setSelectedIOC(null)}>
          <div className="mx-4 w-full max-w-lg rounded-xl border border-slate-700 bg-slate-900 p-6" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-white">IOC Details</h2>
              <button onClick={() => setSelectedIOC(null)} className="text-slate-500 hover:text-slate-300">Close</button>
            </div>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-500">Type</span>
                <span className="text-sm font-semibold text-cyan-400 uppercase">{selectedIOC.type}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-500">Value</span>
                <span className="text-sm font-mono text-slate-200">{selectedIOC.value}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-500">Reputation</span>
                <span className={`text-sm font-semibold ${REP_CONFIG[selectedIOC.reputation]?.color || 'text-slate-400'}`}>{selectedIOC.reputation}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-500">Risk Score</span>
                <span className="text-sm font-bold text-white">{getRiskScore(selectedIOC)}/100</span>
              </div>
              {selectedIOC.enrichment_data && Object.keys(selectedIOC.enrichment_data).length > 0 && (
                <div>
                  <span className="text-xs text-slate-500">Enrichment Data</span>
                  <pre className="mt-1 rounded-lg bg-slate-950 p-3 text-xs text-slate-300 font-mono overflow-x-auto">
                    {JSON.stringify(selectedIOC.enrichment_data, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
