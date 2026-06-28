import React, { useState } from 'react';

interface IOC {
  id: string;
  type: 'ip' | 'domain' | 'hash' | 'url' | 'email' | 'registry';
  value: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: number;
  source: string;
  firstSeen: string;
  lastSeen: string;
  tags: string[];
  verified: boolean;
}

interface ThreatCorrelation {
  id: string;
  name: string;
  type: 'apt' | 'malware' | 'campaign' | 'vulnerability';
  confidence: number;
  description: string;
  mitreTechniques: string[];
  relatedIncidents: number;
}

interface TimelineEvent {
  id: string;
  timestamp: string;
  event: string;
  source: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

interface IncidentDetails {
  id: string;
  title: string;
  status: 'active' | 'investigating' | 'contained' | 'resolved';
  severity: 'critical' | 'high' | 'medium' | 'low';
  assignee: string;
  createdAt: string;
  updatedAt: string;
  affectedSystems: string[];
  attackVectors: string[];
  summary: string;
}

const INCIDENT: IncidentDetails = {
  id: 'INC-2024-0847',
  title: 'Advanced Persistent Threat - Credential Harvesting Campaign',
  status: 'investigating',
  severity: 'critical',
  assignee: 'Sarah Chen',
  createdAt: '2024-12-14 02:17:33 UTC',
  updatedAt: '2024-12-14 08:43:11 UTC',
  affectedSystems: ['DESKTOP-7K2M9P', 'SRV-DC-01', 'SRV-FILE-03', 'LAPTOP-MKT-22'],
  attackVectors: ['Spearphishing', 'Credential Theft', 'Lateral Movement', 'Data Exfiltration'],
  summary: 'A sophisticated threat actor gained initial access via a spearphishing email containing a malicious macro-enabled document. The attacker subsequently performed credential dumping from LSASS memory, moved laterally to domain controller SRV-DC-01, and established persistence via scheduled tasks. Evidence of staged data exfiltration detected to external C2 infrastructure.',
};

const IOCS: IOC[] = [
  { id: 'ioc1', type: 'ip', value: '185.220.101.47', severity: 'critical', confidence: 97, source: 'Threat Intel Feed', firstSeen: '2024-12-14 02:31:00', lastSeen: '2024-12-14 08:22:00', tags: ['C2', 'TOR Exit'], verified: true },
  { id: 'ioc2', type: 'domain', value: 'update-svc.microsft-cdn.com', severity: 'critical', confidence: 94, source: 'DNS Analysis', firstSeen: '2024-12-14 02:45:00', lastSeen: '2024-12-14 07:58:00', tags: ['Typosquat', 'C2', 'Phishing'], verified: true },
  { id: 'ioc3', type: 'hash', value: 'a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9', severity: 'high', confidence: 89, source: 'EDR Alert', firstSeen: '2024-12-14 03:12:00', lastSeen: '2024-12-14 03:12:00', tags: ['Malware', 'Dropper'], verified: true },
  { id: 'ioc4', type: 'url', value: 'hxxps://update-svc.microsft-cdn[.]com/payload/stage2.bin', severity: 'critical', confidence: 96, source: 'Proxy Logs', firstSeen: '2024-12-14 03:15:00', lastSeen: '2024-12-14 06:44:00', tags: ['Payload', 'Stage2'], verified: true },
  { id: 'ioc5', type: 'email', value: 'hr-noreply@microsofit-corp.com', severity: 'high', confidence: 91, source: 'Email Gateway', firstSeen: '2024-12-14 02:17:00', lastSeen: '2024-12-14 02:17:00', tags: ['Phishing', 'Sender'], verified: true },
  { id: 'ioc6', type: 'registry', value: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SvcHost32', severity: 'high', confidence: 85, source: 'EDR Telemetry', firstSeen: '2024-12-14 04:02:00', lastSeen: '2024-12-14 08:01:00', tags: ['Persistence', 'Registry'], verified: false },
  { id: 'ioc7', type: 'ip', value: '45.142.212.118', severity: 'high', confidence: 82, source: 'Firewall Logs', firstSeen: '2024-12-14 05:33:00', lastSeen: '2024-12-14 08:15:00', tags: ['Exfil', 'C2'], verified: false },
  { id: 'ioc8', type: 'hash', value: 'b7e3a1f9c2d8e4b5a6c7d8e9f0a1b2c3d4e5f6b7', severity: 'medium', confidence: 73, source: 'Sandbox Analysis', firstSeen: '2024-12-14 04:45:00', lastSeen: '2024-12-14 04:45:00', tags: ['Ransomware', 'Encrypted'], verified: false },
];

const CORRELATIONS: ThreatCorrelation[] = [
  { id: 'tc1', name: 'APT29 (Cozy Bear)', type: 'apt', confidence: 78, description: 'Russian state-sponsored threat group known for targeting government and private sector organizations. TTPs align with observed spearphishing and credential theft patterns.', mitreTechniques: ['T1566.001', 'T1003.001', 'T1021.001', 'T1041'], relatedIncidents: 3 },
  { id: 'tc2', name: 'NOBELIUM Campaign', type: 'campaign', confidence: 65, description: 'Large-scale supply chain and credential theft campaign. Domain typosquatting and macro-enabled document delivery methods match observed IOCs.', mitreTechniques: ['T1195', 'T1566', 'T1059'], relatedIncidents: 1 },
  { id: 'tc3', name: 'Cobalt Strike Beacon', type: 'malware', confidence: 91, description: 'Commercial penetration testing tool widely abused by threat actors. Identified C2 communication patterns and staging behavior consistent with Cobalt Strike.', mitreTechniques: ['T1055', 'T1027', 'T1071.001'], relatedIncidents: 7 },
  { id: 'tc4', name: 'CVE-2024-21887', type: 'vulnerability', confidence: 60, description: 'Critical command injection vulnerability in Ivanti Connect Secure VPN. May have been used for initial access prior to spearphishing as a secondary vector.', mitreTechniques: ['T1190'], relatedIncidents: 2 },
];

const TIMELINE: TimelineEvent[] = [
  { id: 't1', timestamp: '02:17:33', event: 'Malicious email received by j.morrison@corp.local with attachment "Q4_Report_Final.xlsm"', source: 'Email Gateway', severity: 'high' },
  { id: 't2', timestamp: '02:31:12', event: 'Macro execution detected on DESKTOP-7K2M9P — spawned cmd.exe child process', source: 'EDR', severity: 'critical' },
  { id: 't3', timestamp: '02:31:45', event: 'Outbound connection to 185.220.101.47:443 established — C2 beacon identified', source: 'Firewall', severity: 'critical' },
  { id: 't4', timestamp: '03:12:08', event: 'LSASS memory access detected — credential dumping via Mimikatz signatures', source: 'EDR', severity: 'critical' },
  { id: 't5', timestamp: '03:44:21', event: 'Lateral movement detected — RDP login to SRV-DC-01 using harvested credentials', source: 'SIEM', severity: 'critical' },
  { id: 't6', timestamp: '04:02:55', event: 'Persistence established via registry run key on SRV-DC-01', source: 'EDR', severity: 'high' },
  { id: 't7', timestamp: '05:33:19', event: 'Data staging detected — 4.2GB archive created in C:\\Temp\\backup_old', source: 'DLP', severity: 'high' },
  { id: 't8', timestamp: '06:44:07', event: 'Exfiltration attempt detected — connection to 45.142.212.118:8443', source: 'Firewall', severity: 'critical' },
  { id: 't9', timestamp: '08:22:44', event: 'Incident detected by SOC analyst — automated containment triggered', source: 'SOC', severity: 'info' },
];

type TabType = 'summary' | 'iocs' | 'correlations' | 'timeline';

const InvestigationPanel: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabType>('summary');
  const [iocTypeFilter, setIocTypeFilter] = useState<string>('all');
  const [expandedCorrelation, setExpandedCorrelation] = useState<string | null>(null);
  const [selectedIocs, setSelectedIocs] = useState<string[]>([]);

  const severityConfig = {
    critical: { badge: 'bg-red-900/60 text-red-300 border-red-500/50', dot: 'bg-red-400', text: 'text-red-400', border: 'border-l-red-500' },
    high: { badge: 'bg-orange-900/60 text-orange-300 border-orange-500/50', dot: 'bg-orange-400', text: 'text-orange-400', border: 'border-l-orange-500' },
    medium: { badge: 'bg-yellow-900/60 text-yellow-300 border-yellow-500/50', dot: 'bg-yellow-400', text: 'text-yellow-400', border: 'border-l-yellow-500' },
    low: { badge: 'bg-green-900/60 text-green-300 border-green-500/50', dot: 'bg-green-400', text: 'text-green-400', border: 'border-l-green-500' },
    info: { badge: 'bg-blue-900/60 text-blue-300 border-blue-500/50', dot: 'bg-blue-400', text: 'text-blue-400', border: 'border-l-blue-500' },
  };

  const statusConfig = {
    active: 'bg-red-900/60 text-red-300 border-red-500/50',
    investigating: 'bg-yellow-900/60 text-yellow-300 border-yellow-500/50',
    contained: 'bg-orange-900/60 text-orange-300 border-orange-500/50',
    resolved: 'bg-green-900/60 text-green-300 border-green-500/50',
  };

  const iocTypeConfig: Record<string, { label: string; color: string; icon: React.ReactNode }> = {
    ip: { label: 'IP', color: 'text-red-400 bg-red-900/30 border-red-500/40', icon: <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" /></svg> },
    domain: { label: 'Domain', color: 'text-orange-400 bg-orange-900/30 border-orange-500/40', icon: <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" /></svg> },
    hash: { label: 'Hash', color: 'text-purple-400 bg-purple-900/30 border-purple-500/40', icon: <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 20l4-16m2 16l4-16M6 9h14M4 15h14" /></svg> },
    url: { label: 'URL', color: 'text-yellow-400 bg-yellow-900/30 border-yellow-500/40', icon: <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg> },
    email: { label: 'Email', color: 'text-blue-400 bg-blue-900/30 border-blue-500/40', icon: <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg> },
    registry: { label: 'Registry', color: 'text-cyan-400 bg-cyan-900/30 border-cyan-500/40', icon: <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18" /></svg> },
  };

  const correlationTypeConfig: Record<string, { color: string; bg: string }> = {
    apt: { color: 'text-red-400', bg: 'bg-red-900/30 border-red-500/40' },
    malware: { color: 'text-orange-400', bg: 'bg-orange-900/30 border-orange-500/40' },
    campaign: { color: 'text-purple-400', bg: 'bg-purple-900/30 border-purple-500/40' },
    vulnerability: { color: 'text-yellow-400', bg: 'bg-yellow-900/30 border-yellow-500/40' },
  };

  const filteredIocs = iocTypeFilter === 'all' ? IOCS : IOCS.filter(i => i.type === iocTypeFilter);

  const toggleIoc = (id: string) => {
    setSelectedIocs(prev => prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]);
  };

  const tabs: { id: TabType; label: string; count?: number; icon: React.ReactNode }[] = [
    {
      id: 'summary', label: 'Summary', icon:
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
    },
    {
      id: 'iocs', label: 'IOCs', count: IOCS.length, icon:
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
    },
    {
      id: 'correlations', label: 'Threats', count: CORRELATIONS.length, icon:
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" /></svg>
    },
    {
      id: 'timeline', label: 'Timeline', count: TIMELINE.length, icon:
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
    },
  ];

  return (
    <div className="bg-gray-950 text-gray-100 min-h-full flex flex-col">
      {/* Incident Header */}
      <div className="bg-gray-900/60 border-b border-gray-700/50 p-4 lg:p-5">
        <div className="flex items-start justify-between gap-3 flex-wrap mb-3">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-mono text-cyan-400 bg-cyan-400/10 border border-cyan-400/30 px-2 py-0.5 rounded">{INCIDENT.id}</span>
              <span className={`text-xs font-semibold px-2.5 py-0.5 rounded-full border capitalize ${statusConfig[INCIDENT.status]}`}>
                <span className="inline-block w-1.5 h-1.5 rounded-full bg-current mr-1.5 animate-pulse" />
                {INCIDENT.status}
              </span>
              <span className={`text-xs font-semibold px-2.5 py-0.5 rounded-full border capitalize ${severityConfig[INCIDENT.severity].badge}`}>
                {INCIDENT.severity}
              </span>
            </div>
            <h1 className="text-sm font-bold text-gray-100 leading-tight">{INCIDENT.title}</h1>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: 'Assignee', value: INCIDENT.assignee, icon: <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg> },
            { label: 'Affected Systems', value: `${INCIDENT.affectedSystems.length} hosts`, icon: <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18" /></svg> },
            { label: 'Created', value: INCIDENT.createdAt.split(' ')[1], icon: <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> },
            { label: 'Last Updated', value: INCIDENT.updatedAt.split(' ')[1], icon: <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" /></svg> },
          ].map(item => (
            <div key={item.label} className="bg-gray-800/50 border border-gray-700/40 rounded-lg p-2.5">
              <div className="flex items-center gap-1.5 text-gray-500 mb-1">
                {item.icon}
                <span className="text-xs">{item.label}</span>
              </div>
              <div className="text-xs font-medium text-gray-200 font-mono">{item.value}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-700/50 bg-gray-900/40 px-4">
        <div className="flex gap-0.5">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-3 py-3 text-xs font-medium border-b-2 transition-all ${
                activeTab === tab.id
                  ? 'border-cyan-400 text-cyan-400'
                  : 'border-transparent text-gray-500 hover:text-gray-300 hover:border-gray-600'
              }`}
            >
              {tab.icon}
              {tab.label}
              {tab.count !== undefined && (
                <span className={`text-xs px-1.5 py-0.5 rounded-full font-mono ${activeTab === tab.id ? 'bg-cyan-400/20 text-cyan-400' : 'bg-gray-800 text-gray-500'}`}>
                  {tab.count}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Tab Content */}
      <div className="flex-1 overflow-y-auto p-4 lg:p-5">

        {/* Summary Tab */}
        {activeTab === 'summary' && (
          <div className="space-y-4">
            <div className="bg-gray-900/60 border border-gray-700/50 rounded-lg p-4">
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                <svg className="w-3.5 h-3.5 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                Incident Summary
              </h3>
              <p className="text-sm text-gray-300 leading-relaxed">{INCIDENT.summary}</p>
            </div>

            <div className="bg-gray-900/60 border border-gray-700/50 rounded-lg p-4">
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                <svg className="w-3.5 h-3.5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>
                Affected Systems
              </h3>
              <div className="flex flex-wrap gap-2">
                {INCIDENT.affectedSystems.map(sys => (
                  <span key={sys} className="text-xs font-mono bg-gray-800/80 border border-gray-700/50 text-gray-300 px-2.5 py-1.5 rounded flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
                    {sys}
                  </span>
                ))}
              </div>
            </div>

            <div className="bg-gray-900/60 border border-gray-700/50 rounded-lg p-4">
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                <svg className="w-3.5 h-3.5 text-orange-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" /></svg>
                Attack Vectors
              </h3>
              <div className="flex flex-wrap gap-2">
                {INCIDENT.attackVectors.map((v, i) => (
                  <span key={v} className="text-xs bg-orange-900/30 border border-orange-500/30 text-orange-300 px-2.5 py-1 rounded-full flex items-center gap-1.5">
                    <span className="font-mono text-orange-500">{String(i + 1).padStart(2, '0')}</span>
                    {v}
                  </span>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-3 gap-3">
              {[
                { label: 'IOCs Identified', value: IOCS.length, color: 'text-red-400', sub: `${IOCS.filter(i => i.severity === 'critical').length} critical` },
                { label: 'Threat Correlations', value: CORRELATIONS.length, color: 'text-purple-400', sub: `${CORRELATIONS.filter(c => c.confidence >= 80).length} high confidence` },
                { label: 'Timeline Events', value: TIMELINE.length, color: 'text-cyan-400', sub: `${TIMELINE.filter(t => t.severity === 'critical').length} critical` },
              ].map(stat => (
                <div key={stat.label} className="bg-gray-900/60 border border-gray-700/50 rounded-lg p-3 text-center">
                  <div className={`text-2xl font-bold font-mono ${stat.color}`}>{stat.value}</div>
                  <div className="text-xs text-gray-400 mt-0.5">{stat.label}</div>
                  <div className="text-xs text-gray-600 mt-0.5">{stat.sub}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* IOCs Tab */}
        {activeTab === 'iocs' && (
          <div className="space-y-3">
            {/* IOC Type Filter */}
            <div className="flex gap-1.5 flex-wrap">
              <button
                onClick={() => setIocTypeFilter('all')}
                className={`px-2.5 py-1 rounded text-xs font-medium border transition-all ${iocTypeFilter === 'all' ? 'bg-gray-700 border-gray-500 text-gray-100' : 'bg-gray-800/50 border-gray-700/40 text-gray-500 hover:text-gray-300'}`}
              >
                All ({IOCS.length})
              </button>
              {Object.entries(iocTypeConfig).map(([type, cfg]) => {
                const count = IOCS.filter(i => i.type === type).length;
                if (!count) return null;
                return (
                  <button
                    key={type}
                    onClick={() => setIocTypeFilter(type)}
                    className={`px-2.5 py-1 rounded text-xs font-medium border transition-all flex items-center gap-1 ${iocTypeFilter === type ? `${cfg.color} border` : 'bg-gray-800/50 border-gray-700/40 text-gray-500 hover:text-gray-300'}`}
                  >
                    {cfg.icon} {cfg.label} ({count})
                  </button>
                );
              })}
            </div>

            {selectedIocs.length > 0 && (
              <div className="flex items-center justify-between bg-cyan-900/20 border border-cyan-500/30 rounded-lg px-3 py-2">
                <span className="text-xs text-cyan-400">{selectedIocs.length} IOC{selectedIocs.length > 1 ? 's' : ''} selected</span>
                <div className="flex gap-2">
                  <button className="text-xs bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-400 border border-cyan-500/40 px-2 py-1 rounded transition-all">Export</button>
                  <button className="text-xs bg-red-500/20 hover:bg-red-500/30 text-red-400 border border-red-500/40 px-2 py-1 rounded transition-all">Block All</button>
                </div>
              </div>
            )}

            <div className="space-y-2">
              {filteredIocs.map(ioc => {
                const typeCfg = iocTypeConfig[ioc.type];
                const sevCfg = severityConfig[ioc.severity];
                const isSelected = selectedIocs.includes(ioc.id);
                return (
                  <div
                    key={ioc.id}
                    className={`bg-gray-900/60 border border-l-2 ${sevCfg.border} rounded-lg p-3 transition-all cursor-pointer ${isSelected ? 'border-cyan-500/50 ring-1 ring-cyan-500/30' : 'border-gray-700/50 hover:border-gray-600/60'}`}
                    onClick={() => toggleIoc(ioc.id)}
                  >
                    <div className="flex items-start gap-2.5">
                      <div className={`flex-shrink-0 mt-0.5 w-4 h-4 rounded border transition-all ${isSelected ? 'bg-cyan-500/30 border-cyan-500/60' : 'border-gray-600'}`}>
                        {isSelected && <svg className="w-full h-full text-cyan-400 p-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" /></svg>}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap mb-1">
                          <span className={`text-xs font-medium px-1.5 py-0.5 rounded border flex items-center gap-1 ${typeCfg.color}`}>
                            {typeCfg.icon} {typeCfg.label}
                          </span>
                          <span className={`text-xs px-2 py-0.5 rounded-full border capitalize ${sevCfg.badge}`}>{ioc.severity}</span>
                          {ioc.verified && <span className="text-xs bg-green-900/30 text-green-400 border border-green-500/30 px-1.5 py-0.5 rounded flex items-center gap-1"><svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>Verified</span>}
                          <span className="text-xs text-gray-500 ml-auto">Confidence: <span className="text-cyan-400 font-mono">{ioc.confidence}%</span></span>
                        </div>
                        <div className="font-mono text-xs text-gray-200 truncate mb-1.5">{ioc.value}</div>
                        <div className="flex items-center gap-3 flex-wrap">
                          <span className="text-xs text-gray-600">Source: <span className="text-gray-400">{ioc.source}</span></span>
                          <span className="text-xs text-gray-600">Last: <span className="text-gray-400 font-mono">{ioc.lastSeen.split(' ')[1]}</span></span>
                          <div className="flex gap-1">
                            {ioc.tags.map(tag => (
                              <span key={tag} className="text-xs bg-gray-800/80 text-gray-500 border border-gray-700/40 px-1.5 py-0.5 rounded">{tag}</span>
                            ))}
                          </div>
                        </div>
                        <div className="mt-1.5 h-1 bg-gray-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full transition-all ${ioc.confidence >= 90 ? 'bg-red-500' : ioc.confidence >= 75 ? 'bg-orange-500' : 'bg-yellow-500'}`}
                            style={{ width: `${ioc.confidence}%` }}
                          />
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Correlations Tab */}
        {activeTab === 'correlations' && (
          <div className="space-y-3">
            {CORRELATIONS.map(corr => {
              const typeCfg = correlationTypeConfig[corr.type];
              const isExpanded = expandedCorrelation === corr.id;
              return (
                <div key={corr.id} className="bg-gray-900/60 border border-gray-700/50 rounded-lg overflow-hidden">
                  <button
                    className="w-full text-left p-4 hover:bg-gray-800/30 transition-all"
                    onClick={() => setExpandedCorrelation(isExpanded ? null : corr.id)}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 flex-wrap mb-1.5">
                          <span className={`text-xs font-semibold px-2 py-0.5 rounded border capitalize ${typeCfg.bg} ${typeCfg.color}`}>{corr.type}</span>
                          <span className="text-xs text-gray-500">
                            Confidence: <span className={`font-mono font-semibold ${corr.confidence >= 80 ? 'text-red-400' : corr.confidence >= 65 ? 'text-orange-400' : 'text-yellow-400'}`}>{corr.confidence}%</span>
                          </span>
                          <span className="text-xs text-gray-600">{corr.relatedIncidents} related incidents</span>
                        </div>
                        <h3 className="text-sm font-semibold text-gray-100">{corr.name}</h3>
                      </div>
                      <svg className={`w-4 h-4 text-gray-500 flex-shrink-0 mt-0.5 transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
                    </div>
                    <div className="mt-2 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full ${corr.confidence >= 80 ? 'bg-red-500' : corr.confidence >= 65 ? 'bg-orange-500' : 'bg-yellow-500'}`}
                        style={{ width: `${corr.confidence}%` }}
                      />
                    </div>
                  </button>
                  {isExpanded && (
                    <div className="px-4 pb-4 border-t border-gray-700/40 pt-3 space-y-3">
                      <p className="text-xs text-gray-400 leading-relaxed">{corr.description}</p>
                      <div>
                        <div className="text-xs text-gray-500 mb-1.5">MITRE ATT&CK Techniques</div>
                        <div className="flex flex-wrap gap-1.5">
                          {corr.mitreTechniques.map(t => (
                            <span key={t} className="text-xs font-mono bg-purple-900/30 text-purple-400 border border-purple-500/30 px-2 py-0.5 rounded">{t}</span>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* Timeline Tab */}
        {activeTab === 'timeline' && (
          <div className="relative">
            <div className="absolute left-[4.5rem] top-0 bottom-0 w-px bg-gray-700/50" />
            <div className="space-y-0">
              {TIMELINE.map((event, idx) => {
                const sevCfg = severityConfig[event.severity];
                return (
                  <div key={event.id} className="relative flex gap-4 pb-4">
                    <div className="w-16 flex-shrink-0 text-right">
                      <span className="text-xs font-mono text-gray-500">{event.timestamp}</span>
                    </div>
                    <div className="relative flex-shrink-0 flex items-start justify-center w-5 mt-0.5">
                      <div className={`w-2.5 h-2.5 rounded-full border-2 border-gray-900 z-10 ${sevCfg.dot} ${event.severity === 'critical' ? 'animate-pulse' : ''}`} />
                    </div>
                    <div className={`flex-1 bg-gray-900/50 border border-l-2 ${sevCfg.border} border-gray-700/40 rounded-lg p-3 ${idx === 0 ? '' : ''}`}>
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <span className={`text-xs px-2 py-0.5 rounded-full border capitalize ${sevCfg.badge}`}>{event.severity}</span>
                        <span className="text-xs text-gray-500 bg-gray-800/60 border border-gray-700/40 px-2 py-0.5 rounded">{event.source}</span>
                      </div>
                      <p className="text-xs text-gray-300 leading-relaxed">{event.event}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default InvestigationPanel;
 