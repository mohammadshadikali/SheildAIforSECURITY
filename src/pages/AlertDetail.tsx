import { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  ArrowLeft,
  Shield,
  AlertTriangle,
  Brain,
  Target,
  Clock,
  ArrowRight,
} from 'lucide-react';
import { store, useStore } from '../lib/store';
import { getSeverityColor, getSeverityBg, getStatusColor, getThreatTypeLabel } from '../lib/seedData';
import { MITRE_TECHNIQUES } from '../lib/mitreData';

export function AlertDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const alerts = useStore(s => s.alerts);
  const [triaging, setTriaging] = useState(false);
  const [triageResult, setTriageResult] = useState<string | null>(null);

  const alert = alerts.find(a => a.id === id);

  const handleTriage = async () => {
    setTriaging(true);
    await new Promise(r => setTimeout(r, 2000));
    setTriageResult('Foundry IQ triage complete. Alert classified and MITRE TTPs mapped. Confidence: High.');
    if (alert) {
      const idx = store.alerts.findIndex(a => a.id === alert.id);
      if (idx >= 0) {
        store.alerts[idx].status = 'triaged';
      }
    }
    setTriaging(false);
  };

  if (!alert) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-slate-500">Alert not found</p>
      </div>
    );
  }

  const relatedTechniques = MITRE_TECHNIQUES.filter(t =>
    alert.threat_type === 'brute_force' && (t.id.startsWith('T1110') || t.id === 'T1078') ||
    alert.threat_type === 'sql_injection' && (t.id === 'T1190' || t.id.startsWith('T1071')) ||
    alert.threat_type === 'suspicious_login' && (t.id === 'T1078' || t.id.startsWith('T1110')) ||
    alert.threat_type === 'c2_communication' && (t.id.startsWith('T1071') || t.id === 'T1573') ||
    alert.threat_type === 'privilege_escalation' && (t.id.startsWith('T1548') || t.id === 'T1068') ||
    alert.threat_type === 'credential_dumping' && (t.id.startsWith('T1003') || t.id === 'T1555') ||
    alert.threat_type === 'exfiltration' && (t.id.startsWith('T1041') || t.id === 'T1048') ||
    alert.threat_type === 'ransomware' && (t.id.startsWith('T1486') || t.id === 'T1489' || t.id === 'T1490') ||
    alert.threat_type === 'lateral_movement' && (t.id.startsWith('T1021')) ||
    alert.threat_type === 'phishing' && (t.id === 'T1566') ||
    alert.threat_type === 'persistence' && (t.id.startsWith('T1053') || t.id.startsWith('T1547')) ||
    alert.threat_type === 'execution' && (t.id.startsWith('T1059'))
  ).slice(0, 5);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <button onClick={() => navigate('/alerts')} className="rounded-lg p-2 text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition-colors">
          <ArrowLeft className="h-5 w-5" />
        </button>
        <div className="flex-1">
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold text-white">{alert.title}</h1>
            <span className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-semibold ${getSeverityBg(alert.severity)} ${getSeverityColor(alert.severity)}`}>
              {alert.severity.toUpperCase()}
            </span>
          </div>
          <p className="mt-1 text-sm text-slate-400">Source: {alert.source} | ID: {alert.id}</p>
        </div>
        <button
          onClick={handleTriage}
          disabled={triaging}
          className="flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          <Brain className="h-4 w-4" />
          {triaging ? 'Analyzing...' : alert.status === 'triaged' ? 'Re-Analyze with Foundry IQ' : 'Analyze with Microsoft Foundry IQ'}
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
          <p className="text-xs text-slate-500 mb-1">Status</p>
          <p className={`text-lg font-semibold capitalize ${getStatusColor(alert.status)}`}>{alert.status}</p>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
          <p className="text-xs text-slate-500 mb-1">Confidence</p>
          <div className="flex items-center gap-2">
            <div className="h-2 flex-1 rounded-full bg-slate-700">
              <div className="h-full rounded-full bg-cyan-400" style={{ width: `${alert.confidence * 100}%` }} />
            </div>
            <span className="text-sm font-medium text-slate-200">{(alert.confidence * 100).toFixed(0)}%</span>
          </div>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
          <p className="text-xs text-slate-500 mb-1">Threat Type</p>
          <p className="text-lg font-semibold text-cyan-400">{getThreatTypeLabel(alert.threat_type)}</p>
        </div>
      </div>

      {triageResult && (
        <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/5 p-5">
          <div className="flex items-center gap-2 mb-2">
            <Brain className="h-5 w-5 text-cyan-400" />
            <h3 className="text-sm font-semibold text-cyan-400">Foundry IQ Triage Result</h3>
          </div>
          <p className="text-sm text-slate-300">{triageResult}</p>
        </div>
      )}

      {triaging && (
        <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-5">
          <div className="flex items-center gap-3">
            <div className="h-5 w-5 animate-spin rounded-full border-2 border-cyan-400 border-t-transparent" />
            <p className="text-sm text-cyan-400">Foundry IQ agent analyzing alert patterns...</p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <h3 className="mb-3 text-sm font-semibold text-slate-300">Raw Alert Payload</h3>
          <pre className="overflow-x-auto rounded-lg bg-slate-950 p-4 text-xs text-slate-300 font-mono leading-relaxed">
            {JSON.stringify(alert.raw_payload, null, 2)}
          </pre>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <div className="flex items-center gap-2 mb-3">
            <Target className="h-4 w-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-300">MITRE ATT&CK Mappings</h3>
          </div>
          <div className="space-y-2">
            {relatedTechniques.map(tech => (
              <div key={tech.id} className="rounded-lg border border-slate-800 bg-slate-800/30 p-3 hover:bg-slate-800/60 transition-colors">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="rounded bg-cyan-500/20 px-1.5 py-0.5 text-xs font-mono font-bold text-cyan-400">{tech.id}</span>
                    <span className="text-sm text-slate-200">{tech.name}</span>
                  </div>
                  <span className="text-xs text-slate-500">{tech.tactic}</span>
                </div>
                <p className="mt-1 text-xs text-slate-500">{tech.description}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {alert.raw_payload && (
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <h3 className="mb-3 text-sm font-semibold text-slate-300">Extracted Indicators of Compromise</h3>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {Object.entries(alert.raw_payload).map(([key, value]) => {
              const strVal = String(value);
              const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(strVal);
              const isURL = /^https?:\/\//.test(strVal);
              const isHash = /^[a-f0-9]{32,64}$/i.test(strVal);
              const isIOC = isIP || isURL || isHash || key.includes('ip') || key.includes('domain') || key.includes('hash') || key.includes('url');
              if (!isIOC) return null;
              return (
                <div key={key} className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-800/30 px-3 py-2">
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-slate-500">{key.replace(/_/g, ' ')}</p>
                    <p className="text-sm font-mono text-slate-200">{strVal}</p>
                  </div>
                  <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${
                    isIP ? 'bg-red-500/20 text-red-400' : isURL ? 'bg-orange-500/20 text-orange-400' : isHash ? 'bg-yellow-500/20 text-yellow-400' : 'bg-slate-500/20 text-slate-400'
                  }`}>
                    {isIP ? 'IP' : isURL ? 'URL' : isHash ? 'HASH' : 'IOC'}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
