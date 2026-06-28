import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  ShieldAlert,
  Brain,
  Target,
  Clock,
  ArrowRight,
} from 'lucide-react';
import { useStore } from '../lib/store';
import { getSeverityColor, getSeverityBg, getStatusColor, getThreatTypeLabel } from '../lib/seedData';
import { MITRE_TECHNIQUES } from '../lib/mitreData';

export function IncidentDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const incidents = useStore(s => s.incidents);
  const alerts = useStore(s => s.alerts);
  const mitreMappings = useStore(s => s.mitreMappings);
  const iocs = useStore(s => s.iocs);
  const incident = incidents.find(i => i.id === id);

  const relatedAlerts = alerts.filter(a => a.incident_id === id);
  const relatedMitre = mitreMappings.filter(m => m.incident_id === id);
  const relatedIOCs = iocs.filter(i => i.incident_id === id);

  if (!incident) {
    return <div className="flex items-center justify-center h-64"><p className="text-slate-500">Incident not found</p></div>;
  }

  const relatedTechniques = relatedMitre.length > 0
    ? relatedMitre
    : MITRE_TECHNIQUES.filter(t =>
        incident.attack_vector?.toLowerCase().includes('brute') && (t.id.startsWith('T1110') || t.id === 'T1078') ||
        incident.attack_vector?.toLowerCase().includes('sql') && (t.id === 'T1190' || t.id.startsWith('T1071')) ||
        incident.attack_vector?.toLowerCase().includes('phishing') && (t.id === 'T1566' || t.id.startsWith('T1078')) ||
        incident.attack_vector?.toLowerCase().includes('ransomware') && (t.id.startsWith('T1486') || t.id === 'T1490') ||
        incident.attack_vector?.toLowerCase().includes('lateral') && t.id.startsWith('T1021') ||
        incident.attack_vector?.toLowerCase().includes('credential') && (t.id.startsWith('T1003') || t.id.startsWith('T1110'))
      ).slice(0, 5);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <button onClick={() => navigate('/incidents')} className="rounded-lg p-2 text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition-colors">
          <ArrowLeft className="h-5 w-5" />
        </button>
        <div className="flex-1">
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold text-white">{incident.title}</h1>
            <span className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-semibold ${getSeverityBg(incident.severity)} ${getSeverityColor(incident.severity)}`}>
              {incident.severity.toUpperCase()}
            </span>
            <span className={`text-xs font-medium capitalize ${getStatusColor(incident.status)}`}>{incident.status}</span>
          </div>
          <p className="mt-1 text-sm text-slate-400">{incident.attack_vector}</p>
        </div>
        <button
          onClick={() => navigate(`/ai-assistant?incident=${incident.id}`)}
          className="flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-500 transition-colors"
        >
          <Brain className="h-4 w-4" />
          Analyze with Microsoft Foundry IQ
          <ArrowRight className="h-4 w-4" />
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
          <p className="text-xs text-slate-500">Impact Score</p>
          <div className="mt-1 flex items-center gap-2">
            <p className="text-2xl font-bold text-white">{incident.impact_score}</p>
            <span className="text-xs text-slate-500">/10</span>
          </div>
          <div className="mt-2 h-1.5 w-full rounded-full bg-slate-800">
            <div className={`h-full rounded-full ${incident.impact_score >= 8 ? 'bg-red-500' : incident.impact_score >= 5 ? 'bg-orange-500' : 'bg-yellow-500'}`} style={{ width: `${incident.impact_score * 10}%` }} />
          </div>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
          <p className="text-xs text-slate-500">Related Alerts</p>
          <p className="mt-1 text-2xl font-bold text-white">{relatedAlerts.length}</p>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
          <p className="text-xs text-slate-500">MITRE TTPs</p>
          <p className="mt-1 text-2xl font-bold text-cyan-400">{relatedTechniques.length}</p>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
          <p className="text-xs text-slate-500">IOCs</p>
          <p className="mt-1 text-2xl font-bold text-orange-400">{relatedIOCs.length}</p>
        </div>
      </div>

      {incident.ai_summary && (
        <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-5">
          <div className="flex items-center gap-2 mb-2">
            <Brain className="h-5 w-5 text-cyan-400" />
            <h3 className="text-sm font-semibold text-cyan-400">Foundry IQ Analysis Summary</h3>
          </div>
          <p className="text-sm text-slate-300 leading-relaxed">{incident.ai_summary}</p>
        </div>
      )}

      {incident.description && (
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <h3 className="mb-2 text-sm font-semibold text-slate-300">Description</h3>
          <p className="text-sm text-slate-400 leading-relaxed">{incident.description}</p>
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <div className="flex items-center gap-2 mb-4">
            <Clock className="h-4 w-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-300">Alert Timeline</h3>
          </div>
          <div className="relative space-y-0">
            {relatedAlerts.map((alert, i) => (
              <div key={alert.id} className="relative flex gap-4 pb-4">
                <div className="flex flex-col items-center">
                  <div className={`h-3 w-3 rounded-full border-2 flex-shrink-0 ${
                    alert.severity === 'critical' ? 'border-red-500 bg-red-500' :
                    alert.severity === 'high' ? 'border-orange-500 bg-orange-500' : 'border-yellow-500 bg-yellow-500'
                  }`} />
                  {i < relatedAlerts.length - 1 && <div className="w-px flex-1 bg-slate-700 mt-1" />}
                </div>
                <div className="flex-1 pb-2">
                  <p className="text-sm text-slate-200">{alert.title}</p>
                  <div className="mt-1 flex items-center gap-2 text-xs text-slate-500">
                    <span className={getSeverityColor(alert.severity)}>{alert.severity}</span>
                    <span>{getThreatTypeLabel(alert.threat_type)}</span>
                  </div>
                </div>
              </div>
            ))}
            {relatedAlerts.length === 0 && <p className="text-sm text-slate-500">No linked alerts</p>}
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <div className="flex items-center gap-2 mb-4">
            <Target className="h-4 w-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-300">MITRE ATT&CK Mappings</h3>
          </div>
          <div className="space-y-2">
            {relatedTechniques.map(tech => (
              <div key={tech.technique_id || tech.id} className="rounded-lg border border-slate-800 bg-slate-800/30 p-3 hover:bg-slate-800/60 transition-colors">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="rounded bg-cyan-500/20 px-1.5 py-0.5 text-xs font-mono font-bold text-cyan-400">{tech.technique_id || tech.id}</span>
                    <span className="text-sm text-slate-200">{tech.technique_name || tech.name}</span>
                  </div>
                  <span className="text-xs text-slate-500">{tech.tactic}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
