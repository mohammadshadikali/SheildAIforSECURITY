import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  Plus,
  ChevronDown,
  Search,
  Brain,
  ArrowRight,
} from 'lucide-react';
import { store, useStore, type IncidentRecord } from '../lib/store';
import { getSeverityColor, getSeverityBg, getStatusColor } from '../lib/seedData';

export function IncidentList() {
  const navigate = useNavigate();
  const incidents = useStore(s => s.incidents);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');
  const [showCreate, setShowCreate] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newSeverity, setNewSeverity] = useState('medium');

  const handleCreate = async () => {
    if (!newTitle.trim()) return;
    await store.createIncident({
      title: newTitle,
      description: newDesc,
      severity: newSeverity as IncidentRecord['severity'],
      status: 'open',
      attack_vector: 'Manual creation',
      impact_score: newSeverity === 'critical' ? 9 : newSeverity === 'high' ? 7 : 5,
      ai_summary: '',
    });
    setShowCreate(false);
    setNewTitle('');
    setNewDesc('');
    setNewSeverity('medium');
  };

  const filtered = incidents.filter(i => {
    if (filterSeverity !== 'all' && i.severity !== filterSeverity) return false;
    if (filterStatus !== 'all' && i.status !== filterStatus) return false;
    return true;
  });

  const handleAnalyze = (e: React.MouseEvent, incidentId: string) => {
    e.stopPropagation();
    navigate(`/ai-assistant?incident=${incidentId}`);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Incidents</h1>
          <p className="text-sm text-slate-400 mt-1">{filtered.length} incidents tracked</p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-500 transition-colors"
        >
          <Plus className="h-4 w-4" />
          Create Incident
        </button>
      </div>

      {/* Create Incident Modal */}
      {showCreate && (
        <div className="rounded-xl border border-cyan-500/30 bg-slate-900 p-5">
          <h3 className="text-sm font-semibold text-cyan-400 mb-4">Create New Incident</h3>
          <div className="space-y-3">
            <input
              type="text"
              value={newTitle}
              onChange={e => setNewTitle(e.target.value)}
              placeholder="Incident title"
              className="w-full rounded-lg border border-slate-700 bg-slate-800/50 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 outline-none focus:border-cyan-500/50"
            />
            <textarea
              value={newDesc}
              onChange={e => setNewDesc(e.target.value)}
              placeholder="Description"
              rows={3}
              className="w-full rounded-lg border border-slate-700 bg-slate-800/50 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 outline-none focus:border-cyan-500/50 resize-none"
            />
            <div className="flex items-center gap-3">
              <select
                value={newSeverity}
                onChange={e => setNewSeverity(e.target.value)}
                className="appearance-none rounded-lg border border-slate-700 bg-slate-800/50 px-3 py-2 text-sm text-slate-200 outline-none focus:border-cyan-500/50 cursor-pointer"
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <button onClick={handleCreate} className="rounded-lg bg-cyan-600 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-500 transition-colors">
                Create
              </button>
              <button onClick={() => setShowCreate(false)} className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-400 hover:text-slate-200 transition-colors">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative">
          <select
            value={filterSeverity}
            onChange={e => setFilterSeverity(e.target.value)}
            className="appearance-none rounded-lg border border-slate-700 bg-slate-800/50 py-2 pl-3 pr-8 text-sm text-slate-200 outline-none focus:border-cyan-500/50 cursor-pointer"
          >
            <option value="all">All Severity</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <ChevronDown className="absolute right-2 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400 pointer-events-none" />
        </div>
        <div className="relative">
          <select
            value={filterStatus}
            onChange={e => setFilterStatus(e.target.value)}
            className="appearance-none rounded-lg border border-slate-700 bg-slate-800/50 py-2 pl-3 pr-8 text-sm text-slate-200 outline-none focus:border-cyan-500/50 cursor-pointer"
          >
            <option value="all">All Status</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="contained">Contained</option>
            <option value="resolved">Resolved</option>
            <option value="closed">Closed</option>
          </select>
          <ChevronDown className="absolute right-2 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400 pointer-events-none" />
        </div>
      </div>

      {/* Incident Cards */}
      <div className="grid grid-cols-1 gap-4">
        {filtered.map(incident => (
          <div
            key={incident.id}
            className="group rounded-xl border border-slate-800 bg-slate-900 p-5 hover:border-slate-700 hover:bg-slate-900/80 transition-all"
          >
            <div className="flex items-start justify-between">
              <div className="flex-1 cursor-pointer" onClick={() => navigate(`/ai-assistant?incident=${incident.id}`)}>
                <div className="flex items-center gap-3">
                  <ShieldAlert className="h-5 w-5 text-slate-500 group-hover:text-cyan-400 transition-colors" />
                  <h3 className="text-base font-semibold text-slate-200 group-hover:text-white transition-colors">{incident.title}</h3>
                </div>
                {incident.description && (
                  <p className="mt-2 text-sm text-slate-400 line-clamp-2">{incident.description}</p>
                )}
              </div>
              <div className="flex items-center gap-2 ml-4">
                <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold ${getSeverityBg(incident.severity)} ${getSeverityColor(incident.severity)}`}>
                  {incident.severity.toUpperCase()}
                </span>
                <span className={`text-xs font-medium capitalize ${getStatusColor(incident.status)}`}>
                  {incident.status}
                </span>
              </div>
            </div>

            <div className="mt-3 flex items-center justify-between">
              <div className="flex items-center gap-6 text-xs text-slate-500">
                <span>Impact: {incident.impact_score}/10</span>
                <span className="capitalize">{incident.attack_vector || 'Unknown vector'}</span>
                <span>{new Date(incident.created_at).toLocaleString()}</span>
              </div>
              <button
                onClick={(e) => handleAnalyze(e, incident.id)}
                className="flex items-center gap-1.5 rounded-lg bg-cyan-600/20 border border-cyan-500/30 px-3 py-1.5 text-xs font-medium text-cyan-400 hover:bg-cyan-600/30 transition-colors opacity-0 group-hover:opacity-100"
              >
                <Brain className="h-3 w-3" />
                Analyze with Microsoft Foundry IQ
                <ArrowRight className="h-3 w-3" />
              </button>
            </div>

            <div className="mt-2">
              <div className="h-1 w-full rounded-full bg-slate-800">
                <div
                  className={`h-full rounded-full transition-all ${
                    incident.severity === 'critical' ? 'bg-red-500' :
                    incident.severity === 'high' ? 'bg-orange-500' :
                    incident.severity === 'medium' ? 'bg-yellow-500' : 'bg-blue-500'
                  }`}
                  style={{ width: `${incident.impact_score * 10}%` }}
                />
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
