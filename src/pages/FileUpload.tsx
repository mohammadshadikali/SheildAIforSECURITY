import { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Upload,
  FileText,
  AlertTriangle,
  Shield,
  Brain,
  Loader2,
  Trash2,
  ArrowRight,
  CheckCircle2,
} from 'lucide-react';
import { store } from '../lib/store';
import { analyzeLogs, type ThreatDetectionResult } from '../lib/threatDetection';
import { DEMO_SAMPLE_LOGS, getSeverityColor, getThreatTypeLabel } from '../lib/seedData';

interface UploadedFile {
  name: string;
  size: number;
  type: string;
  content: string;
}

export function FileUpload() {
  const navigate = useNavigate();
  const [dragActive, setDragActive] = useState(false);
  const [file, setFile] = useState<UploadedFile | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [results, setResults] = useState<ThreatDetectionResult[]>([]);
  const [logContent, setLogContent] = useState(DEMO_SAMPLE_LOGS);
  const [createdIncidents, setCreatedIncidents] = useState<Array<{ id: string; title: string }>>([]);

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') setDragActive(true);
    else if (e.type === 'dragleave') setDragActive(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile) processFile(droppedFile);
  }, []);

  const processFile = (f: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      setFile({ name: f.name, size: f.size, type: f.type, content });
      setLogContent(content);
      setResults([]);
      setCreatedIncidents([]);
    };
    reader.readAsText(f);
  };

  const handleAnalyze = async () => {
    setAnalyzing(true);
    setResults([]);
    setCreatedIncidents([]);

    await new Promise(r => setTimeout(r, 1500));

    const detectionResults = analyzeLogs(logContent);
    setResults(detectionResults);

    // Create alerts and incidents for each detected threat
    const newIncidents: Array<{ id: string; title: string }> = [];

    for (const result of detectionResults) {
      // Create alert
      const alert = await store.createAlert({
        title: result.title,
        source: 'Log Upload Analysis',
        severity: result.severity,
        status: 'new',
        threat_type: result.threatType,
        confidence: result.confidence,
        raw_payload: { iocs: result.iocs, mitre: result.mitreTechniques },
      });

      // Auto-create incident for significant threats
      if (result.severity === 'critical' || result.severity === 'high' || result.severity === 'medium') {
        const incident = await store.createIncident({
          title: result.title,
          description: result.description,
          severity: result.severity,
          status: 'open',
          attack_vector: `Detected via log analysis - ${getThreatTypeLabel(result.threatType)}`,
          impact_score: result.severity === 'critical' ? 9 : result.severity === 'high' ? 7 : 5,
          ai_summary: result.description,
        });

        // Link alert to incident
        await store.linkAlertToIncident(alert.id, incident.id);

        // Create IOCs
        for (const ioc of result.iocs) {
          await store.createIOC({
            incident_id: incident.id,
            alert_id: alert.id,
            type: ioc.type === 'hash' ? 'other' as const : ioc.type as any,
            value: ioc.value,
            reputation: ioc.reputation as any,
            enrichment_data: {},
          });
        }

        // Create MITRE mappings
        for (const tech of result.mitreTechniques) {
          await store.createMitreMapping({
            incident_id: incident.id,
            technique_id: tech.id,
            technique_name: tech.name,
            tactic: tech.tactic,
            confidence: result.confidence,
            reasoning: `Auto-mapped by Foundry IQ from ${getThreatTypeLabel(result.threatType)} detection`,
            mapped_by: 'foundry-iq-agent',
          });
        }

        newIncidents.push({ id: incident.id, title: incident.title });
      }
    }

    // Log the upload
    try {
      await store.createAlert({
        title: `Log Analysis Complete - ${detectionResults.length} threats found`,
        source: 'System',
        severity: detectionResults.some(r => r.severity === 'critical') ? 'high' : 'info',
        status: 'closed',
        threat_type: 'analysis_complete',
        confidence: 1.0,
        raw_payload: { threats: detectionResults.length, types: detectionResults.map(r => r.threatType), filename: file?.name },
      });
    } catch {}

    setCreatedIncidents(newIncidents);
    setAnalyzing(false);
  };

  const loadSampleLogs = () => {
    setLogContent(DEMO_SAMPLE_LOGS);
    setFile({ name: 'sample-security-logs.json', size: DEMO_SAMPLE_LOGS.length, type: 'application/json', content: DEMO_SAMPLE_LOGS });
    setResults([]);
    setCreatedIncidents([]);
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Log Upload & Analysis</h1>
        <p className="text-sm text-slate-400 mt-1">Upload security logs for automated threat detection and incident creation</p>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Upload Area */}
        <div className="space-y-4">
          <div
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            className={`relative rounded-xl border-2 border-dashed p-8 text-center transition-all ${
              dragActive
                ? 'border-cyan-400 bg-cyan-500/10'
                : 'border-slate-700 bg-slate-900 hover:border-slate-600'
            }`}
          >
            <Upload className={`mx-auto h-10 w-10 ${dragActive ? 'text-cyan-400' : 'text-slate-500'} transition-colors`} />
            <p className="mt-3 text-sm text-slate-300">Drag & drop log files here</p>
            <p className="mt-1 text-xs text-slate-500">JSON, CSV, or plain text log files</p>
            <input
              type="file"
              accept=".json,.csv,.txt,.log"
              onChange={e => e.target.files?.[0] && processFile(e.target.files[0])}
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
            />
          </div>

          {file && (
            <div className="rounded-lg border border-slate-700 bg-slate-800/50 p-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileText className="h-4 w-4 text-cyan-400" />
                  <span className="text-sm text-slate-200">{file.name}</span>
                  <span className="text-xs text-slate-500">({(file.size / 1024).toFixed(1)} KB)</span>
                </div>
                <button onClick={() => { setFile(null); setResults([]); setCreatedIncidents([]); }} className="text-slate-500 hover:text-slate-300">
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            </div>
          )}

          {/* Log Content Editor */}
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-slate-300">Log Content</h3>
              <button onClick={loadSampleLogs} className="text-xs text-cyan-400 hover:text-cyan-300">
                Load sample logs
              </button>
            </div>
            <textarea
              value={logContent}
              onChange={e => { setLogContent(e.target.value); setResults([]); setCreatedIncidents([]); }}
              rows={12}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs font-mono text-slate-300 placeholder-slate-600 outline-none focus:border-cyan-500/50 resize-none"
              placeholder="Paste log content here or upload a file..."
            />
          </div>

          <button
            onClick={handleAnalyze}
            disabled={analyzing || !logContent.trim()}
            className="w-full flex items-center justify-center gap-2 rounded-lg bg-cyan-600 px-4 py-3 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {analyzing ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Analyzing with Microsoft Foundry IQ...
              </>
            ) : (
              <>
                <Brain className="h-4 w-4" />
                Analyze with Microsoft Foundry IQ
              </>
            )}
          </button>
        </div>

        {/* Results */}
        <div className="space-y-4">
          {results.length === 0 && !analyzing && (
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-8 text-center">
              <Shield className="mx-auto h-12 w-12 text-slate-600" />
              <p className="mt-3 text-sm text-slate-400">Upload logs and run analysis to detect threats</p>
              <p className="mt-1 text-xs text-slate-600">Detects: Brute Force, SQL Injection, Suspicious Logins</p>
              <p className="mt-1 text-xs text-slate-600">Detected threats automatically create incidents</p>
            </div>
          )}

          {analyzing && (
            <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-8 text-center">
              <Loader2 className="mx-auto h-10 w-10 animate-spin text-cyan-400" />
              <p className="mt-3 text-sm text-cyan-400">Running Foundry IQ threat detection agents...</p>
              <p className="mt-1 text-xs text-slate-500">Analyzing patterns, extracting IOCs, mapping MITRE TTPs, creating incidents</p>
            </div>
          )}

          {/* Created Incidents Banner */}
          {createdIncidents.length > 0 && (
            <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-5">
              <div className="flex items-center gap-2 mb-3">
                <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                <h3 className="text-sm font-semibold text-emerald-400">{createdIncidents.length} Incidents Auto-Created</h3>
              </div>
              <div className="space-y-2">
                {createdIncidents.map(inc => (
                  <button
                    key={inc.id}
                    onClick={() => navigate(`/ai-assistant?incident=${inc.id}`)}
                    className="w-full flex items-center justify-between rounded-lg border border-slate-700 bg-slate-800/50 px-4 py-2.5 text-left hover:bg-slate-800 transition-colors group"
                  >
                    <div className="flex items-center gap-2">
                      <Shield className="h-4 w-4 text-emerald-400" />
                      <span className="text-sm text-slate-200">{inc.title}</span>
                    </div>
                    <div className="flex items-center gap-2 text-xs text-cyan-400 opacity-0 group-hover:opacity-100 transition-opacity">
                      <span>Analyze with Foundry IQ</span>
                      <ArrowRight className="h-3 w-3" />
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {results.map((result, i) => (
            <div key={i} className="rounded-xl border border-slate-800 bg-slate-900 p-5">
              <div className="flex items-start gap-3">
                <div className={`flex-shrink-0 rounded-lg p-2 ${
                  result.severity === 'critical' ? 'bg-red-500/20' :
                  result.severity === 'high' ? 'bg-orange-500/20' :
                  result.severity === 'medium' ? 'bg-yellow-500/20' : 'bg-blue-500/20'
                }`}>
                  <AlertTriangle className={`h-5 w-5 ${getSeverityColor(result.severity)}`} />
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-semibold text-white">{result.title}</h3>
                    <span className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold ${getSeverityColor(result.severity)}`}>
                      {result.severity.toUpperCase()}
                    </span>
                    {createdIncidents.find(ci => ci.title === result.title) && (
                      <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-400">
                        INCIDENT CREATED
                      </span>
                    )}
                  </div>
                  <p className="mt-1 text-xs text-slate-400 leading-relaxed">{result.description}</p>

                  <div className="mt-3 flex items-center gap-4 text-xs">
                    <span className="text-slate-500">Type: <span className="text-cyan-400">{getThreatTypeLabel(result.threatType)}</span></span>
                    <span className="text-slate-500">Confidence: <span className="text-cyan-400">{(result.confidence * 100).toFixed(0)}%</span></span>
                  </div>

                  {result.iocs.length > 0 && (
                    <div className="mt-3">
                      <p className="text-xs font-semibold text-slate-500 mb-1.5">Indicators of Compromise</p>
                      <div className="flex flex-wrap gap-1.5">
                        {result.iocs.map((ioc, j) => (
                          <span key={j} className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[10px] font-mono ${
                            ioc.reputation === 'malicious' ? 'border-red-500/40 bg-red-500/10 text-red-400' :
                            ioc.reputation === 'suspicious' ? 'border-orange-500/40 bg-orange-500/10 text-orange-400' :
                            'border-slate-600 bg-slate-800 text-slate-400'
                          }`}>
                            {ioc.type.toUpperCase()}: {ioc.value}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {result.mitreTechniques.length > 0 && (
                    <div className="mt-3">
                      <p className="text-xs font-semibold text-slate-500 mb-1.5">MITRE ATT&CK TTPs</p>
                      <div className="space-y-1">
                        {result.mitreTechniques.map((tech, j) => (
                          <div key={j} className="flex items-center gap-2 text-xs">
                            <span className="rounded bg-cyan-500/20 px-1.5 py-0.5 font-mono font-bold text-cyan-400">{tech.id}</span>
                            <span className="text-slate-300">{tech.name}</span>
                            <span className="text-slate-600">({tech.tactic})</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Navigate to AI Assistant */}
                  {createdIncidents.find(ci => ci.title === result.title) && (
                    <button
                      onClick={() => {
                        const inc = createdIncidents.find(ci => ci.title === result.title);
                        if (inc) navigate(`/ai-assistant?incident=${inc.id}`);
                      }}
                      className="mt-3 flex items-center gap-2 rounded-lg bg-cyan-600/20 border border-cyan-500/30 px-3 py-1.5 text-xs font-medium text-cyan-400 hover:bg-cyan-600/30 transition-colors"
                    >
                      <Brain className="h-3 w-3" />
                      Analyze with Microsoft Foundry IQ
                      <ArrowRight className="h-3 w-3" />
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
