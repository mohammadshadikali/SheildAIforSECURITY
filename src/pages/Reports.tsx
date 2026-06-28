import { useState, useMemo } from 'react';
import {
  FileText,
  Download,
  Eye,
} from 'lucide-react';
import { useStore, store, type ReportRecord } from '../lib/store';
import { generateIncidentReport } from '../lib/threatDetection';
import { MITRE_TECHNIQUES } from '../lib/mitreData';

export function Reports() {
  const reports = useStore(s => s.reports);
  const incidents = useStore(s => s.incidents);
  const alerts = useStore(s => s.alerts);
  const iocs = useStore(s => s.iocs);
  const mitreMappings = useStore(s => s.mitreMappings);
  const [previewReport, setPreviewReport] = useState<ReportRecord | null>(null);

  const displayReports = useMemo<ReportRecord[]>(() => {
    if (reports.length > 0) return reports;

    return incidents.map(incident => {
      const relatedAlerts = alerts.filter(a => a.incident_id === incident.id);
      const relatedIOCs = iocs.filter(i => i.incident_id === incident.id);
      const relatedMitre = mitreMappings.filter(m => m.incident_id === incident.id);

      const mitreForReport = relatedMitre.length > 0
        ? relatedMitre.map(m => ({ technique_id: m.technique_id, technique_name: m.technique_name, tactic: m.tactic, confidence: m.confidence }))
        : MITRE_TECHNIQUES.filter(t =>
            incident.attack_vector?.toLowerCase().includes('brute') && (t.id.startsWith('T1110') || t.id === 'T1078') ||
            incident.attack_vector?.toLowerCase().includes('sql') && (t.id === 'T1190') ||
            incident.attack_vector?.toLowerCase().includes('phishing') && (t.id === 'T1566' || t.id.startsWith('T1078')) ||
            incident.attack_vector?.toLowerCase().includes('ransomware') && (t.id.startsWith('T1486') || t.id === 'T1490') ||
            incident.attack_vector?.toLowerCase().includes('lateral') && t.id.startsWith('T1021') ||
            incident.attack_vector?.toLowerCase().includes('credential') && (t.id.startsWith('T1003') || t.id.startsWith('T1110'))
          ).slice(0, 4).map(t => ({ ...t, confidence: 0.8 }));

      const content = generateIncidentReport(
        incident,
        relatedAlerts.map(a => ({ title: a.title, threat_type: a.threat_type, raw_payload: a.raw_payload })),
        relatedIOCs.map(i => ({ type: i.type, value: i.value, reputation: i.reputation })),
        mitreForReport,
      );

      return {
        id: `report-auto-${incident.id}`,
        incident_id: incident.id,
        report_type: 'full' as const,
        content_json: content,
        generated_at: incident.updated_at || incident.created_at,
      };
    });
  }, [reports, incidents, alerts, iocs, mitreMappings]);

  const handleExport = (report: typeof reports[0]) => {
    const blob = new Blob([JSON.stringify(report.content_json, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `report-${report.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportText = (report: ReportRecord) => {
    const c = report.content_json;
    const text = `
INCIDENT REPORT
===============
Generated: ${c.generated_at || report.generated_at}
Type: ${report.report_type.toUpperCase()}

EXECUTIVE SUMMARY
-----------------
${c.executive_summary || 'N/A'}

ATTACK NARRATIVE
----------------
${c.attack_narrative || 'N/A'}

INDICATORS OF COMPROMISE
------------------------
${Array.isArray(c.iocs) ? (c.iocs as Array<{type: string; value: string; reputation: string}>).map((ioc: any) => `  [${ioc.type.toUpperCase()}] ${ioc.value} - ${ioc.reputation}`).join('\n') : 'None'}

MITRE ATT&CK COVERAGE
---------------------
${Array.isArray(c.mitre_coverage) ? (c.mitre_coverage as Array<{technique_id: string; technique_name: string; tactic: string; confidence: number}>).map((m: any) => `  ${m.technique_id} - ${m.technique_name} (${m.tactic}) [${(m.confidence * 100).toFixed(0)}%]`).join('\n') : 'None'}

RECOMMENDATIONS
---------------
${Array.isArray(c.recommendations) ? (c.recommendations as Array<{priority: string; action: string; owner: string}>).map((r: any, i: number) => `  ${i + 1}. [${r.priority}] ${r.action} (Owner: ${r.owner})`).join('\n') : 'None'}

Classification: ${c.data_classification || 'CONFIDENTIAL'}
    `.trim();

    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `report-${report.id}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Incident Reports</h1>
        <p className="text-sm text-slate-400 mt-1">{displayReports.length} reports generated</p>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/50">
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Report</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Incident</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Type</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Generated</th>
                <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-wider text-slate-400">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {displayReports.map(report => {
                const incident = incidents.find(i => i.id === report.incident_id);
                return (
                  <tr key={report.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <FileText className="h-4 w-4 text-cyan-400" />
                        <span className="text-sm text-slate-200">{report.id.slice(0, 8)}...</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm text-slate-300 max-w-xs truncate">{incident?.title || 'Unknown'}</td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex rounded-md border px-2 py-0.5 text-xs font-semibold ${
                        report.report_type === 'executive' ? 'bg-blue-500/20 border-blue-500/40 text-blue-400' :
                        report.report_type === 'technical' ? 'bg-orange-500/20 border-orange-500/40 text-orange-400' :
                        'bg-cyan-500/20 border-cyan-500/40 text-cyan-400'
                      }`}>{report.report_type}</span>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-500">{new Date(report.generated_at).toLocaleString()}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-1">
                        <button onClick={() => setPreviewReport(report)} className="rounded p-1.5 text-slate-400 hover:bg-slate-800 hover:text-cyan-400 transition-colors" title="Preview">
                          <Eye className="h-4 w-4" />
                        </button>
                        <button onClick={() => handleExport(report)} className="rounded p-1.5 text-slate-400 hover:bg-slate-800 hover:text-cyan-400 transition-colors" title="Export JSON">
                          <Download className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {displayReports.length === 0 && (
          <div className="flex flex-col items-center justify-center py-12">
            <FileText className="h-8 w-8 text-slate-600 mb-2" />
            <p className="text-sm text-slate-500">No reports generated yet</p>
            <p className="text-xs text-slate-600 mt-1">Generate a report from an incident</p>
          </div>
        )}
      </div>

      {previewReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => setPreviewReport(null)}>
          <div className="mx-4 max-h-[80vh] w-full max-w-3xl overflow-y-auto rounded-xl border border-slate-700 bg-slate-900 p-6" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <FileText className="h-5 w-5 text-cyan-400" />
                <h2 className="text-lg font-semibold text-white">Report Preview</h2>
              </div>
              <div className="flex items-center gap-2">
                <button onClick={() => handleExportText(previewReport)} className="flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors">
                  <Download className="h-3 w-3" /> Export Text
                </button>
                <button onClick={() => setPreviewReport(null)} className="rounded-lg px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200">Close</button>
              </div>
            </div>
            <pre className="overflow-x-auto rounded-lg bg-slate-950 p-4 text-xs text-slate-300 font-mono leading-relaxed">
              {JSON.stringify(previewReport.content_json, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
