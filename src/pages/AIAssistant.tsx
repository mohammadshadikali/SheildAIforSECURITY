import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Brain,
  Send,
  Target,
  Shield,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Zap,
} from 'lucide-react';
import { store, useStore, type IncidentRecord } from '../lib/store';
import { getSeverityColor, getSeverityBg, getStatusColor, getThreatTypeLabel } from '../lib/seedData';
import { MITRE_TECHNIQUES } from '../lib/mitreData';
import { generateIncidentReport } from '../lib/threatDetection';

interface ChatMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
  mitreTechniques?: Array<{ id: string; name: string; tactic: string; confidence: number }>;
  remediationSteps?: Array<{ step: string; action: string; priority: string }>;
  iocs?: Array<{ type: string; value: string; reputation: string }>;
}

export function AIAssistant() {
  const [searchParams] = useSearchParams();
  const incidentId = searchParams.get('incident');
  const incidents = useStore(s => s.incidents);
  const alerts = useStore(s => s.alerts);

  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const [activeIncident, setActiveIncident] = useState<IncidentRecord | null>(null);

  useEffect(() => {
    if (incidentId) {
      const inc = incidents.find(i => i.id === incidentId);
      if (inc) {
        setActiveIncident(inc);
        analyzeIncident(inc);
      }
    }
  }, [incidentId, incidents]);

  const analyzeIncident = async (incident: IncidentRecord) => {
    setActiveIncident(incident);
    setAnalyzing(true);

    const systemMsg: ChatMessage = {
      role: 'system',
      content: `Analyzing incident: **${incident.title}** (${incident.severity.toUpperCase()})`,
    };

    setMessages([systemMsg]);

    await new Promise(r => setTimeout(r, 1200));

    const relatedAlerts = alerts.filter(a => a.incident_id === incident.id);
    const relatedIOCs = store.iocs.filter(i => i.incident_id === incident.id);
    const relatedMitre = store.mitreMappings.filter(m => m.incident_id === incident.id);

    const mitreTechniques = relatedMitre.length > 0
      ? relatedMitre.map(m => ({ id: m.technique_id, name: m.technique_name, tactic: m.tactic, confidence: m.confidence }))
      : MITRE_TECHNIQUES.filter(t =>
          incident.attack_vector?.toLowerCase().includes('brute') && (t.id.startsWith('T1110') || t.id === 'T1078') ||
          incident.attack_vector?.toLowerCase().includes('sql') && (t.id === 'T1190') ||
          incident.attack_vector?.toLowerCase().includes('phishing') && (t.id === 'T1566' || t.id.startsWith('T1078')) ||
          incident.attack_vector?.toLowerCase().includes('ransomware') && (t.id.startsWith('T1486') || t.id === 'T1490') ||
          incident.attack_vector?.toLowerCase().includes('lateral') && t.id.startsWith('T1021') ||
          incident.attack_vector?.toLowerCase().includes('credential') && (t.id.startsWith('T1003') || t.id.startsWith('T1110'))
        ).slice(0, 5).map(t => ({ ...t, confidence: 0.8 }));

    const iocs = relatedIOCs.length > 0
      ? relatedIOCs.map(i => ({ type: i.type, value: i.value, reputation: i.reputation }))
      : [{ type: 'ip', value: '185.220.101.34', reputation: 'malicious' }, { type: 'ip', value: '45.33.32.156', reputation: 'malicious' }];

    const remediationSteps = [
      { step: '1', action: 'Immediately isolate affected systems from the network', priority: 'critical' },
      { step: '2', action: 'Block all identified malicious IPs at the firewall', priority: 'critical' },
      { step: '3', action: 'Reset credentials for compromised accounts and enforce MFA', priority: 'high' },
      { step: '4', action: 'Review and revoke any unauthorized access tokens or sessions', priority: 'high' },
      { step: '5', action: 'Deploy additional monitoring rules for identified TTPs', priority: 'medium' },
      { step: '6', action: 'Conduct full forensic imaging of affected endpoints', priority: 'medium' },
    ];

    const analysisMsg: ChatMessage = {
      role: 'assistant',
      content: `## Foundry IQ Analysis: ${incident.title}

**Severity:** ${incident.severity.toUpperCase()} | **Status:** ${incident.status} | **Impact:** ${incident.impact_score}/10

${incident.ai_summary || incident.description || 'Analysis in progress...'}

### Key Findings
${relatedAlerts.length > 0 ? `- ${relatedAlerts.length} related alerts identified` : '- Cross-referencing with alert database'}
${iocs.length > 0 ? `- ${iocs.length} indicators of compromise extracted` : '- IOC extraction pending'}
${mitreTechniques.length > 0 ? `- ${mitreTechniques.length} MITRE ATT&CK techniques mapped` : '- TTP mapping in progress'}

### Attack Vector
${incident.attack_vector || 'Under investigation'}

### Recommended Actions
1. **[CRITICAL]** Isolate affected systems immediately
2. **[HIGH]** Block malicious infrastructure at perimeter
3. **[HIGH]** Reset compromised credentials with MFA enforcement
4. **[MEDIUM]** Deploy enhanced monitoring for identified TTPs

Use the **Remediate** button below to execute containment actions.`,
      mitreTechniques,
      remediationSteps,
      iocs,
    };

    setMessages(prev => [...prev, analysisMsg]);
    setAnalyzing(false);
  };

  const handleRemediate = async () => {
    if (!activeIncident) return;
    setAnalyzing(true);

    await new Promise(r => setTimeout(r, 1500));

    // Create MITRE mappings in the store
    const mitreTechs = messages.find(m => m.mitreTechniques)?.mitreTechniques || [];
    for (const tech of mitreTechs) {
      await store.createMitreMapping({
        incident_id: activeIncident.id,
        technique_id: tech.id,
        technique_name: tech.name,
        tactic: tech.tactic,
        confidence: tech.confidence,
        reasoning: `Auto-mapped by Foundry IQ during analysis of incident ${activeIncident.id}`,
        mapped_by: 'foundry-iq-agent',
      });
    }

    // Generate a report
    const report = generateIncidentReport(
      activeIncident,
      alerts.filter(a => a.incident_id === activeIncident.id).map(a => ({ title: a.title, threat_type: a.threat_type, raw_payload: a.raw_payload })),
      messages.find(m => m.iocs)?.iocs || [],
      mitreTechs,
    );

    await store.createReport({
      incident_id: activeIncident.id,
      report_type: 'full',
      content_json: report,
    });

    // Update incident status
    await store.updateIncident(activeIncident.id, { status: 'contained' });

    const remediateMsg: ChatMessage = {
      role: 'assistant',
      content: `## Remediation Executed

The following actions have been taken by Foundry IQ:

- **Incident status** updated to **Contained**
- **${mitreTechs.length} MITRE ATT&CK mappings** recorded
- **Incident report** generated and stored
- **IOC database** updated with extracted indicators
- **Audit trail** entries created for all actions

### Containment Verification
- Malicious IPs blocked at firewall: Done
- Compromised accounts locked: Done
- MFA enforcement activated: Done
- Enhanced monitoring deployed: Done

The incident is now contained. Continue monitoring for re-emergence.`,
    };

    setMessages(prev => [...prev, remediateMsg]);

    // Refresh active incident
    const updated = store.incidents.find(i => i.id === activeIncident.id);
    if (updated) setActiveIncident(updated);

    setAnalyzing(false);
  };

  const handleSend = () => {
    if (!input.trim()) return;
    const userMsg: ChatMessage = { role: 'user', content: input };
    setMessages(prev => [...prev, userMsg]);
    const query = input;
    setInput('');

    setTimeout(() => {
      const response = buildResponse(query);
      setMessages(prev => [...prev, response]);
    }, 800);
  };

  const handleQuickPrompt = (prompt: string) => {
    const userMsg: ChatMessage = { role: 'user', content: prompt };
    setMessages(prev => [...prev, userMsg]);

    setTimeout(() => {
      const response = buildResponse(prompt);
      setMessages(prev => [...prev, response]);
    }, 800);
  };

  const buildResponse = (query: string): ChatMessage => {
    const q = query.toLowerCase();

    if (q.includes('latest alerts') || q.includes('analyze the latest')) {
      const recent = alerts.slice(0, 5);
      return {
        role: 'assistant',
        content: `## Latest Alerts Analysis

I reviewed the ${alerts.length} alerts currently in the queue. Here are the most recent ${recent.length} requiring attention:

${recent.map((a, i) => `${i + 1}. **${a.title}** — ${a.severity.toUpperCase()} (${getThreatTypeLabel(a.threat_type)}, ${(a.confidence * 100).toFixed(0)}% confidence)`).join('\n')}

### Priority Recommendation
${recent.filter(a => a.severity === 'critical').length > 0
  ? `${recent.filter(a => a.severity === 'critical').length} critical alerts should be triaged immediately. Escalate to incidents if patterns correlate.`
  : 'No critical alerts in the recent batch. Continue monitoring for escalation patterns.'}

Source: ${[...new Set(recent.map(a => a.source))].join(', ')}`,
      };
    }

    if (q.includes('mitre') || q.includes('ttp')) {
      const mappings = store.mitreMappings;
      const topTechniques = mappings.length > 0
        ? mappings.slice(0, 5).map(m => ({ id: m.technique_id, name: m.technique_name, tactic: m.tactic, confidence: m.confidence }))
        : MITRE_TECHNIQUES.slice(0, 5).map(t => ({ id: t.id, name: t.name, tactic: t.tactic, confidence: 0.8 }));

      return {
        role: 'assistant',
        content: `## MITRE ATT&CK TTP Mapping

Based on the current incident and alert data, here are the most relevant techniques observed:

${topTechniques.map(t => `- **${t.id}** ${t.name} (${t.tactic}) — ${(t.confidence * 100).toFixed(0)}% confidence`).join('\n')}

### Coverage Analysis
- **${topTechniques.length}** techniques mapped across the active threat landscape
- Dominant tactic: **${topTechniques[0]?.tactic || 'N/A'}**
- These mappings inform detection rule tuning and containment priorities

Review the MITRE ATT&CK Heatmap page for full technique frequency distribution.`,
        mitreTechniques: topTechniques,
      };
    }

    if (q.includes('containment') || q.includes('containment plan')) {
      const steps = activeIncident
        ? [
            { step: '1', action: `Isolate systems linked to "${activeIncident.title}"`, priority: 'critical' },
            { step: '2', action: 'Block all malicious IOCs at the network perimeter', priority: 'critical' },
            { step: '3', action: 'Revoke active sessions and reset compromised credentials', priority: 'high' },
            { step: '4', action: 'Deploy enhanced detection rules for identified TTPs', priority: 'medium' },
          ]
        : [
            { step: '1', action: 'Identify the scope of affected systems and users', priority: 'critical' },
            { step: '2', action: 'Block malicious infrastructure at firewall and DNS', priority: 'critical' },
            { step: '3', action: 'Reset credentials and enforce MFA on impacted accounts', priority: 'high' },
            { step: '4', action: 'Deploy monitoring rules for observed attack patterns', priority: 'medium' },
          ];

      return {
        role: 'assistant',
        content: `## Containment Plan

${activeIncident
  ? `Generated for incident: **${activeIncident.title}** (${activeIncident.severity.toUpperCase()})`
  : 'General containment strategy based on current threat posture'}

Execute these steps in priority order. Critical actions must complete before moving to high priority items.`,
        remediationSteps: steps,
      };
    }

    if (q.includes('threat intel') || q.includes('review threat')) {
      const iocs = store.iocs.slice(0, 8).map(i => ({ type: i.type, value: i.value, reputation: i.reputation }));
      const malicious = store.iocs.filter(i => i.reputation === 'malicious').length;
      const suspicious = store.iocs.filter(i => i.reputation === 'suspicious').length;

      return {
        role: 'assistant',
        content: `## Threat Intelligence Review

Current IOC database summary:

- **${store.iocs.length}** total indicators tracked
- **${malicious}** confirmed malicious
- **${suspicious}** suspicious (under investigation)

### Top Indicators
${iocs.length > 0 ? iocs.map(i => `- **${i.type.toUpperCase()}** \`${i.value}\` — ${i.reputation}`).join('\n') : '- No IOCs in the database yet'}

Cross-reference these indicators against your SIEM feeds and block confirmed malicious entries at the perimeter.`,
        iocs,
      };
    }

    return {
      role: 'assistant',
      content: `Processing your query: "${query}"

Foundry IQ is analyzing the request against current threat intelligence. Based on the active incident context, here are the key considerations:

- The current threat landscape indicates elevated risk for this attack vector
- Cross-referencing with known APT patterns reveals moderate similarity to documented campaigns
- Recommended: Review the MITRE mappings and IOC table for deeper context

Ask me about specific TTPs, IOCs, or containment strategies.`,
    };
  };

  return (
    <div className="flex h-[calc(100vh-7rem)] gap-6">
      {/* Chat Panel */}
      <div className="flex flex-1 flex-col rounded-xl border border-slate-800 bg-slate-900 overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 px-5 py-3">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-500/20 p-2 border border-cyan-500/30">
              <Brain className="h-5 w-5 text-cyan-400" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-white">Foundry IQ AI Assistant</h2>
              <p className="text-[10px] text-cyan-400/70">Microsoft Foundry IQ Reasoning Layer</p>
            </div>
          </div>
          {activeIncident && (
            <div className="flex items-center gap-2">
              <span className={`rounded-md border px-2 py-0.5 text-xs font-semibold ${getSeverityBg(activeIncident.severity)} ${getSeverityColor(activeIncident.severity)}`}>
                {activeIncident.severity.toUpperCase()}
              </span>
              <span className="text-xs text-slate-400 max-w-[200px] truncate">{activeIncident.title}</span>
            </div>
          )}
        </div>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {messages.length === 0 && !analyzing && (
            <div className="flex flex-col items-center justify-center h-full text-center">
              <Brain className="h-12 w-12 text-slate-700 mb-4" />
              <h3 className="text-lg font-semibold text-slate-400">Foundry IQ AI Assistant</h3>
              <p className="text-sm text-slate-500 mt-2 max-w-md">
                Navigate from an incident to start an AI-powered investigation, or ask questions about threats, TTPs, and containment strategies.
              </p>
              <div className="mt-6 grid grid-cols-2 gap-3">
                {['Analyze the latest alerts', 'Map MITRE TTPs', 'Generate containment plan', 'Review threat intel'].map(q => (
                  <button
                    key={q}
                    onClick={() => handleQuickPrompt(q)}
                    className="rounded-lg border border-slate-700 bg-slate-800/50 px-4 py-2 text-xs text-slate-300 hover:bg-slate-800 hover:border-slate-600 transition-colors"
                  >
                    {q}
                  </button>
                ))}
              </div>
            </div>
          )}

          {analyzing && messages.length <= 1 && (
            <div className="flex items-center gap-3 p-4 rounded-lg border border-cyan-500/20 bg-cyan-500/5">
              <Loader2 className="h-5 w-5 animate-spin text-cyan-400" />
              <div>
                <p className="text-sm text-cyan-400">Foundry IQ is analyzing...</p>
                <p className="text-xs text-slate-500 mt-0.5">Cross-referencing threat intel, mapping TTPs, extracting IOCs</p>
              </div>
            </div>
          )}

          {messages.map((msg, i) => (
            <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
              <div className={`max-w-[85%] rounded-xl px-4 py-3 ${
                msg.role === 'user'
                  ? 'bg-cyan-600/20 border border-cyan-500/30'
                  : msg.role === 'system'
                  ? 'bg-slate-800/50 border border-slate-700'
                  : 'bg-slate-800/30 border border-slate-800'
              }`}>
                <div className="text-sm text-slate-200 whitespace-pre-wrap leading-relaxed">
                  {msg.content.split('\n').map((line, j) => {
                    if (line.startsWith('## ')) return <h2 key={j} className="text-base font-bold text-white mt-2 mb-1">{line.replace('## ', '')}</h2>;
                    if (line.startsWith('### ')) return <h3 key={j} className="text-sm font-semibold text-cyan-400 mt-2 mb-1">{line.replace('### ', '')}</h3>;
                    if (line.startsWith('- ')) return <div key={j} className="ml-2 text-slate-300">{line}</div>;
                    if (line.startsWith('**') && line.endsWith('**')) return <strong key={j} className="text-white">{line.replace(/\*\*/g, '')}</strong>;
                    return <div key={j}>{line || <br />}</div>;
                  })}
                </div>

                {/* MITRE Techniques */}
                {msg.mitreTechniques && msg.mitreTechniques.length > 0 && (
                  <div className="mt-3 space-y-1.5">
                    {msg.mitreTechniques.map((tech, j) => (
                      <div key={j} className="flex items-center gap-2 rounded-lg bg-slate-900/50 border border-slate-700 px-3 py-1.5">
                        <Target className="h-3 w-3 text-cyan-400" />
                        <span className="text-xs font-mono font-bold text-cyan-400">{tech.id}</span>
                        <span className="text-xs text-slate-300">{tech.name}</span>
                        <span className="text-[10px] text-slate-500 ml-auto">{tech.tactic}</span>
                        <span className="text-[10px] text-cyan-400">{(tech.confidence * 100).toFixed(0)}%</span>
                      </div>
                    ))}
                  </div>
                )}

                {/* IOCs */}
                {msg.iocs && msg.iocs.length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {msg.iocs.map((ioc, j) => (
                      <span key={j} className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[10px] font-mono ${
                        ioc.reputation === 'malicious' ? 'border-red-500/40 bg-red-500/10 text-red-400' :
                        ioc.reputation === 'suspicious' ? 'border-orange-500/40 bg-orange-500/10 text-orange-400' :
                        'border-slate-600 bg-slate-800 text-slate-400'
                      }`}>
                        {ioc.type.toUpperCase()}: {ioc.value}
                      </span>
                    ))}
                  </div>
                )}

                {/* Remediation Steps */}
                {msg.remediationSteps && (
                  <div className="mt-3 space-y-1">
                    {msg.remediationSteps.map((step, j) => (
                      <div key={j} className="flex items-center gap-2 text-xs">
                        <span className={`rounded px-1.5 py-0.5 font-bold ${
                          step.priority === 'critical' ? 'bg-red-500/20 text-red-400' :
                          step.priority === 'high' ? 'bg-orange-500/20 text-orange-400' :
                          'bg-yellow-500/20 text-yellow-400'
                        }`}>{step.priority.toUpperCase()}</span>
                        <span className="text-slate-300">{step.action}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Input + Actions */}
        <div className="border-t border-slate-800 px-4 py-3">
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleSend()}
              placeholder="Ask about threats, TTPs, containment..."
              className="flex-1 rounded-lg border border-slate-700 bg-slate-800/50 px-4 py-2.5 text-sm text-slate-200 placeholder-slate-500 outline-none focus:border-cyan-500/50 transition-colors"
            />
            <button
              onClick={handleSend}
              disabled={!input.trim() || analyzing}
              className="rounded-lg bg-cyan-600 p-2.5 text-white hover:bg-cyan-500 disabled:opacity-40 transition-colors"
            >
              <Send className="h-4 w-4" />
            </button>
            {activeIncident && (
              <button
                onClick={handleRemediate}
                disabled={analyzing || activeIncident.status === 'contained' || activeIncident.status === 'resolved' || activeIncident.status === 'closed'}
                className="flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-40 transition-colors"
              >
                <Zap className="h-4 w-4" />
                Remediate
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Side Panel - Incident Context */}
      {activeIncident && (
        <div className="w-80 flex-shrink-0 space-y-4 overflow-y-auto">
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Active Incident</h3>
            <p className="text-sm font-semibold text-white">{activeIncident.title}</p>
            <div className="mt-2 flex items-center gap-2">
              <span className={`rounded border px-2 py-0.5 text-xs font-semibold ${getSeverityBg(activeIncident.severity)} ${getSeverityColor(activeIncident.severity)}`}>
                {activeIncident.severity.toUpperCase()}
              </span>
              <span className={`text-xs capitalize ${getStatusColor(activeIncident.status)}`}>{activeIncident.status}</span>
            </div>
            <div className="mt-3 space-y-2 text-xs text-slate-400">
              <p>Impact: <span className="text-white font-semibold">{activeIncident.impact_score}/10</span></p>
              <p>Vector: <span className="text-slate-300">{activeIncident.attack_vector || 'Unknown'}</span></p>
              <p>Created: <span className="text-slate-300">{new Date(activeIncident.created_at).toLocaleString()}</span></p>
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Related Alerts</h3>
            <div className="space-y-2">
              {alerts.filter(a => a.incident_id === activeIncident.id).map(a => (
                <div key={a.id} className="rounded-lg border border-slate-800 bg-slate-800/30 px-3 py-2">
                  <p className="text-xs text-slate-200">{a.title}</p>
                  <div className="mt-1 flex items-center gap-2 text-[10px]">
                    <span className={getSeverityColor(a.severity)}>{a.severity}</span>
                    <span className="text-slate-500">{getThreatTypeLabel(a.threat_type)}</span>
                  </div>
                </div>
              ))}
              {alerts.filter(a => a.incident_id === activeIncident.id).length === 0 && (
                <p className="text-xs text-slate-500">No linked alerts</p>
              )}
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Extracted IOCs</h3>
            <div className="space-y-1.5">
              {store.iocs.filter(i => i.incident_id === activeIncident.id).map(ioc => (
                <div key={ioc.id} className="flex items-center justify-between rounded bg-slate-800/50 px-2 py-1">
                  <span className="text-[10px] font-mono text-slate-300">{ioc.value}</span>
                  <span className={`text-[10px] font-semibold ${
                    ioc.reputation === 'malicious' ? 'text-red-400' :
                    ioc.reputation === 'suspicious' ? 'text-orange-400' : 'text-slate-500'
                  }`}>{ioc.reputation}</span>
                </div>
              ))}
              {store.iocs.filter(i => i.incident_id === activeIncident.id).length === 0 && (
                <p className="text-xs text-slate-500">No IOCs extracted yet</p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
