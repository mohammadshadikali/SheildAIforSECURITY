import { useState } from 'react';
import {
  Shield,
  Mail,
  Lock,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Clock,
  User,
  Zap,
  ArrowRight,
} from 'lucide-react';

interface PlaybookStep {
  id: number;
  action: string;
  owner: string;
  priority: 'critical' | 'high' | 'medium';
  estimated_time: string;
  automated: boolean;
  completed?: boolean;
}

interface Playbook {
  id: string;
  title: string;
  description: string;
  icon: React.ElementType;
  category: string;
  severity: string;
  steps: PlaybookStep[];
  mitre_techniques: string[];
}

const PLAYBOOKS: Playbook[] = [
  {
    id: 'phishing-response',
    title: 'Phishing Response',
    description: 'End-to-end containment and remediation workflow for phishing attacks targeting employee credentials.',
    icon: Mail,
    category: 'Email Security',
    severity: 'high',
    mitre_techniques: ['T1566', 'T1078', 'T1110'],
    steps: [
      { id: 1, action: 'Quarantine malicious email across all mailboxes', owner: 'Email Security Team', priority: 'critical', estimated_time: '5 min', automated: true },
      { id: 2, action: 'Block phishing URL at web proxy and DNS sinkhole', owner: 'Network Security', priority: 'critical', estimated_time: '5 min', automated: true },
      { id: 3, action: 'Identify all users who clicked the link or opened attachment', owner: 'SOC Analyst', priority: 'critical', estimated_time: '15 min', automated: true },
      { id: 4, action: 'Force password reset for affected accounts', owner: 'Identity Team', priority: 'high', estimated_time: '10 min', automated: true },
      { id: 5, action: 'Enable MFA enforcement on compromised accounts', owner: 'Identity Team', priority: 'high', estimated_time: '10 min', automated: true },
      { id: 6, action: 'Review OAuth grants and app consent for hijacked sessions', owner: 'Identity Team', priority: 'high', estimated_time: '20 min', automated: false },
      { id: 7, action: 'Scan endpoints for downloaded malware or payloads', owner: 'EDR Team', priority: 'high', estimated_time: '30 min', automated: true },
      { id: 8, action: 'Send targeted awareness communication to affected users', owner: 'Security Awareness', priority: 'medium', estimated_time: '60 min', automated: false },
    ],
  },
  {
    id: 'unauthorized-access',
    title: 'Unauthorized Access Response',
    description: 'Containment and investigation workflow for compromised accounts and unauthorized system access.',
    icon: Lock,
    category: 'Identity & Access',
    severity: 'critical',
    mitre_techniques: ['T1078', 'T1110', 'T1021'],
    steps: [
      { id: 1, action: 'Immediately disable compromised user account', owner: 'Identity Team', priority: 'critical', estimated_time: '2 min', automated: true },
      { id: 2, action: 'Revoke all active sessions and refresh tokens', owner: 'Identity Team', priority: 'critical', estimated_time: '5 min', automated: true },
      { id: 3, action: 'Block source IP addresses at firewall and WAF', owner: 'Network Security', priority: 'critical', estimated_time: '5 min', automated: true },
      { id: 4, action: 'Audit all actions taken by compromised account in last 24h', owner: 'SOC Analyst', priority: 'critical', estimated_time: '30 min', automated: false },
      { id: 5, action: 'Check for lateral movement via RDP, SSH, or SMB', owner: 'SOC Analyst', priority: 'high', estimated_time: '20 min', automated: true },
      { id: 6, action: 'Isolate endpoints with suspicious process activity', owner: 'EDR Team', priority: 'high', estimated_time: '10 min', automated: true },
      { id: 7, action: 'Reset credentials with enforced complexity and MFA', owner: 'Identity Team', priority: 'high', estimated_time: '15 min', automated: true },
      { id: 8, action: 'Create forensic image of affected endpoints', owner: 'IR Team', priority: 'medium', estimated_time: '60 min', automated: false },
      { id: 9, action: 'Document full attack timeline for incident report', owner: 'SOC Lead', priority: 'medium', estimated_time: '45 min', automated: false },
    ],
  },
  {
    id: 'ransomware-response',
    title: 'Ransomware Containment',
    description: 'Emergency containment and recovery workflow for ransomware deployment events.',
    icon: Shield,
    category: 'Endpoint Security',
    severity: 'critical',
    mitre_techniques: ['T1486', 'T1490', 'T1021'],
    steps: [
      { id: 1, action: 'Network-isolate all affected endpoints immediately', owner: 'Network Security', priority: 'critical', estimated_time: '2 min', automated: true },
      { id: 2, action: 'Disable shared drives and SMB access to prevent spread', owner: 'Infrastructure', priority: 'critical', estimated_time: '5 min', automated: true },
      { id: 3, action: 'Identify patient zero and lateral movement path', owner: 'SOC Analyst', priority: 'critical', estimated_time: '30 min', automated: false },
      { id: 4, action: 'Block C2 domains and IPs from ransomware payload', owner: 'Network Security', priority: 'critical', estimated_time: '10 min', automated: true },
      { id: 5, action: 'Verify backup integrity and initiate recovery plan', owner: 'Infrastructure', priority: 'high', estimated_time: '60 min', automated: false },
      { id: 6, action: 'Capture memory dumps before shutdown for forensics', owner: 'IR Team', priority: 'high', estimated_time: '20 min', automated: false },
      { id: 7, action: 'Notify management and legal per incident response plan', owner: 'SOC Lead', priority: 'high', estimated_time: '15 min', automated: false },
    ],
  },
  {
    id: 'brute-force-response',
    title: 'Brute Force Mitigation',
    description: 'Automated and manual response to credential brute force attacks against authentication services.',
    icon: AlertTriangle,
    category: 'Authentication',
    severity: 'high',
    mitre_techniques: ['T1110', 'T1110.001', 'T1110.003'],
    steps: [
      { id: 1, action: 'Block attacking IPs at the perimeter firewall', owner: 'Network Security', priority: 'critical', estimated_time: '5 min', automated: true },
      { id: 2, action: 'Enable account lockout policy (5 failed attempts = 30 min lock)', owner: 'Identity Team', priority: 'critical', estimated_time: '5 min', automated: true },
      { id: 3, action: 'Verify no accounts were successfully compromised', owner: 'SOC Analyst', priority: 'critical', estimated_time: '15 min', automated: true },
      { id: 4, action: 'Force password reset for any accounts with successful brute force', owner: 'Identity Team', priority: 'high', estimated_time: '10 min', automated: true },
      { id: 5, action: 'Deploy rate limiting on authentication endpoints', owner: 'Infrastructure', priority: 'high', estimated_time: '20 min', automated: false },
      { id: 6, action: 'Review logs for credential stuffing patterns against other services', owner: 'SOC Analyst', priority: 'medium', estimated_time: '30 min', automated: false },
    ],
  },
];

export function Playbooks() {
  const [activePlaybook, setActivePlaybook] = useState<Playbook | null>(null);
  const [completedSteps, setCompletedSteps] = useState<Set<string>>(new Set());

  const toggleStep = (playbookId: string, stepId: number) => {
    const key = `${playbookId}-${stepId}`;
    setCompletedSteps(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const getStepCompleted = (playbookId: string, stepId: number) => {
    return completedSteps.has(`${playbookId}-${stepId}`);
  };

  const getProgress = (playbook: Playbook) => {
    const total = playbook.steps.length;
    const done = playbook.steps.filter(s => getStepCompleted(playbook.id, s.id)).length;
    return Math.round((done / total) * 100);
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Response Playbooks</h1>
        <p className="text-sm text-slate-400 mt-1">Step-by-step containment and remediation workflows</p>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Playbook List */}
        <div className="space-y-3">
          {PLAYBOOKS.map(pb => {
            const progress = getProgress(pb);
            const isActive = activePlaybook?.id === pb.id;
            const Icon = pb.icon;

            return (
              <button
                key={pb.id}
                onClick={() => setActivePlaybook(pb)}
                className={`w-full rounded-xl border p-4 text-left transition-all ${
                  isActive
                    ? 'border-cyan-500/40 bg-cyan-500/10 shadow-lg shadow-cyan-500/5'
                    : 'border-slate-800 bg-slate-900 hover:border-slate-700 hover:bg-slate-900/80'
                }`}
              >
                <div className="flex items-center gap-3">
                  <div className={`rounded-lg p-2.5 ${isActive ? 'bg-cyan-500/20 border border-cyan-500/30' : 'bg-slate-800 border border-slate-700'}`}>
                    <Icon className={`h-5 w-5 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <h3 className="text-sm font-semibold text-white">{pb.title}</h3>
                    <p className="text-xs text-slate-500 mt-0.5">{pb.category} | {pb.steps.length} steps</p>
                  </div>
                  <ChevronRight className={`h-4 w-4 ${isActive ? 'text-cyan-400' : 'text-slate-600'}`} />
                </div>
                <div className="mt-3">
                  <div className="flex items-center justify-between text-xs text-slate-500 mb-1">
                    <span>Progress</span>
                    <span>{progress}%</span>
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-slate-800">
                    <div
                      className={`h-full rounded-full transition-all ${progress === 100 ? 'bg-emerald-400' : 'bg-cyan-400'}`}
                      style={{ width: `${progress}%` }}
                    />
                  </div>
                </div>
                <div className="mt-2 flex flex-wrap gap-1">
                  {pb.mitre_techniques.map(t => (
                    <span key={t} className="rounded bg-cyan-500/10 px-1.5 py-0.5 text-[10px] font-mono text-cyan-400">{t}</span>
                  ))}
                </div>
              </button>
            );
          })}
        </div>

        {/* Playbook Detail */}
        <div className="lg:col-span-2">
          {activePlaybook ? (
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
              <div className="flex items-center gap-3 mb-1">
                <activePlaybook.icon className="h-6 w-6 text-cyan-400" />
                <h2 className="text-lg font-bold text-white">{activePlaybook.title}</h2>
              </div>
              <p className="text-sm text-slate-400 mb-6">{activePlaybook.description}</p>

              <div className="space-y-3">
                {activePlaybook.steps.map((step, i) => {
                  const isDone = getStepCompleted(activePlaybook.id, step.id);
                  const priorityConfig = {
                    critical: { color: 'text-red-400', bg: 'bg-red-500/20' },
                    high: { color: 'text-orange-400', bg: 'bg-orange-500/20' },
                    medium: { color: 'text-yellow-400', bg: 'bg-yellow-500/20' },
                  }[step.priority];

                  return (
                    <div
                      key={step.id}
                      onClick={() => toggleStep(activePlaybook.id, step.id)}
                      className={`rounded-lg border p-4 cursor-pointer transition-all ${
                        isDone
                          ? 'border-emerald-500/30 bg-emerald-500/5'
                          : 'border-slate-800 bg-slate-800/30 hover:bg-slate-800/60'
                      }`}
                    >
                      <div className="flex items-start gap-3">
                        <div className={`flex-shrink-0 flex h-7 w-7 items-center justify-center rounded-full border text-xs font-bold ${
                          isDone
                            ? 'border-emerald-500/50 bg-emerald-500/20 text-emerald-400'
                            : 'border-slate-600 bg-slate-800 text-slate-400'
                        }`}>
                          {isDone ? <CheckCircle2 className="h-4 w-4" /> : step.id}
                        </div>
                        <div className="flex-1">
                          <p className={`text-sm font-medium ${isDone ? 'text-emerald-300 line-through' : 'text-slate-200'}`}>
                            {step.action}
                          </p>
                          <div className="mt-2 flex flex-wrap items-center gap-3 text-xs">
                            <span className={`rounded px-1.5 py-0.5 font-semibold ${priorityConfig.bg} ${priorityConfig.color}`}>
                              {step.priority.toUpperCase()}
                            </span>
                            <span className="flex items-center gap-1 text-slate-500">
                              <User className="h-3 w-3" /> {step.owner}
                            </span>
                            <span className="flex items-center gap-1 text-slate-500">
                              <Clock className="h-3 w-3" /> {step.estimated_time}
                            </span>
                            {step.automated && (
                              <span className="flex items-center gap-1 text-cyan-400">
                                <Zap className="h-3 w-3" /> Automated
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>

              {getProgress(activePlaybook) === 100 && (
                <div className="mt-6 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-4 flex items-center gap-3">
                  <CheckCircle2 className="h-6 w-6 text-emerald-400" />
                  <div>
                    <p className="text-sm font-semibold text-emerald-400">Playbook Complete</p>
                    <p className="text-xs text-slate-400 mt-0.5">All containment actions have been executed. Incident can be moved to resolved.</p>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-12 text-center">
              <Shield className="mx-auto h-12 w-12 text-slate-700 mb-3" />
              <h3 className="text-lg font-semibold text-slate-400">Select a Playbook</h3>
              <p className="text-sm text-slate-500 mt-2">Choose a response playbook from the left to view step-by-step containment actions</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
