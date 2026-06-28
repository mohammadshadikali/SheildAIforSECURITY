import React, { useState } from 'react';

interface SuggestedAction {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: 'containment' | 'investigation' | 'remediation' | 'hardening' | 'monitoring';
  estimatedTime: string;
  automated: boolean;
  mitreTechnique?: string;
  completed: boolean;
}

const ACTIONS: SuggestedAction[] = [
  {
    id: 'a1',
    title: 'Isolate Compromised Endpoint',
    description: 'Immediately isolate host DESKTOP-7K2M9P from the network to prevent lateral movement and further damage.',
    severity: 'critical',
    category: 'containment',
    estimatedTime: '2 min',
    automated: true,
    mitreTechnique: 'T1021',
    completed: false,
  },
  {
    id: 'a2',
    title: 'Revoke Suspicious User Credentials',
    description: 'Disable and rotate credentials for user account svc_backup@corp.local which shows signs of compromise via password spraying.',
    severity: 'critical',
    category: 'containment',
    estimatedTime: '5 min',
    automated: true,
    mitreTechnique: 'T1110.003',
    completed: false,
  },
  {
    id: 'a3',
    title: 'Block Malicious IP Ranges',
    description: 'Add firewall rules to block outbound traffic to identified C2 infrastructure: 185.220.101.0/24, 45.142.212.0/24.',
    severity: 'high',
    category: 'containment',
    estimatedTime: '3 min',
    automated: true,
    mitreTechnique: 'T1041',
    completed: false,
  },
  {
    id: 'a4',
    title: 'Collect Memory Forensics',
    description: 'Capture volatile memory from affected endpoints before remediation to preserve evidence for incident analysis.',
    severity: 'high',
    category: 'investigation',
    estimatedTime: '15 min',
    automated: false,
    completed: false,
  },
  {
    id: 'a5',
    title: 'Scan for Lateral Movement Indicators',
    description: 'Run threat hunting query across all endpoints for Pass-the-Hash and RDP-based lateral movement artifacts.',
    severity: 'high',
    category: 'investigation',
    estimatedTime: '10 min',
    automated: true,
    mitreTechnique: 'T1550.002',
    completed: false,
  },
  {
    id: 'a6',
    title: 'Patch CVE-2024-21887 on VPN Gateway',
    description: 'Apply emergency patch for critical Ivanti Connect Secure vulnerability actively exploited in this incident.',
    severity: 'critical',
    category: 'remediation',
    estimatedTime: '30 min',
    automated: false,
    completed: false,
  },
  {
    id: 'a7',
    title: 'Enable PowerShell Script Block Logging',
    description: 'Deploy group policy to enable PowerShell script block logging across all Windows endpoints for better visibility.',
    severity: 'medium',
    category: 'hardening',
    estimatedTime: '20 min',
    automated: true,
    mitreTechnique: 'T1059.001',
    completed: false,
  },
  {
    id: 'a8',
    title: 'Enable Enhanced LSASS Protection',
    description: 'Configure Windows Credential Guard and enable LSASS protection to prevent credential dumping attacks.',
    severity: 'medium',
    category: 'hardening',
    estimatedTime: '25 min',
    automated: false,
    mitreTechnique: 'T1003.001',
    completed: false,
  },
  {
    id: 'a9',
    title: 'Monitor DNS for Exfiltration Patterns',
    description: 'Deploy DNS monitoring rule to detect DNS tunneling and data exfiltration over port 53 from internal hosts.',
    severity: 'medium',
    category: 'monitoring',
    estimatedTime: '8 min',
    automated: true,
    completed: false,
  },
  {
    id: 'a10',
    title: 'Review and Rotate API Keys',
    description: 'Audit all service account API keys and rotate any credentials that may have been exposed during the incident.',
    severity: 'low',
    category: 'remediation',
    estimatedTime: '45 min',
    automated: false,
    completed: false,
  },
];

const CATEGORIES = ['all', 'containment', 'investigation', 'remediation', 'hardening', 'monitoring'] as const;
type Category = typeof CATEGORIES[number];

const SuggestedActions: React.FC = () => {
  const [actions, setActions] = useState<SuggestedAction[]>(ACTIONS);
  const [activeCategory, setActiveCategory] = useState<Category>('all');
  const [activeSeverity, setActiveSeverity] = useState<string>('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [runningId, setRunningId] = useState<string | null>(null);

  const severityConfig = {
    critical: {
      badge: 'bg-red-900/60 text-red-300 border-red-500/50',
      border: 'border-l-red-500',
      glow: 'hover:shadow-red-500/10',
      icon: 'text-red-400',
      dot: 'bg-red-400',
    },
    high: {
      badge: 'bg-orange-900/60 text-orange-300 border-orange-500/50',
      border: 'border-l-orange-500',
      glow: 'hover:shadow-orange-500/10',
      icon: 'text-orange-400',
      dot: 'bg-orange-400',
    },
    medium: {
      badge: 'bg-yellow-900/60 text-yellow-300 border-yellow-500/50',
      border: 'border-l-yellow-500',
      glow: 'hover:shadow-yellow-500/10',
      icon: 'text-yellow-400',
      dot: 'bg-yellow-400',
    },
    low: {
      badge: 'bg-green-900/60 text-green-300 border-green-500/50',
      border: 'border-l-green-500',
      glow: 'hover:shadow-green-500/10',
      icon: 'text-green-400',
      dot: 'bg-green-400',
    },
  };

  const categoryConfig: Record<string, { label: string; icon: React.ReactNode; color: string }> = {
    all: { label: 'All', icon: null, color: 'text-gray-400' },
    containment: {
      label: 'Containment',
      color: 'text-red-400',
      icon: (
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
        </svg>
      ),
    },
    investigation: {
      label: 'Investigation',
      color: 'text-blue-400',
      icon: (
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
      ),
    },
    remediation: {
      label: 'Remediation',
      color: 'text-purple-400',
      icon: (
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
        </svg>
      ),
    },
    hardening: {
      label: 'Hardening',
      color: 'text-cyan-400',
      icon: (
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
      ),
    },
    monitoring: {
      label: 'Monitoring',
      color: 'text-green-400',
      icon: (
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
        </svg>
      ),
    },
  };

  const filteredActions = actions.filter(a => {
    const matchCat = activeCategory === 'all' || a.category === activeCategory;
    const matchSev = activeSeverity === 'all' || a.severity === activeSeverity;
    return matchCat && matchSev;
  });

  const completedCount = actions.filter(a => a.completed).length;
  const criticalCount = actions.filter(a => a.severity === 'critical' && !a.completed).length;

  const handleComplete = (id: string) => {
    setActions(prev => prev.map(a => a.id === id ? { ...a, completed: !a.completed } : a));
  };

  const handleRun = async (id: string) => {
    setRunningId(id);
    await new Promise(r => setTimeout(r, 2000));
    setRunningId(null);
    setActions(prev => prev.map(a => a.id === id ? { ...a, completed: true } : a));
  };

  return (
    <div className="bg-gray-950 text-gray-100 p-4 lg:p-6 min-h-full">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-1">
          <div className="w-8 h-8 rounded bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center">
            <svg className="w-4 h-4 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          </div>
          <div>
            <h1 className="text-lg font-bold text-gray-100">Suggested Actions</h1>
            <p className="text-xs text-gray-500">AI-powered security recommendations</p>
          </div>
        </div>

        {/* Progress */}
        <div className="mt-4 bg-gray-900/60 border border-gray-700/50 rounded-lg p-3">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-gray-400">Remediation Progress</span>
            <span className="text-xs font-mono text-cyan-400">{completedCount}/{actions.length} completed</span>
          </div>
          <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-cyan-500 to-cyan-400 rounded-full transition-all duration-500"
              style={{ width: `${(completedCount / actions.length) * 100}%` }}
            />
          </div>
          {criticalCount > 0 && (
            <div className="flex items-center gap-1.5 mt-2">
              <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
              <span className="text-xs text-red-400">{criticalCount} critical action{criticalCount > 1 ? 's' : ''} pending</span>
            </div>
          )}
        </div>
      </div>

      {/* Filters */}
      <div className="space-y-3 mb-5">
        {/* Category filter */}
        <div className="flex gap-1.5 flex-wrap">
          {CATEGORIES.map(cat => {
            const cfg = categoryConfig[cat];
            const count = cat === 'all' ? actions.length : actions.filter(a => a.category === cat).length;
            return (
              <button
                key={cat}
                onClick={() => setActiveCategory(cat)}
                className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                  activeCategory === cat
                    ? 'bg-gray-700/80 border-gray-500/60 text-gray-100'
                    : 'bg-gray-800/50 border-gray-700/40 text-gray-500 hover:text-gray-300 hover:border-gray-600'
                }`}
              >
                {cfg.icon && <span className={activeCategory === cat ? cfg.color : ''}>{cfg.icon}</span>}
                <span>{cfg.label}</span>
                <span className={`font-mono text-xs px-1 rounded ${activeCategory === cat ? 'bg-gray-600 text-gray-200' : 'bg-gray-700/50 text-gray-500'}`}>{count}</span>
              </button>
            );
          })}
        </div>

        {/* Severity filter */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-600">Severity:</span>
          <div className="flex gap-1">
            {['all', 'critical', 'high', 'medium', 'low'].map(sev => (
              <button
                key={sev}
                onClick={() => setActiveSeverity(sev)}
                className={`px-2.5 py-1 rounded text-xs font-medium border capitalize transition-all ${
                  activeSeverity === sev
                    ? sev === 'all'
                      ? 'bg-gray-700 border-gray-500 text-gray-200'
                      : `border ${severityConfig[sev as keyof typeof severityConfig].badge}`
                    : 'bg-gray-800/40 border-gray-700/40 text-gray-600 hover:text-gray-400'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Results count */}
      <div className="text-xs text-gray-600 mb-3">
        Showing <span className="text-cyan-400 font-medium">{filteredActions.length}</span> actions
      </div>

      {/* Action Cards */}
      <div className="space-y-2">
        {filteredActions.map(action => {
          const sev = severityConfig[action.severity];
          const cat = categoryConfig[action.category];
          const isExpanded = expandedId === action.id;
          const isRunning = runningId === action.id;

          return (
            <div
              key={action.id}
              className={`group relative bg-gray-900/60 border border-gray-700/50 border-l-2 ${sev.border} rounded-lg overflow-hidden transition-all duration-200 ${sev.glow} hover:shadow-lg ${action.completed ? 'opacity-60' : ''}`}
            >
              {/* Main row */}
              <div className="flex items-start gap-3 p-3.5">
                {/* Checkbox */}
                <button
                  onClick={() => handleComplete(action.id)}
                  className={`mt-0.5 flex-shrink-0 w-4 h-4 rounded border transition-all ${
                    action.completed
                      ? 'bg-cyan-500/30 border-cyan-500/60'
                      : 'border-gray-600 hover:border-cyan-500/60'
                  }`}
                >
                  {action.completed && (
                    <svg className="w-full h-full text-cyan-400 p-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                    </svg>
                  )}
                </button>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-start justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`text-xs font-medium ${cat.color} flex items-center gap-1`}>
                        {cat.icon}
                        {cat.label}
                      </span>
                      <span className={`text-xs px-2 py-0.5 rounded-full border capitalize font-medium ${sev.badge}`}>
                        <span className={`inline-block w-1 h-1 rounded-full ${sev.dot} mr-1 ${action.severity === 'critical' || action.severity === 'high' ? 'animate-pulse' : ''}`} />
                        {action.severity}
                      </span>
                      {action.automated && (
                        <span className="text-xs bg-cyan-900/30 text-cyan-400 border border-cyan-500/30 px-1.5 py-0.5 rounded flex items-center gap-1">
                          <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                          </svg>
                          Auto
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-gray-600 flex items-center gap-1">
                        <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        {action.estimatedTime}
                      </span>
                    </div>
                  </div>

                  <h3 className={`text-sm font-semibold mt-1.5 ${action.completed ? 'line-through text-gray-500' : 'text-gray-100'}`}>
                    {action.title}
                  </h3>

                  {/* Collapsed description */}
                  {!isExpanded && (
                    <p className="text-xs text-gray-500 mt-1 line-clamp-1">{action.description}</p>
                  )}

                  {/* Expanded content */}
                  {isExpanded && (
                    <div className="mt-2 space-y-3">
                      <p className="text-xs text-gray-400 leading-relaxed">{action.description}</p>
                      {action.mitreTechnique && (
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-gray-600">MITRE:</span>
                          <span className="text-xs font-mono bg-purple-900/30 text-purple-400 border border-purple-500/30 px-2 py-0.5 rounded">
                            {action.mitreTechnique}
                          </span>
                        </div>
                      )}
                      <div className="flex items-center gap-2 pt-1">
                        {action.automated && !action.completed && (
                          <button
                            onClick={() => handleRun(action.id)}
                            disabled={isRunning}
                            className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/40 rounded-lg text-xs font-medium text-cyan-400 transition-all disabled:opacity-50"
                          >
                            {isRunning ? (
                              <>
                                <svg className="w-3 h-3 animate-spin" fill="none" viewBox="0 0 24 24">
                                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                                </svg>
                                Running...
                              </>
                            ) : (
                              <>
                                <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                                Run Automated Action
                              </>
                            )}
                          </button>
                        )}
                        <button
                          onClick={() => handleComplete(action.id)}
                          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                            action.completed
                              ? 'bg-gray-800/50 border-gray-700/50 text-gray-500 hover:text-gray-300'
                              : 'bg-green-900/20 border-green-500/30 text-green-400 hover:bg-green-900/40'
                          }`}
                        >
                          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                          </svg>
                          {action.completed ? 'Mark Incomplete' : 'Mark Complete'}
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                {/* Expand toggle */}
                <button
                  onClick={() => setExpandedId(isExpanded ? null : action.id)}
                  className="flex-shrink-0 text-gray-600 hover:text-gray-400 transition-colors mt-0.5"
                >
                  <svg
                    className={`w-4 h-4 transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}
                    fill="none" viewBox="0 0 24 24" stroke="currentColor"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </button>
              </div>

              {/* Running progress bar */}
              {isRunning && (
                <div className="h-0.5 bg-gray-800">
                  <div className="h-full bg-cyan-400 animate-pulse" style={{ animation: 'runProgress 2s linear forwards' }} />
                </div>
              )}
            </div>
          );
        })}
      </div>

      {filteredActions.length === 0 && (
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <svg className="w-10 h-10 text-gray-700 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <p className="text-gray-600 text-sm">No actions match the selected filters</p>
          <button
            onClick={() => { setActiveCategory('all'); setActiveSeverity('all'); }}
            className="mt-2 text-xs text-cyan-400 hover:text-cyan-300"
          >
            Clear filters
          </button>
        </div>
      )}

      <style>{`
        @keyframes runProgress {
          from { width: 0%; }
          to { width: 100%; }
        }
        .line-clamp-1 {
          display: -webkit-box;
          -webkit-line-clamp: 1;
          -webkit-box-orient: vertical;
          overflow: hidden;
        }
      `}</style>
    </div>
  );
};

export default SuggestedActions;
