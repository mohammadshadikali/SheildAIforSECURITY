import { useState } from 'react';
import { Target } from 'lucide-react';
import { MITRE_TACTICS, MITRE_TECHNIQUES, getTechniquesByTactic } from '../lib/mitreData';
import { useStore } from '../lib/store';

export function MitreHeatmap() {
  const [selectedCell, setSelectedCell] = useState<{ id: string; name: string; tactic: string; description: string; hitCount: number } | null>(null);
  const mitreMappings = useStore(s => s.mitreMappings);
  const incidents = useStore(s => s.incidents);

  const hitMap: Record<string, number> = {};
  mitreMappings.forEach(m => {
    hitMap[m.technique_id] = (hitMap[m.technique_id] || 0) + 1;
  });

  // Add some baseline hits from demo incidents for visual richness
  incidents.forEach(inc => {
    const text = `${inc.title} ${inc.description} ${inc.attack_vector}`.toLowerCase();
    const attackKeywords: Record<string, string[]> = {
      'T1110': ['brute', 'brute force'],
      'T1190': ['sql', 'injection', 'web'],
      'T1078': ['login', 'account', 'credential'],
      'T1566': ['phishing', 'email'],
      'T1486': ['ransomware', 'encrypt'],
      'T1021': ['lateral', 'rdp', 'smb', 'ssh'],
      'T1059': ['powershell', 'script', 'command'],
    };
    Object.entries(attackKeywords).forEach(([techId, keywords]) => {
      if (keywords.some(k => text.includes(k))) {
        if (!hitMap[techId]) hitMap[techId] = 1;
      }
    });
  });

  const getHeatColor = (count: number): string => {
    if (count === 0) return 'bg-slate-800/30';
    if (count === 1) return 'bg-cyan-500/20';
    if (count === 2) return 'bg-cyan-500/40';
    if (count === 3) return 'bg-orange-500/40';
    if (count >= 4) return 'bg-red-500/50';
    return 'bg-slate-800/30';
  };

  const getHeatBorder = (count: number): string => {
    if (count === 0) return 'border-slate-800/50';
    if (count === 1) return 'border-cyan-500/30';
    if (count === 2) return 'border-cyan-500/50';
    if (count === 3) return 'border-orange-500/50';
    if (count >= 4) return 'border-red-500/50';
    return 'border-slate-800/50';
  };

  const tacticAbbr: Record<string, string> = {
    'Initial Access': 'INIT', 'Execution': 'EXEC', 'Persistence': 'PERS',
    'Privilege Escalation': 'PRIV', 'Defense Evasion': 'DEF',
    'Credential Access': 'CRED', 'Discovery': 'DISC', 'Lateral Movement': 'LAT',
    'Collection': 'COLL', 'Command and Control': 'C2',
    'Exfiltration': 'EXFIL', 'Impact': 'IMPT',
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">MITRE ATT&CK Heatmap</h1>
        <p className="text-sm text-slate-400 mt-1">Threat technique frequency across all incidents</p>
      </div>

      <div className="flex items-center gap-4 rounded-xl border border-slate-800 bg-slate-900 px-4 py-3">
        <span className="text-xs text-slate-400">Frequency:</span>
        <div className="flex items-center gap-2">
          {[{ bg: 'bg-slate-800/30', bd: 'border-slate-800/50', label: '0' }, { bg: 'bg-cyan-500/20', bd: 'border-cyan-500/30', label: '1' }, { bg: 'bg-cyan-500/40', bd: 'border-cyan-500/50', label: '2' }, { bg: 'bg-orange-500/40', bd: 'border-orange-500/50', label: '3' }, { bg: 'bg-red-500/50', bd: 'border-red-500/50', label: '4+' }].map(l => (
            <div key={l.label} className="flex items-center gap-1.5">
              <div className={`h-4 w-8 rounded ${l.bg} border ${l.bd}`} />
              <span className="text-[10px] text-slate-500">{l.label}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="overflow-x-auto">
        <div className="min-w-[1100px]">
          <div className="grid grid-cols-12 gap-1 mb-1">
            {MITRE_TACTICS.map(tactic => (
              <div key={tactic} className="rounded-lg bg-slate-800/50 px-2 py-2 text-center">
                <p className="text-[10px] font-bold uppercase tracking-wider text-cyan-400">{tacticAbbr[tactic]}</p>
                <p className="text-[8px] text-slate-500 mt-0.5 leading-tight">{tactic}</p>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-12 gap-1">
            {MITRE_TACTICS.map(tactic => {
              const techniques = getTechniquesByTactic(tactic);
              return (
                <div key={tactic} className="flex flex-col gap-1">
                  {techniques.map(tech => {
                    const hits = hitMap[tech.id] || 0;
                    return (
                      <button
                        key={tech.id}
                        onClick={() => setSelectedCell({ ...tech, hitCount: hits })}
                        className={`rounded border px-1.5 py-1.5 text-left transition-all hover:scale-[1.02] ${getHeatColor(hits)} ${getHeatBorder(hits)}`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-[9px] font-mono font-bold text-slate-300">{tech.id}</span>
                          {hits > 0 && <span className={`text-[8px] font-bold ${hits >= 3 ? 'text-red-400' : hits >= 2 ? 'text-orange-400' : 'text-cyan-400'}`}>{hits}</span>}
                        </div>
                        <p className="text-[8px] text-slate-400 leading-tight mt-0.5 line-clamp-2">{tech.name}</p>
                      </button>
                    );
                  })}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {selectedCell && (
        <div className="rounded-xl border border-cyan-500/20 bg-slate-900 p-5">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Target className="h-5 w-5 text-cyan-400" />
              <span className="rounded bg-cyan-500/20 px-2 py-0.5 text-sm font-mono font-bold text-cyan-400">{selectedCell.id}</span>
              <h3 className="text-base font-semibold text-white">{selectedCell.name}</h3>
            </div>
            <button onClick={() => setSelectedCell(null)} className="text-slate-500 hover:text-slate-300 text-sm">Close</button>
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div>
              <p className="text-xs text-slate-500">Tactic</p>
              <p className="text-sm text-slate-200">{selectedCell.tactic}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">Incident Hits</p>
              <p className={`text-sm font-semibold ${selectedCell.hitCount >= 3 ? 'text-red-400' : selectedCell.hitCount >= 2 ? 'text-orange-400' : selectedCell.hitCount > 0 ? 'text-cyan-400' : 'text-slate-500'}`}>{selectedCell.hitCount}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">Risk Level</p>
              <p className={`text-sm font-semibold ${selectedCell.hitCount >= 4 ? 'text-red-400' : selectedCell.hitCount >= 2 ? 'text-orange-400' : 'text-cyan-400'}`}>
                {selectedCell.hitCount >= 4 ? 'Critical' : selectedCell.hitCount >= 2 ? 'Elevated' : selectedCell.hitCount > 0 ? 'Moderate' : 'Low'}
              </p>
            </div>
          </div>
          <div className="mt-3">
            <p className="text-xs text-slate-500">Description</p>
            <p className="text-sm text-slate-300 mt-1">{selectedCell.description}</p>
          </div>
        </div>
      )}

      <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
        <h3 className="text-sm font-semibold text-slate-300 mb-4">Most Frequently Observed Techniques</h3>
        <div className="space-y-2">
          {Object.entries(hitMap)
            .filter(([, count]) => count > 0)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 8)
            .map(([techId, count]) => {
              const tech = MITRE_TECHNIQUES.find(t => t.id === techId);
              if (!tech) return null;
              return (
                <div key={techId} className="flex items-center gap-4 rounded-lg border border-slate-800 bg-slate-800/30 px-4 py-2.5">
                  <span className="rounded bg-cyan-500/20 px-2 py-0.5 text-xs font-mono font-bold text-cyan-400 flex-shrink-0">{techId}</span>
                  <span className="text-sm text-slate-200 flex-1">{tech.name}</span>
                  <span className="text-xs text-slate-500">{tech.tactic}</span>
                  <div className="flex items-center gap-2">
                    <div className="h-1.5 w-20 rounded-full bg-slate-700">
                      <div className="h-full rounded-full bg-red-400" style={{ width: `${Math.min(count * 20, 100)}%` }} />
                    </div>
                    <span className="text-xs font-bold text-red-400">{count}</span>
                  </div>
                </div>
              );
            })}
          {Object.keys(hitMap).length === 0 && <p className="text-sm text-slate-500 text-center py-4">No technique hits recorded yet</p>}
        </div>
      </div>
    </div>
  );
}
