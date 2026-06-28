import { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bell, Search, Shield, Brain, X, User, LogOut, ChevronDown } from 'lucide-react';
import { useStore, store, type AlertRecord, type IncidentRecord, type IOCRecord } from '../../lib/store';

type SearchResult = {
  id: string;
  type: 'alert' | 'incident' | 'ioc';
  title: string;
  subtitle: string;
  route: string;
};

export function TopBar() {
  const navigate = useNavigate();
  const alerts = useStore(s => s.alerts);
  const incidents = useStore(s => s.incidents);
  const iocs = useStore(s => s.iocs);

  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<SearchResult[]>([]);
  const [showSearchResults, setShowSearchResults] = useState(false);

  const [showFoundryIQ, setShowFoundryIQ] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [showProfile, setShowProfile] = useState(false);

  const searchRef = useRef<HTMLDivElement>(null);
  const notifRef = useRef<HTMLDivElement>(null);
  const profileRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (searchRef.current && !searchRef.current.contains(e.target as Node)) {
        setShowSearchResults(false);
      }
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setShowNotifications(false);
      }
      if (profileRef.current && !profileRef.current.contains(e.target as Node)) {
        setShowProfile(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  useEffect(() => {
    if (!searchQuery.trim()) {
      setSearchResults([]);
      setShowSearchResults(false);
      return;
    }

    const q = searchQuery.toLowerCase();
    const results: SearchResult[] = [];

    incidents.forEach((inc: IncidentRecord) => {
      if (inc.title.toLowerCase().includes(q) || inc.id.toLowerCase().includes(q) || inc.description.toLowerCase().includes(q) || inc.attack_vector.toLowerCase().includes(q)) {
        results.push({
          id: inc.id,
          type: 'incident',
          title: inc.title,
          subtitle: `Incident · ${inc.severity} · ${inc.status}`,
          route: `/incidents/${inc.id}`,
        });
      }
    });

    alerts.forEach((a: AlertRecord) => {
      if (a.title.toLowerCase().includes(q) || a.id.toLowerCase().includes(q) || a.source.toLowerCase().includes(q) || a.threat_type.toLowerCase().includes(q)) {
        results.push({
          id: a.id,
          type: 'alert',
          title: a.title,
          subtitle: `Alert · ${a.severity} · ${a.source}`,
          route: `/alerts/${a.id}`,
        });
      }
    });

    iocs.forEach((ioc: IOCRecord) => {
      if (ioc.value.toLowerCase().includes(q) || ioc.type.toLowerCase().includes(q) || ioc.reputation.toLowerCase().includes(q)) {
        results.push({
          id: ioc.id,
          type: 'ioc',
          title: ioc.value,
          subtitle: `IOC · ${ioc.type} · ${ioc.reputation}`,
          route: `/threat-intel`,
        });
      }
    });

    setSearchResults(results.slice(0, 12));
    setShowSearchResults(true);
  }, [searchQuery, alerts, incidents, iocs]);

  const handleResultClick = (route: string) => {
    navigate(route);
    setSearchQuery('');
    setShowSearchResults(false);
  };

  const newAlerts = alerts.filter(a => a.status === 'new');
  const notificationItems = newAlerts.slice(0, 5).map(a => ({
    id: a.id,
    title: a.title,
    subtitle: `${a.severity} · ${a.source}`,
    route: `/alerts/${a.id}`,
  }));

  const handleNotificationClick = (route: string) => {
    navigate(route);
    setShowNotifications(false);
  };

  const handleLogout = () => {
    setShowProfile(false);
    navigate('/');
  };

  const typeIcon = (type: SearchResult['type']) => {
    switch (type) {
      case 'incident': return '🛡';
      case 'alert': return '⚠';
      case 'ioc': return '◈';
    }
  };

  return (
    <>
      <header className="flex h-16 items-center justify-between border-b border-slate-800 bg-slate-900/80 backdrop-blur-sm px-6">
        <div className="flex items-center gap-4 flex-1">
          <div ref={searchRef} className="relative max-w-md w-full">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              onFocus={() => searchQuery.trim() && setShowSearchResults(true)}
              placeholder="Search alerts, incidents, IOCs..."
              className="w-full rounded-lg border border-slate-700 bg-slate-800/50 py-2 pl-10 pr-4 text-sm text-slate-200 placeholder-slate-500 outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/30 transition-colors"
            />
            {showSearchResults && searchResults.length > 0 && (
              <div className="absolute top-full left-0 right-0 mt-2 rounded-lg border border-slate-700 bg-slate-900 shadow-xl z-50 max-h-96 overflow-y-auto">
                <div className="px-3 py-2 text-xs text-slate-500 border-b border-slate-800">
                  {searchResults.length} result{searchResults.length !== 1 ? 's' : ''}
                </div>
                {searchResults.map(r => (
                  <button
                    key={`${r.type}-${r.id}`}
                    onClick={() => handleResultClick(r.route)}
                    className="flex w-full items-center gap-3 px-3 py-2.5 text-left hover:bg-slate-800 transition-colors border-b border-slate-800/50 last:border-0"
                  >
                    <span className="text-slate-500 text-sm">{typeIcon(r.type)}</span>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-slate-200 truncate">{r.title}</p>
                      <p className="text-xs text-slate-500 truncate">{r.subtitle}</p>
                    </div>
                  </button>
                ))}
              </div>
            )}
            {showSearchResults && searchQuery.trim() && searchResults.length === 0 && (
              <div className="absolute top-full left-0 right-0 mt-2 rounded-lg border border-slate-700 bg-slate-900 shadow-xl z-50 px-4 py-3 text-sm text-slate-500">
                No results found for "{searchQuery}"
              </div>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3">
          {/* Microsoft Foundry IQ Badge */}
          <button
            onClick={() => setShowFoundryIQ(true)}
            className="flex items-center gap-2 rounded-lg border border-blue-500/30 bg-gradient-to-r from-blue-500/10 to-cyan-500/10 px-3 py-1.5 hover:from-blue-500/20 hover:to-cyan-500/20 transition-colors"
            title="Open Foundry IQ Reasoning Layer"
          >
            <Brain className="h-4 w-4 text-blue-400" />
            <div className="text-xs">
              <p className="font-semibold text-blue-400">Foundry IQ</p>
              <p className="text-[9px] text-slate-500">Reasoning Layer</p>
            </div>
          </button>

          {/* Notification Bell */}
          <div ref={notifRef} className="relative">
            <button
              onClick={() => setShowNotifications(prev => !prev)}
              className="relative rounded-lg p-2 text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition-colors"
              title="Notifications"
            >
              <Bell className="h-5 w-5" />
              <span className="absolute right-1 top-1 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[10px] font-bold text-white">
                {newAlerts.length}
              </span>
            </button>
            {showNotifications && (
              <div className="absolute right-0 top-full mt-2 w-80 rounded-lg border border-slate-700 bg-slate-900 shadow-xl z-50">
                <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
                  <p className="text-sm font-medium text-slate-200">Notifications</p>
                  <span className="text-xs text-slate-500">{newAlerts.length} new</span>
                </div>
                <div className="max-h-80 overflow-y-auto">
                  {notificationItems.length > 0 ? (
                    notificationItems.map(n => (
                      <button
                        key={n.id}
                        onClick={() => handleNotificationClick(n.route)}
                        className="flex w-full items-start gap-3 px-4 py-3 text-left hover:bg-slate-800 transition-colors border-b border-slate-800/50 last:border-0"
                      >
                        <span className="mt-0.5 h-2 w-2 rounded-full bg-cyan-400 flex-shrink-0" />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm text-slate-200 truncate">{n.title}</p>
                          <p className="text-xs text-slate-500 truncate">{n.subtitle}</p>
                        </div>
                      </button>
                    ))
                  ) : (
                    <div className="px-4 py-6 text-center text-sm text-slate-500">No new notifications</div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* User Profile */}
          <div ref={profileRef} className="relative">
            <button
              onClick={() => setShowProfile(prev => !prev)}
              className="flex items-center gap-3 rounded-lg border border-slate-700 bg-slate-800/50 px-3 py-1.5 hover:bg-slate-800 transition-colors"
              title="User profile"
            >
              <Shield className="h-4 w-4 text-cyan-400" />
              <div className="text-xs text-left">
                <p className="font-medium text-slate-200">SOC Analyst</p>
                <p className="text-slate-500">Tier 2</p>
              </div>
              <ChevronDown className="h-3 w-3 text-slate-500" />
            </button>
            {showProfile && (
              <div className="absolute right-0 top-full mt-2 w-64 rounded-lg border border-slate-700 bg-slate-900 shadow-xl z-50">
                <div className="px-4 py-3 border-b border-slate-800">
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-full bg-cyan-500/20 border border-cyan-500/30">
                      <Shield className="h-5 w-5 text-cyan-400" />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-slate-200">SOC Analyst</p>
                      <p className="text-xs text-slate-500">Tier 2 · Security Operations</p>
                    </div>
                  </div>
                </div>
                <div className="py-1">
                  <button className="flex w-full items-center gap-3 px-4 py-2.5 text-left text-sm text-slate-300 hover:bg-slate-800 transition-colors">
                    <User className="h-4 w-4 text-slate-500" />
                    Profile
                  </button>
                  <button
                    onClick={handleLogout}
                    className="flex w-full items-center gap-3 px-4 py-2.5 text-left text-sm text-slate-300 hover:bg-slate-800 transition-colors"
                  >
                    <LogOut className="h-4 w-4 text-slate-500" />
                    Logout
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Foundry IQ Reasoning Layer Modal */}
      {showFoundryIQ && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
          onClick={() => setShowFoundryIQ(false)}
        >
          <div
            className="w-full max-w-2xl rounded-xl border border-slate-700 bg-slate-900 shadow-2xl"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-slate-800 px-6 py-4">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-500/20 border border-blue-500/30">
                  <Brain className="h-5 w-5 text-blue-400" />
                </div>
                <div>
                  <h2 className="text-base font-semibold text-slate-100">Foundry IQ Reasoning Layer</h2>
                  <p className="text-xs text-slate-500">AI analysis context</p>
                </div>
              </div>
              <button
                onClick={() => setShowFoundryIQ(false)}
                className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition-colors"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <div className="px-6 py-6">
              <div className="rounded-lg border border-slate-800 bg-slate-800/30 p-4">
                <p className="text-sm text-slate-300">
                  Foundry IQ Reasoning Layer — AI analysis context will appear here.
                </p>
                <p className="text-xs text-slate-500 mt-3">
                  The reasoning layer correlates alerts, incidents, IOCs, and MITRE ATT&CK mappings to provide contextual analysis and recommended actions for the SOC analyst.
                </p>
              </div>
              <div className="mt-4 grid grid-cols-3 gap-3">
                <div className="rounded-lg border border-slate-800 bg-slate-800/30 p-3">
                  <p className="text-xs text-slate-500">Active Incidents</p>
                  <p className="text-lg font-semibold text-slate-200 mt-1">{incidents.length}</p>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-800/30 p-3">
                  <p className="text-xs text-slate-500">Open Alerts</p>
                  <p className="text-lg font-semibold text-slate-200 mt-1">{alerts.length}</p>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-800/30 p-3">
                  <p className="text-xs text-slate-500">Tracked IOCs</p>
                  <p className="text-lg font-semibold text-slate-200 mt-1">{iocs.length}</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
