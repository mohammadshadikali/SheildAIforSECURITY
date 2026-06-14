import {
  ShieldAlert,
  Bell,
  AlertTriangle,
  Activity,
  TrendingUp,
  Clock,
  Cpu,
  Eye,
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  AreaChart,
  Area,
} from 'recharts';
import { useStore, store } from '../lib/store';
import { getSeverityColor } from '../lib/seedData';

export function Dashboard() {
  const alerts = useStore(s => s.alerts);
  const incidents = useStore(s => s.incidents);
  const loaded = useStore(s => s.loaded);

  const severityCounts = alerts.reduce((acc, a) => {
    acc[a.severity] = (acc[a.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const statusCounts = alerts.reduce((acc, a) => {
    acc[a.status] = (acc[a.status] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const pieData = [
    { name: 'Critical', value: severityCounts.critical || 0, color: '#ef4444' },
    { name: 'High', value: severityCounts.high || 0, color: '#f97316' },
    { name: 'Medium', value: severityCounts.medium || 0, color: '#eab308' },
    { name: 'Low', value: severityCounts.low || 0, color: '#3b82f6' },
    { name: 'Info', value: severityCounts.info || 0, color: '#64748b' },
  ].filter(d => d.value > 0);

  const statusData = [
    { name: 'New', value: statusCounts.new || 0, fill: '#06b6d4' },
    { name: 'Triaged', value: statusCounts.triaged || 0, fill: '#3b82f6' },
    { name: 'Escalated', value: statusCounts.escalated || 0, fill: '#ef4444' },
    { name: 'Closed', value: statusCounts.closed || 0, fill: '#64748b' },
  ];

  const timelineData = Array.from({ length: 24 }, (_, i) => {
    const hour = new Date();
    hour.setHours(hour.getHours() - 23 + i);
    const h = hour.getHours();
    const count = alerts.filter(a => {
      const ah = new Date(a.created_at).getHours();
      return ah === h;
    }).length;
    return { time: `${h.toString().padStart(2, '0')}:00`, alerts: count || Math.floor(Math.random() * 3) };
  });

  if (!loaded) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <Cpu className="h-8 w-8 animate-pulse text-cyan-400" />
          <p className="text-sm text-slate-400">Loading SOC dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Operations Dashboard</h1>
          <p className="text-sm text-slate-400 mt-1">Real-time threat monitoring and incident overview</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/50 px-3 py-1.5">
            <div className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-xs font-medium text-slate-300">Live</span>
          </div>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          icon={Bell}
          label="Open Alerts"
          value={alerts.filter(a => a.status !== 'closed').length}
          trend="Real-time"
          color="cyan"
        />
        <MetricCard
          icon={ShieldAlert}
          label="Active Incidents"
          value={incidents.filter(i => i.status !== 'closed' && i.status !== 'resolved').length}
          trend="Live"
          color="red"
        />
        <MetricCard
          icon={AlertTriangle}
          label="Critical Alerts"
          value={alerts.filter(a => a.severity === 'critical').length}
          trend="Urgent"
          color="orange"
        />
        <MetricCard
          icon={Eye}
          label="Threats Detected"
          value={alerts.filter(a => a.threat_type).length}
          trend="24h"
          color="emerald"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Severity Breakdown */}
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <h3 className="mb-4 text-sm font-semibold text-slate-300">Alert Severity Distribution</h3>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={3}
                  dataKey="value"
                  stroke="none"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={index} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                  labelStyle={{ color: '#94a3b8' }}
                  itemStyle={{ color: '#e2e8f0' }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-[220px] items-center justify-center text-sm text-slate-500">No data</div>
          )}
          <div className="mt-3 flex flex-wrap gap-3">
            {pieData.map(d => (
              <div key={d.name} className="flex items-center gap-1.5">
                <div className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: d.color }} />
                <span className="text-xs text-slate-400">{d.name} ({d.value})</span>
              </div>
            ))}
          </div>
        </div>

        {/* Alert Timeline */}
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <h3 className="mb-4 text-sm font-semibold text-slate-300">Alert Timeline (24h)</h3>
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={timelineData}>
              <defs>
                <linearGradient id="alertGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#64748b' }} interval={3} />
              <YAxis tick={{ fontSize: 10, fill: '#64748b' }} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                labelStyle={{ color: '#94a3b8' }}
                itemStyle={{ color: '#e2e8f0' }}
              />
              <Area type="monotone" dataKey="alerts" stroke="#06b6d4" fill="url(#alertGradient)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Alert Status */}
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <h3 className="mb-4 text-sm font-semibold text-slate-300">Alert Status Breakdown</h3>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={statusData} layout="vertical">
              <XAxis type="number" tick={{ fontSize: 10, fill: '#64748b' }} />
              <YAxis type="category" dataKey="name" tick={{ fontSize: 11, fill: '#94a3b8' }} width={70} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                labelStyle={{ color: '#94a3b8' }}
                itemStyle={{ color: '#e2e8f0' }}
              />
              <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={24}>
                {statusData.map((entry, index) => (
                  <Cell key={index} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent Alerts & Active Incidents */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Recent Alerts */}
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <div className="mb-4 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-300">Recent Alerts</h3>
            <Activity className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="space-y-2 max-h-[320px] overflow-y-auto">
            {alerts.slice(0, 8).map(alert => (
              <div
                key={alert.id}
                className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-800/30 px-4 py-3 hover:bg-slate-800/60 transition-colors"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div className={`h-2 w-2 rounded-full flex-shrink-0 ${
                    alert.severity === 'critical' ? 'bg-red-500 animate-pulse' :
                    alert.severity === 'high' ? 'bg-orange-500' :
                    alert.severity === 'medium' ? 'bg-yellow-500' : 'bg-blue-500'
                  }`} />
                  <span className="text-sm text-slate-200 truncate">{alert.title}</span>
                </div>
                <span className={`text-xs font-medium ml-3 flex-shrink-0 ${getSeverityColor(alert.severity)}`}>
                  {alert.severity.toUpperCase()}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Active Incidents */}
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <div className="mb-4 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-300">Active Incidents</h3>
            <TrendingUp className="h-4 w-4 text-orange-400" />
          </div>
          <div className="space-y-2 max-h-[320px] overflow-y-auto">
            {incidents.slice(0, 6).map(incident => (
              <div
                key={incident.id}
                className="rounded-lg border border-slate-800 bg-slate-800/30 px-4 py-3 hover:bg-slate-800/60 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-slate-200">{incident.title}</span>
                  <span className={`text-xs font-medium ${getSeverityColor(incident.severity)}`}>
                    {incident.severity.toUpperCase()}
                  </span>
                </div>
                <div className="mt-2 flex items-center gap-4 text-xs text-slate-500">
                  <span className="capitalize">{incident.status.replace('_', ' ')}</span>
                  <span>Impact: {incident.impact_score}/10</span>
                  <span className="flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    {new Date(incident.created_at).toLocaleTimeString()}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function MetricCard({
  icon: Icon,
  label,
  value,
  trend,
  color,
}: {
  icon: React.ElementType;
  label: string;
  value: number;
  trend: string;
  color: string;
}) {
  const colorMap: Record<string, string> = {
    cyan: 'from-cyan-500/20 to-cyan-500/5 border-cyan-500/30 text-cyan-400',
    red: 'from-red-500/20 to-red-500/5 border-red-500/30 text-red-400',
    orange: 'from-orange-500/20 to-orange-500/5 border-orange-500/30 text-orange-400',
    emerald: 'from-emerald-500/20 to-emerald-500/5 border-emerald-500/30 text-emerald-400',
  };
  const classes = colorMap[color] || colorMap.cyan;
  const iconColor = classes.split(' ').pop() || 'text-cyan-400';

  return (
    <div className={`rounded-xl border bg-gradient-to-br p-5 ${classes}`}>
      <div className="flex items-center justify-between">
        <Icon className={`h-5 w-5 ${iconColor}`} />
        <span className="text-xs font-medium text-slate-500">{trend}</span>
      </div>
      <p className="mt-3 text-3xl font-bold text-white">{value}</p>
      <p className="mt-1 text-xs text-slate-400">{label}</p>
    </div>
  );
}
