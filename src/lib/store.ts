import { supabase } from './supabase';

export interface AlertRecord {
  id: string;
  title: string;
  source: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: 'new' | 'triaged' | 'escalated' | 'closed';
  threat_type: string;
  confidence: number;
  raw_payload: Record<string, unknown>;
  incident_id?: string | null;
  created_at: string;
}

export interface IncidentRecord {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: 'open' | 'investigating' | 'contained' | 'resolved' | 'closed';
  attack_vector: string;
  impact_score: number;
  ai_summary: string;
  created_at: string;
  updated_at: string;
}

export interface IOCRecord {
  id: string;
  incident_id?: string | null;
  alert_id?: string | null;
  type: 'ip' | 'domain' | 'hash' | 'url' | 'email' | 'cve' | 'other';
  value: string;
  reputation: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  enrichment_data: Record<string, unknown>;
  first_seen?: string | null;
  last_seen?: string | null;
  created_at: string;
}

export interface MitreMappingRecord {
  id: string;
  incident_id: string;
  technique_id: string;
  technique_name: string;
  tactic: string;
  sub_technique?: string | null;
  confidence: number;
  reasoning: string;
  mapped_by: string;
  created_at: string;
}

export interface ReportRecord {
  id: string;
  incident_id: string;
  report_type: 'full' | 'executive' | 'technical';
  content_json: Record<string, unknown>;
  generated_at: string;
}

export interface AuditRecord {
  id: string;
  action: string;
  resource_type: string;
  resource_id?: string | null;
  details: Record<string, unknown>;
  created_at: string;
}

type EventHandler = () => void;
const listeners: Set<EventHandler> = new Set();

export function subscribe(handler: EventHandler): () => void {
  listeners.add(handler);
  return () => listeners.delete(handler);
}

function notify() {
  listeners.forEach(h => h());
}

// ---- In-memory store (falls back when Supabase is unavailable) ----

export const store = {
  alerts: [] as AlertRecord[],
  incidents: [] as IncidentRecord[],
  iocs: [] as IOCRecord[],
  mitreMappings: [] as MitreMappingRecord[],
  reports: [] as ReportRecord[],
  auditLogs: [] as AuditRecord[],
  loaded: false,
};

// ---- CRUD operations ----

export async function createAlert(alert: Omit<AlertRecord, 'id' | 'created_at'>): Promise<AlertRecord> {
  const record: AlertRecord = {
    ...alert,
    id: `alert-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    created_at: new Date().toISOString(),
  };

  try {
    const { data } = await supabase.from('alerts').insert({
      source: record.source,
      raw_payload: record.raw_payload,
      title: record.title,
      severity: record.severity,
      status: record.status,
      threat_type: record.threat_type,
      confidence: record.confidence,
    }).select().maybeSingle();
    if (data) Object.assign(record, data);
  } catch { /* use local */ }

  store.alerts.unshift(record);
  logAudit('ALERT_CREATED', 'alert', record.id, { severity: record.severity, threat_type: record.threat_type });
  notify();
  return record;
}

export async function createIncident(incident: Omit<IncidentRecord, 'id' | 'created_at' | 'updated_at'>): Promise<IncidentRecord> {
  const record: IncidentRecord = {
    ...incident,
    id: `inc-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  try {
    const { data } = await supabase.from('incidents').insert({
      title: record.title,
      description: record.description,
      severity: record.severity,
      status: record.status,
      attack_vector: record.attack_vector,
      impact_score: record.impact_score,
      ai_summary: record.ai_summary,
    }).select().maybeSingle();
    if (data) Object.assign(record, data);
  } catch { /* use local */ }

  store.incidents.unshift(record);
  logAudit('INCIDENT_CREATED', 'incident', record.id, { severity: record.severity, title: record.title });
  notify();
  return record;
}

export async function updateIncident(id: string, updates: Partial<IncidentRecord>): Promise<void> {
  const idx = store.incidents.findIndex(i => i.id === id);
  if (idx >= 0) {
    Object.assign(store.incidents[idx], updates, { updated_at: new Date().toISOString() });
  }

  try {
    await supabase.from('incidents').update(updates).eq('id', id);
  } catch { /* local only */ }

  logAudit('INCIDENT_UPDATED', 'incident', id, updates);
  notify();
}

export async function linkAlertToIncident(alertId: string, incidentId: string): Promise<void> {
  const alert = store.alerts.find(a => a.id === alertId);
  if (alert) {
    alert.incident_id = incidentId;
    alert.status = 'escalated';
  }

  try {
    await supabase.from('alerts').update({ incident_id: incidentId, status: 'escalated' }).eq('id', alertId);
  } catch { /* local only */ }

  logAudit('ALERT_LINKED', 'alert', alertId, { incident_id: incidentId });
  notify();
}

export async function createIOC(ioc: Omit<IOCRecord, 'id' | 'created_at'>): Promise<IOCRecord> {
  const record: IOCRecord = {
    ...ioc,
    id: `ioc-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    created_at: new Date().toISOString(),
  };

  try {
    const { data } = await supabase.from('iocs').insert({
      incident_id: record.incident_id,
      alert_id: record.alert_id,
      type: record.type,
      value: record.value,
      reputation: record.reputation,
      enrichment_data: record.enrichment_data,
      first_seen: record.first_seen,
      last_seen: record.last_seen,
    }).select().maybeSingle();
    if (data) Object.assign(record, data);
  } catch { /* local */ }

  store.iocs.unshift(record);
  notify();
  return record;
}

export async function createMitreMapping(mapping: Omit<MitreMappingRecord, 'id' | 'created_at'>): Promise<MitreMappingRecord> {
  const record: MitreMappingRecord = {
    ...mapping,
    id: `mitre-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    created_at: new Date().toISOString(),
  };

  try {
    const { data } = await supabase.from('mitre_mappings').insert({
      incident_id: record.incident_id,
      technique_id: record.technique_id,
      technique_name: record.technique_name,
      tactic: record.tactic,
      sub_technique: record.sub_technique,
      confidence: record.confidence,
      reasoning: record.reasoning,
      mapped_by: record.mapped_by,
    }).select().maybeSingle();
    if (data) Object.assign(record, data);
  } catch { /* local */ }

  store.mitreMappings.unshift(record);
  logAudit('MITRE_MAPPED', 'mitre_mapping', record.technique_id, { incident_id: record.incident_id, confidence: record.confidence });
  notify();
  return record;
}

export async function createReport(report: Omit<ReportRecord, 'id' | 'generated_at'>): Promise<ReportRecord> {
  const record: ReportRecord = {
    ...report,
    id: `report-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    generated_at: new Date().toISOString(),
  };

  try {
    const { data } = await supabase.from('reports').insert({
      incident_id: record.incident_id,
      report_type: record.report_type,
      content_json: record.content_json,
    }).select().maybeSingle();
    if (data) Object.assign(record, data);
  } catch { /* local */ }

  store.reports.unshift(record);
  logAudit('REPORT_GENERATED', 'report', record.id, { type: record.report_type, incident_id: record.incident_id });
  notify();
  return record;
}

async function logAudit(action: string, resourceType: string, resourceId: string, details: Record<string, unknown>): Promise<void> {
  const record: AuditRecord = {
    id: `audit-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    action,
    resource_type: resourceType,
    resource_id: resourceId,
    details,
    created_at: new Date().toISOString(),
  };

  store.auditLogs.unshift(record);

  try {
    await supabase.from('audit_logs').insert({
      action: record.action,
      resource_type: record.resource_type,
      resource_id: record.resource_id,
      details: record.details,
    });
  } catch { /* local only */ }
}

// ---- Initialization with demo data ----

import { DEMO_ALERTS, DEMO_INCIDENTS } from './seedData';

export async function initializeStore(): Promise<void> {
  if (store.loaded) return;

  try {
    const [alertRes, incidentRes, iocRes, reportRes, auditRes, mitreRes] = await Promise.all([
      supabase.from('alerts').select('*').order('created_at', { ascending: false }),
      supabase.from('incidents').select('*').order('created_at', { ascending: false }),
      supabase.from('iocs').select('*').order('created_at', { ascending: false }),
      supabase.from('reports').select('*').order('generated_at', { ascending: false }),
      supabase.from('audit_logs').select('*').order('created_at', { ascending: false }),
      supabase.from('mitre_mappings').select('*').order('created_at', { ascending: false }),
    ]);

    if (alertRes.data && alertRes.data.length > 0) {
      store.alerts = alertRes.data as AlertRecord[];
      store.incidents = incidentRes.data as IncidentRecord[];
      store.iocs = iocRes.data as IOCRecord[];
      store.reports = reportRes.data as ReportRecord[];
      store.auditLogs = auditRes.data as AuditRecord[];
      store.mitreMappings = mitreRes.data as MitreMappingRecord[];
      store.loaded = true;
      notify();
      return;
    }
  } catch { /* fallback to demo */ }

  // Seed demo data into local store
  store.incidents = DEMO_INCIDENTS.map((inc, i) => ({
    id: `demo-inc-${i}`,
    ...inc,
    created_at: new Date(Date.now() - i * 7200000).toISOString(),
    updated_at: new Date(Date.now() - i * 3600000).toISOString(),
  }));

  store.alerts = DEMO_ALERTS.map((a, i) => ({
    id: `demo-alert-${i}`,
    ...a,
    incident_id: i < 4 ? store.incidents[Math.min(i, store.incidents.length - 1)]?.id || null : null,
    created_at: new Date(Date.now() - i * 3600000).toISOString(),
  })) as AlertRecord[];

  store.iocs = [
    { id: 'demo-ioc-0', incident_id: 'demo-inc-0', type: 'ip', value: '185.220.101.34', reputation: 'malicious', enrichment_data: { country: 'DE', asn: 'AS131342', tor_exit: true }, first_seen: '2026-06-12T02:15:00Z', last_seen: '2026-06-12T04:30:00Z', created_at: new Date(Date.now() - 3600000).toISOString() },
    { id: 'demo-ioc-1', incident_id: 'demo-inc-0', type: 'ip', value: '45.33.32.156', reputation: 'malicious', enrichment_data: { country: 'US', asn: 'AS63949', known_attacker: true }, first_seen: '2026-06-12T06:45:00Z', last_seen: '2026-06-12T06:45:00Z', created_at: new Date(Date.now() - 7200000).toISOString() },
    { id: 'demo-ioc-2', incident_id: 'demo-inc-2', type: 'ip', value: '91.134.22.18', reputation: 'suspicious', enrichment_data: { country: 'RU', asn: 'AS12389' }, first_seen: '2026-06-12T08:35:00Z', last_seen: '2026-06-12T08:35:00Z', created_at: new Date(Date.now() - 10800000).toISOString() },
    { id: 'demo-ioc-3', incident_id: 'demo-inc-3', type: 'hash', value: 'a3f2b8c9d1e4f5a6b7c8d9e0f1a2b3c4', reputation: 'malicious', enrichment_data: { vt_score: '54/72', malware_family: 'Lock3D' }, created_at: new Date(Date.now() - 14400000).toISOString() },
    { id: 'demo-ioc-4', incident_id: 'demo-inc-3', type: 'domain', value: 'update-service.darkcloud.xyz', reputation: 'malicious', enrichment_data: { resolved_ip: '91.215.85.42', registered: '2026-05-20' }, created_at: new Date(Date.now() - 18000000).toISOString() },
    { id: 'demo-ioc-5', incident_id: 'demo-inc-3', type: 'url', value: 'https://micr0soft-secure.com/login', reputation: 'malicious', enrichment_data: { phishing_kit: 'M365 PhishKit v2.1' }, created_at: new Date(Date.now() - 21600000).toISOString() },
    { id: 'demo-ioc-6', incident_id: 'demo-inc-1', type: 'email', value: 'it-support@micr0soft-secure.com', reputation: 'malicious', enrichment_data: { spoofed: true, spf_fail: true }, created_at: new Date(Date.now() - 25200000).toISOString() },
    { id: 'demo-ioc-7', type: 'cve', value: 'CVE-2026-2931', reputation: 'suspicious', enrichment_data: { cvss: 8.1, product: 'Apache Struts' }, created_at: new Date(Date.now() - 28800000).toISOString() },
    { id: 'demo-ioc-8', type: 'ip', value: '203.0.113.50', reputation: 'clean', enrichment_data: { country: 'US', asn: 'AS7018' }, created_at: new Date(Date.now() - 32400000).toISOString() },
  ] as IOCRecord[];

  store.auditLogs = [
    { id: 'demo-audit-0', action: 'ALERT_CREATED', resource_type: 'alert', resource_id: 'demo-alert-0', details: { source: 'IDS/Suricata', severity: 'critical' }, created_at: new Date(Date.now() - 3600000).toISOString() },
    { id: 'demo-audit-1', action: 'INCIDENT_CREATED', resource_type: 'incident', resource_id: 'demo-inc-0', details: { severity: 'critical' }, created_at: new Date(Date.now() - 7200000).toISOString() },
    { id: 'demo-audit-2', action: 'MITRE_MAPPED', resource_type: 'mitre_mapping', resource_id: 'T1110', details: { confidence: 0.92 }, created_at: new Date(Date.now() - 10800000).toISOString() },
    { id: 'demo-audit-3', action: 'REPORT_GENERATED', resource_type: 'report', resource_id: 'demo-report-0', details: { type: 'full' }, created_at: new Date(Date.now() - 14400000).toISOString() },
  ] as AuditRecord[];

  store.loaded = true;
  notify();
}

// Custom hook
import { useState, useEffect } from 'react';

export function useStore<T>(selector: (s: typeof store) => T): T {
  const [value, setValue] = useState(() => selector(store));

  useEffect(() => {
    const unsub = subscribe(() => {
      setValue(selector(store));
    });
    return unsub;
  }, [selector]);

  return value;
}
