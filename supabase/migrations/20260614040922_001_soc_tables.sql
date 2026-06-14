/*
# Create AI SOC Assistant Tables
Single-tenant app. 7 tables: incidents, alerts, mitre_mappings, iocs, reports, uploads, audit_logs.
RLS enabled with public access policies for anon + authenticated.
*/
CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL, description TEXT,
    severity TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('critical','high','medium','low','info')),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','investigating','contained','resolved','closed')),
    ai_summary TEXT, attack_vector TEXT,
    impact_score INTEGER DEFAULT 1 CHECK (impact_score BETWEEN 1 AND 10),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source TEXT NOT NULL DEFAULT 'manual',
    raw_payload JSONB NOT NULL DEFAULT '{}',
    title TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'low' CHECK (severity IN ('critical','high','medium','low','info')),
    status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','triaged','escalated','closed')),
    threat_type TEXT, confidence REAL DEFAULT 0.0,
    incident_id UUID REFERENCES incidents(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS mitre_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    technique_id TEXT NOT NULL, technique_name TEXT NOT NULL, tactic TEXT NOT NULL,
    sub_technique TEXT, confidence REAL NOT NULL DEFAULT 0.5,
    reasoning TEXT, mapped_by TEXT NOT NULL DEFAULT 'agent',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS iocs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    type TEXT NOT NULL CHECK (type IN ('ip','domain','hash','url','email','cve','other')),
    value TEXT NOT NULL,
    reputation TEXT DEFAULT 'unknown' CHECK (reputation IN ('malicious','suspicious','clean','unknown')),
    enrichment_data JSONB DEFAULT '{}',
    first_seen TIMESTAMPTZ, last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    report_type TEXT NOT NULL DEFAULT 'full' CHECK (report_type IN ('full','executive','technical')),
    content_json JSONB NOT NULL DEFAULT '{}',
    generated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS uploads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    original_name TEXT NOT NULL, stored_name TEXT NOT NULL,
    mime_type TEXT NOT NULL DEFAULT 'text/plain',
    file_size INTEGER NOT NULL DEFAULT 0, sha256 TEXT,
    analysis_result JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action TEXT NOT NULL, resource_type TEXT NOT NULL,
    resource_id UUID, details JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_mitre_incident ON mitre_mappings(incident_id);
CREATE INDEX IF NOT EXISTS idx_iocs_incident ON iocs(incident_id);
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE mitre_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE iocs ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE uploads ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "incidents_select" ON incidents;
CREATE POLICY "incidents_select" ON incidents FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "incidents_insert" ON incidents;
CREATE POLICY "incidents_insert" ON incidents FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "incidents_update" ON incidents;
CREATE POLICY "incidents_update" ON incidents FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "incidents_delete" ON incidents;
CREATE POLICY "incidents_delete" ON incidents FOR DELETE TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "alerts_select" ON alerts;
CREATE POLICY "alerts_select" ON alerts FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "alerts_insert" ON alerts;
CREATE POLICY "alerts_insert" ON alerts FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "alerts_update" ON alerts;
CREATE POLICY "alerts_update" ON alerts FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "alerts_delete" ON alerts;
CREATE POLICY "alerts_delete" ON alerts FOR DELETE TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "mitre_select" ON mitre_mappings;
CREATE POLICY "mitre_select" ON mitre_mappings FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "mitre_insert" ON mitre_mappings;
CREATE POLICY "mitre_insert" ON mitre_mappings FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "mitre_update" ON mitre_mappings;
CREATE POLICY "mitre_update" ON mitre_mappings FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "mitre_delete" ON mitre_mappings;
CREATE POLICY "mitre_delete" ON mitre_mappings FOR DELETE TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "iocs_select" ON iocs;
CREATE POLICY "iocs_select" ON iocs FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "iocs_insert" ON iocs;
CREATE POLICY "iocs_insert" ON iocs FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "iocs_update" ON iocs;
CREATE POLICY "iocs_update" ON iocs FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "iocs_delete" ON iocs;
CREATE POLICY "iocs_delete" ON iocs FOR DELETE TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "reports_select" ON reports;
CREATE POLICY "reports_select" ON reports FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "reports_insert" ON reports;
CREATE POLICY "reports_insert" ON reports FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "reports_delete" ON reports;
CREATE POLICY "reports_delete" ON reports FOR DELETE TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "uploads_select" ON uploads;
CREATE POLICY "uploads_select" ON uploads FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "uploads_insert" ON uploads;
CREATE POLICY "uploads_insert" ON uploads FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "uploads_delete" ON uploads;
CREATE POLICY "uploads_delete" ON uploads FOR DELETE TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "audit_select" ON audit_logs;
CREATE POLICY "audit_select" ON audit_logs FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "audit_insert" ON audit_logs;
CREATE POLICY "audit_insert" ON audit_logs FOR INSERT TO anon, authenticated WITH CHECK (true);