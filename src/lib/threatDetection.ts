export interface ThreatDetectionResult {
  threatType: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: number;
  title: string;
  description: string;
  iocs: Array<{ type: string; value: string; reputation: string }>;
  mitreTechniques: Array<{ id: string; name: string; tactic: string }>;
}

interface LogEntry {
  timestamp?: string;
  message?: string;
  source_ip?: string;
  dest_ip?: string;
  username?: string;
  action?: string;
  status?: string;
  url?: string;
  method?: string;
  user_agent?: string;
  response_code?: number;
  query?: string;
  [key: string]: unknown;
}

function extractIPs(line: string): string[] {
  const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  return line.match(ipRegex) || [];
}

function extractEmails(line: string): string[] {
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
  return line.match(emailRegex) || [];
}

function extractHashes(line: string): string[] {
  const hashRegex = /\b[a-fA-F0-9]{32,64}\b/g;
  return line.match(hashRegex) || [];
}

function extractUrls(line: string): string[] {
  const urlRegex = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;
  return line.match(urlRegex) || [];
}

function detectBruteForce(entries: LogEntry[]): ThreatDetectionResult | null {
  const failedLogins = entries.filter(e =>
    (e.action === 'login' || e.message?.toLowerCase().includes('login') || e.message?.toLowerCase().includes('authentication')) &&
    (e.status === 'failed' || e.message?.toLowerCase().includes('failed') || e.message?.toLowerCase().includes('denied') || e.message?.toLowerCase().includes('invalid'))
  );

  if (failedLogins.length < 3) return null;

  const ipCounts: Record<string, number> = {};
  const userCounts: Record<string, number> = {};
  const targetIps: string[] = [];

  failedLogins.forEach(e => {
    const msg = (e.message || '') + ' ' + (e.source_ip || '');
    const ips = extractIPs(msg);
    ips.forEach(ip => { ipCounts[ip] = (ipCounts[ip] || 0) + 1; });
    if (e.username) userCounts[e.username] = (userCounts[e.username] || 0) + 1;
    if (e.dest_ip) targetIps.push(e.dest_ip);
  });

  const topIP = Object.entries(ipCounts).sort((a, b) => b[1] - a[1])[0];
  const topUser = Object.entries(userCounts).sort((a, b) => b[1] - a[1])[0];
  const severity = failedLogins.length >= 20 ? 'critical' : failedLogins.length >= 10 ? 'high' : 'medium';
  const confidence = Math.min(0.99, 0.5 + failedLogins.length * 0.03);

  const iocs: Array<{ type: string; value: string; reputation: string }> = [];
  if (topIP) iocs.push({ type: 'ip', value: topIP[0], reputation: 'malicious' });
  targetIps.forEach(ip => { if (!iocs.find(i => i.value === ip)) iocs.push({ type: 'ip', value: ip, reputation: 'suspicious' }); });

  return {
    threatType: 'brute_force',
    severity,
    confidence,
    title: `Brute Force Attack Detected (${failedLogins.length} failed attempts)`,
    description: `${failedLogins.length} failed login attempts detected${topIP ? ` from ${topIP[0]} (${topIP[1]} attempts)` : ''}${topUser ? ` targeting user "${topUser[0]}"` : ''}. This pattern is consistent with automated credential stuffing or brute force attack tools.`,
    iocs,
    mitreTechniques: [
      { id: 'T1110.001', name: 'Brute Force: Password Guessing', tactic: 'Credential Access' },
      { id: 'T1110.003', name: 'Brute Force: Password Spraying', tactic: 'Credential Access' },
      { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion' },
    ],
  };
}

function detectSQLInjection(entries: LogEntry[]): ThreatDetectionResult | null {
  const sqliPatterns = [
    /(\bUNION\b\s+\bSELECT\b)/i,
    /(\bOR\b\s+1\s*=\s*1)/i,
    /(\bAND\b\s+1\s*=\s*1)/i,
    /(';|--|\/\*|\*\/)/i,
    /(\bDROP\b\s+\bTABLE\b)/i,
    /(\bINSERT\b\s+\bINTO\b)/i,
    /(\bSELECT\b\s+.*\bFROM\b)/i,
    /(\bXP_CMDSHELL\b)/i,
    /(\bWAITFOR\b\s+\bDELAY\b)/i,
    /(\bBENCHMARK\b\s*\()/i,
    /(\bSLEEP\b\s*\()/i,
    /(CONCAT\s*\()/i,
    /(%27|%22|%3B|%2D%2D)/i,
  ];

  const suspicious: LogEntry[] = [];
  const matchedIocs: Array<{ type: string; value: string; reputation: string }> = [];

  entries.forEach(e => {
    const text = [e.url, e.query, e.message, JSON.stringify(e.raw_payload || '')].join(' ');
    if (sqliPatterns.some(p => p.test(text))) {
      suspicious.push(e);
      const ips = extractIPs(text);
      ips.forEach(ip => { if (!matchedIocs.find(i => i.value === ip)) matchedIocs.push({ type: 'ip', value: ip, reputation: 'malicious' }); });
      const urls = extractUrls(text);
      urls.forEach(u => { if (!matchedIocs.find(i => i.value === u)) matchedIocs.push({ type: 'url', value: u, reputation: 'malicious' }); });
    }
  });

  if (suspicious.length === 0) return null;

  const severity = suspicious.length >= 5 ? 'critical' : suspicious.length >= 2 ? 'high' : 'medium';
  const confidence = Math.min(0.95, 0.6 + suspicious.length * 0.05);

  return {
    threatType: 'sql_injection',
    severity,
    confidence,
    title: `SQL Injection Attack Detected (${suspicious.length} malicious queries)`,
    description: `${suspicious.length} SQL injection patterns detected in request data. Indicators include UNION-based, boolean-based, and time-based injection attempts. This suggests an active attempt to extract or manipulate database contents.`,
    iocs: matchedIocs,
    mitreTechniques: [
      { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
      { id: 'T1071.001', name: 'Application Layer Protocol: Web Protocols', tactic: 'Command and Control' },
    ],
  };
}

function detectSuspiciousLogin(entries: LogEntry[]): ThreatDetectionResult | null {
  const loginEntries = entries.filter(e =>
    e.action === 'login' || e.message?.toLowerCase().includes('login') || e.message?.toLowerCase().includes('session')
  );

  if (loginEntries.length === 0) return null;

  const suspiciousLogins: LogEntry[] = [];
  const userLocations: Record<string, Set<string>> = {};
  const userTimes: Record<string, number[]> = {};
  const iocs: Array<{ type: string; value: string; reputation: string }> = [];

  loginEntries.forEach(e => {
    const msg = e.message || '';
    const isSuccessful = e.status === 'success' || msg.toLowerCase().includes('success');
    if (!isSuccessful) return;

    const ip = e.source_ip || extractIPs(msg)[0] || '';
    const user = e.username || '';
    const hour = e.timestamp ? new Date(e.timestamp).getHours() : -1;

    if (user && ip) {
      if (!userLocations[user]) userLocations[user] = new Set();
      if (!userTimes[user]) userTimes[user] = [];

      const prevCount = userLocations[user].size;
      userLocations[user].add(ip);
      if (prevCount > 0 && userLocations[user].size > prevCount) {
        suspiciousLogins.push(e);
        if (!iocs.find(i => i.value === ip)) iocs.push({ type: 'ip', value: ip, reputation: 'suspicious' });
      }

      if (hour >= 0) {
        userTimes[user].push(hour);
        if (userTimes[user].length > 1) {
          const hours = userTimes[user];
          const maxH = Math.max(...hours);
          const minH = Math.min(...hours);
          if (maxH - minH > 12 && hours.length < 5) {
            suspiciousLogins.push(e);
          }
        }
      }
    }

    const ua = e.user_agent || '';
    if (ua && (ua.toLowerCase().includes('curl') || ua.toLowerCase().includes('python') || ua.toLowerCase().includes('scanner'))) {
      suspiciousLogins.push(e);
      if (ip && !iocs.find(i => i.value === ip)) iocs.push({ type: 'ip', value: ip, reputation: 'suspicious' });
    }
  });

  if (suspiciousLogins.length === 0) return null;

  const severity = suspiciousLogins.length >= 5 ? 'high' : 'medium';
  const confidence = Math.min(0.85, 0.4 + suspiciousLogins.length * 0.1);

  return {
    threatType: 'suspicious_login',
    severity,
    confidence,
    title: `Suspicious Login Activity (${suspiciousLogins.length} anomalies)`,
    description: `${suspiciousLogins.length} suspicious login patterns detected. Anomalies include logins from new geographic locations, unusual time patterns, or automated user agents. This may indicate compromised credentials or unauthorized access.`,
    iocs,
    mitreTechniques: [
      { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion' },
      { id: 'T1078.003', name: 'Valid Accounts: Local Accounts', tactic: 'Persistence' },
      { id: 'T1110.003', name: 'Brute Force: Password Spraying', tactic: 'Credential Access' },
    ],
  };
}

export function analyzeLogs(logContent: string): ThreatDetectionResult[] {
  const lines = logContent.split('\n').filter(l => l.trim());
  const entries: LogEntry[] = lines.map(line => {
    try {
      const parsed = JSON.parse(line);
      return parsed as LogEntry;
    } catch {
      const ips = extractIPs(line);
      const emails = extractEmails(line);
      const entry: LogEntry = { message: line };
      if (ips.length > 0) entry.source_ip = ips[0];
      if (emails.length > 0) entry.username = emails[0];
      if (line.toLowerCase().includes('failed') || line.toLowerCase().includes('denied')) entry.status = 'failed';
      if (line.toLowerCase().includes('success') || line.toLowerCase().includes('accepted')) entry.status = 'success';
      return entry;
    }
  });

  const results: ThreatDetectionResult[] = [];

  const bruteForce = detectBruteForce(entries);
  if (bruteForce) results.push(bruteForce);

  const sqli = detectSQLInjection(entries);
  if (sqli) results.push(sqli);

  const suspiciousLogin = detectSuspiciousLogin(entries);
  if (suspiciousLogin) results.push(suspiciousLogin);

  if (results.length === 0 && entries.length > 0) {
    const allIPs = new Set<string>();
    const allHashes = new Set<string>();
    const allUrls = new Set<string>();
    entries.forEach(e => {
      const text = [e.message, e.source_ip, e.url, JSON.stringify(e.raw_payload || '')].join(' ');
      extractIPs(text).forEach(ip => allIPs.add(ip));
      extractHashes(text).forEach(h => allHashes.add(h));
      extractUrls(text).forEach(u => allUrls.add(u));
    });

    const iocs: Array<{ type: string; value: string; reputation: string }> = [];
    allIPs.forEach(ip => iocs.push({ type: 'ip', value: ip, reputation: 'unknown' }));
    allHashes.forEach(h => iocs.push({ type: 'hash', value: h, reputation: 'unknown' }));
    allUrls.forEach(u => iocs.push({ type: 'url', value: u, reputation: 'unknown' }));

    if (iocs.length > 0) {
      results.push({
        threatType: 'generic',
        severity: 'low',
        confidence: 0.3,
        title: 'Log Analysis Complete - IOCs Extracted',
        description: `No specific attack patterns detected, but ${iocs.length} indicators of compromise were extracted from the log data for further investigation.`,
        iocs: iocs.slice(0, 20),
        mitreTechniques: [],
      });
    }
  }

  return results;
}

export function generateIncidentReport(
  incident: { title: string; description?: string; severity: string; attack_vector?: string },
  alerts: Array<{ title: string; threat_type?: string; raw_payload: unknown }>,
  iocs: Array<{ type: string; value: string; reputation: string }>,
  mitreMappings: Array<{ technique_id: string; technique_name: string; tactic: string; confidence: number }>
): Record<string, unknown> {
  const now = new Date().toISOString();
  return {
    generated_at: now,
    incident_title: incident.title,
    executive_summary: `Security incident "${incident.title}" was detected and analyzed. The incident has been classified as ${incident.severity} severity. ${alerts.length} alerts are associated with this incident, and ${iocs.length} indicators of compromise have been identified.`,
    attack_narrative: incident.description || incident.attack_vector || 'Attack vector analysis pending.',
    timeline: alerts.map((a, i) => ({
      timestamp: now,
      event: a.title,
      actor: a.threat_type || 'Unknown',
    })),
    iocs: iocs.map(i => ({ type: i.type, value: i.value, reputation: i.reputation })),
    mitre_coverage: mitreMappings.map(m => ({
      technique_id: m.technique_id,
      technique_name: m.technique_name,
      tactic: m.tactic,
      confidence: m.confidence,
    })),
    recommendations: [
      { priority: 'Immediate', action: 'Isolate affected systems and block identified malicious IPs', owner: 'SOC Team' },
      { priority: 'Short-term', action: 'Reset compromised credentials and enforce MFA', owner: 'IT Security' },
      { priority: 'Long-term', action: 'Implement additional monitoring for detected TTPs', owner: 'Security Engineering' },
    ],
    data_classification: 'CONFIDENTIAL',
  };
}
