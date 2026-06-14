import "jsr:@supabase/functions-js/edge-runtime.d.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

interface ThreatDetectionResult {
  threatType: string;
  severity: string;
  confidence: number;
  title: string;
  description: string;
  iocs: Array<{ type: string; value: string; reputation: string }>;
  mitreTechniques: Array<{ id: string; name: string; tactic: string }>;
}

const BRUTE_FORCE_PATTERNS = [
  /failed\s+(login|authentication|auth)/i,
  /authentication\s+failure/i,
  /login\s+failed/i,
  /invalid\s+(password|credentials|user)/i,
  /access\s+denied/i,
  /brute\s*force/i,
];

const SQL_INJECTION_PATTERNS = [
  /UNION\s+SELECT/i,
  /OR\s+1\s*=\s*1/i,
  /AND\s+1\s*=\s*1/i,
  /('|;|--|\/\*|\*\/)/i,
  /DROP\s+TABLE/i,
  /INSERT\s+INTO/i,
  /XP_CMDSHELL/i,
  /WAITFOR\s+DELAY/i,
  /SLEEP\s*\(/i,
  /BENCHMARK\s*\(/i,
  /sqlmap/i,
  /(%27|%22|%3B|%2D%2D)/i,
];

const SUSPICIOUS_LOGIN_PATTERNS = [
  /impossible\s+travel/i,
  /anomalous\s+login/i,
  /new\s+(location|device|ip)/i,
  /unusual\s+(time|activity|access)/i,
  /python-requests/i,
  /curl\//i,
];

function extractIPs(text: string): string[] {
  const matches = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  return [...new Set(matches)];
}

function analyzeLogEntry(line: string): ThreatDetectionResult[] {
  const results: ThreatDetectionResult[] = [];

  const isBruteForce = BRUTE_FORCE_PATTERNS.some(p => p.test(line));
  const isSQLi = SQL_INJECTION_PATTERNS.some(p => p.test(line));
  const isSuspiciousLogin = SUSPICIOUS_LOGIN_PATTERNS.some(p => p.test(line));

  const ips = extractIPs(line);

  if (isBruteForce) {
    results.push({
      threatType: 'brute_force',
      severity: 'high',
      confidence: 0.82,
      title: 'Brute Force Attack Pattern Detected',
      description: 'Multiple failed authentication attempts detected in log entry. Pattern consistent with automated credential attack tools.',
      iocs: ips.map(ip => ({ type: 'ip', value: ip, reputation: 'suspicious' })),
      mitreTechniques: [
        { id: 'T1110.001', name: 'Brute Force: Password Guessing', tactic: 'Credential Access' },
        { id: 'T1110.003', name: 'Brute Force: Password Spraying', tactic: 'Credential Access' },
      ],
    });
  }

  if (isSQLi) {
    results.push({
      threatType: 'sql_injection',
      severity: 'critical',
      confidence: 0.88,
      title: 'SQL Injection Attack Detected',
      description: 'SQL injection patterns identified in request data. Malicious SQL commands detected targeting database layer.',
      iocs: ips.map(ip => ({ type: 'ip', value: ip, reputation: 'malicious' })),
      mitreTechniques: [
        { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
        { id: 'T1071.001', name: 'Application Layer Protocol: Web Protocols', tactic: 'Command and Control' },
      ],
    });
  }

  if (isSuspiciousLogin) {
    results.push({
      threatType: 'suspicious_login',
      severity: 'high',
      confidence: 0.78,
      title: 'Suspicious Login Activity Detected',
      description: 'Anomalous login behavior detected. Impossible travel, unusual timing, or automated user agent patterns observed.',
      iocs: ips.map(ip => ({ type: 'ip', value: ip, reputation: 'suspicious' })),
      mitreTechniques: [
        { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion' },
        { id: 'T1078.003', name: 'Valid Accounts: Local Accounts', tactic: 'Persistence' },
      ],
    });
  }

  return results;
}

function aggregateResults(lineResults: ThreatDetectionResult[][]): ThreatDetectionResult[] {
  const allResults = lineResults.flat();
  const grouped = new Map<string, ThreatDetectionResult>();

  for (const result of allResults) {
    const existing = grouped.get(result.threatType);
    if (existing) {
      existing.confidence = Math.max(existing.confidence, result.confidence);
      existing.iocs = [...new Map([...existing.iocs, ...result.iocs].map(i => [i.value, i])).values()];
      if (result.severity === 'critical') existing.severity = 'critical';
      else if (result.severity === 'high' && existing.severity !== 'critical') existing.severity = 'high';
    } else {
      grouped.set(result.threatType, { ...result, iocs: [...result.iocs] });
    }
  }

  return Array.from(grouped.values());
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  try {
    if (req.method !== "POST") {
      return new Response(
        JSON.stringify({ error: "Method not allowed" }),
        { status: 405, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const { logContent } = await req.json();

    if (!logContent || typeof logContent !== 'string') {
      return new Response(
        JSON.stringify({ error: "logContent is required and must be a string" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const lines = logContent.split('\n').filter(l => l.trim());
    const lineResults = lines.map(line => analyzeLogEntry(line));
    const results = aggregateResults(lineResults);

    return new Response(
      JSON.stringify({
        threats_detected: results.length,
        total_lines_analyzed: lines.length,
        results,
        analyzed_at: new Date().toISOString(),
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (err) {
    return new Response(
      JSON.stringify({ error: err.message || "Internal server error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
