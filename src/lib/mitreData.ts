export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
}

export const MITRE_TACTICS = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
];

export const MITRE_TECHNIQUES: MitreTechnique[] = [
  { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', description: 'Exploiting vulnerabilities in internet-facing applications' },
  { id: 'T1133', name: 'External Remote Services', tactic: 'Initial Access', description: 'Using VPNs, Citrix, or other remote access mechanisms' },
  { id: 'T1566', name: 'Phishing', tactic: 'Initial Access', description: 'Sending malicious emails or messages' },
  { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion', description: 'Using legitimate credentials to evade detection' },
  { id: 'T1078.001', name: 'Valid Accounts: Default Accounts', tactic: 'Defense Evasion', description: 'Using default system accounts' },
  { id: 'T1078.003', name: 'Valid Accounts: Local Accounts', tactic: 'Persistence', description: 'Using local accounts for persistence' },
  { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access', description: 'Attempting to guess passwords through automation' },
  { id: 'T1110.001', name: 'Brute Force: Password Guessing', tactic: 'Credential Access', description: 'Systematically guessing passwords' },
  { id: 'T1110.003', name: 'Brute Force: Password Spraying', tactic: 'Credential Access', description: 'Testing few passwords against many accounts' },
  { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution', description: 'Executing commands via scripting languages' },
  { id: 'T1059.001', name: 'Command and Scripting Interpreter: PowerShell', tactic: 'Execution', description: 'Using PowerShell for execution' },
  { id: 'T1059.003', name: 'Command and Scripting Interpreter: Windows Command Shell', tactic: 'Execution', description: 'Using cmd.exe for execution' },
  { id: 'T1059.004', name: 'Command and Scripting Interpreter: Unix Shell', tactic: 'Execution', description: 'Using Unix shells for execution' },
  { id: 'T1053', name: 'Scheduled Task/Job', tactic: 'Persistence', description: 'Creating scheduled tasks for persistence' },
  { id: 'T1053.005', name: 'Scheduled Task/Job: Scheduled Task', tactic: 'Persistence', description: 'Using Windows Task Scheduler' },
  { id: 'T1547', name: 'Boot or Logon Autostart Execution', tactic: 'Persistence', description: 'Configuring programs to run at boot or logon' },
  { id: 'T1548', name: 'Abuse Elevation Control Mechanism', tactic: 'Privilege Escalation', description: 'Abusing built-in mechanisms to gain elevated access' },
  { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation', description: 'Exploiting vulnerabilities to gain higher privileges' },
  { id: 'T1070', name: 'Indicator Removal', tactic: 'Defense Evasion', description: 'Removing artifacts to evade detection' },
  { id: 'T1070.001', name: 'Indicator Removal: Clear Windows Event Logs', tactic: 'Defense Evasion', description: 'Clearing event logs to remove evidence' },
  { id: 'T1562', name: 'Impair Defenses', tactic: 'Defense Evasion', description: 'Disabling or modifying security tools' },
  { id: 'T1003', name: 'OS Credential Dumping', tactic: 'Credential Access', description: 'Extracting credentials from OS memory or files' },
  { id: 'T1555', name: 'Credentials from Password Stores', tactic: 'Credential Access', description: 'Extracting passwords from local stores' },
  { id: 'T1087', name: 'Account Discovery', tactic: 'Discovery', description: 'Enumerating accounts on a system' },
  { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery', description: 'Scanning for open network services' },
  { id: 'T1083', name: 'File and Directory Discovery', tactic: 'Discovery', description: 'Searching for files and directories' },
  { id: 'T1021', name: 'Remote Services', tactic: 'Lateral Movement', description: 'Using remote services to move laterally' },
  { id: 'T1021.001', name: 'Remote Services: Remote Desktop Protocol', tactic: 'Lateral Movement', description: 'Using RDP for lateral movement' },
  { id: 'T1021.002', name: 'Remote Services: SMB/Windows Admin Shares', tactic: 'Lateral Movement', description: 'Using SMB for lateral movement' },
  { id: 'T1021.004', name: 'Remote Services: SSH', tactic: 'Lateral Movement', description: 'Using SSH for lateral movement' },
  { id: 'T1005', name: 'Data from Local System', tactic: 'Collection', description: 'Accessing data on the local system' },
  { id: 'T1039', name: 'Data from Network Shared Drive', tactic: 'Collection', description: 'Collecting data from network shares' },
  { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control', description: 'Using application layer protocols for C2' },
  { id: 'T1071.001', name: 'Application Layer Protocol: Web Protocols', tactic: 'Command and Control', description: 'Using HTTP/HTTPS for C2' },
  { id: 'T1573', name: 'Encrypted Channel', tactic: 'Command and Control', description: 'Using encryption to hide C2 traffic' },
  { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration', description: 'Stealing data over existing C2 channel' },
  { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', tactic: 'Exfiltration', description: 'Using alternative protocols for data theft' },
  { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact', description: 'Encrypting data to cause business disruption' },
  { id: 'T1489', name: 'Service Stop', tactic: 'Impact', description: 'Stopping or disabling critical services' },
  { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'Impact', description: 'Disabling system recovery features' },
];

export function getTechniquesByTactic(tactic: string): MitreTechnique[] {
  return MITRE_TECHNIQUES.filter(t => t.tactic === tactic);
}

export function getTechniqueById(id: string): MitreTechnique | undefined {
  return MITRE_TECHNIQUES.find(t => t.id === id);
}
