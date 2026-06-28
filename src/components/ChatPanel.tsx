import React, { useState, useRef, useEffect } from 'react';

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  typing?: boolean;
  tags?: string[];
}

const QUICK_PROMPTS = [
  'Summarize active incidents',
  'Show critical IOCs',
  'Latest threat correlations',
  'Recommend containment steps',
  'Explain T1003.001',
  'Check lateral movement',
];

const AI_RESPONSES: Record<string, { content: string; tags?: string[] }> = {
  default: {
    content: `I've analyzed your query against current threat intelligence and incident data. Here's what I found:\n\n**Current Threat Landscape:**\n- 3 active incidents require immediate attention\n- 8 high-confidence IOCs identified in the last 24 hours\n- Cobalt Strike C2 beacon activity detected on 2 endpoints\n\n**Recommended Actions:**\n1. Isolate DESKTOP-7K2M9P immediately\n2. Rotate credentials for svc_backup@corp.local\n3. Block outbound traffic to 185.220.101.47\n\nWould you like me to initiate any of these automated containment actions?`,
    tags: ['INC-2024-0847', 'T1041', 'Cobalt Strike'],
  },
  incident: {
    content: `**Active Incidents Summary (Last 24h)**\n\n🔴 **CRITICAL** — INC-2024-0847\nAPT credential harvesting campaign. 4 hosts affected. Exfiltration detected.\n\n🟠 **HIGH** — INC-2024-0851\nSuspicious PowerShell execution chain on SRV-FILE-03. Under investigation.\n\n🟡 **MEDIUM** — INC-2024-0839\nBrute force attempt on VPN gateway. 1,247 failed logins in 2 hours. Auto-blocked.\n\n**Recommendation:** INC-2024-0847 requires immediate escalation. The threat actor shows APT29-level sophistication based on TTPs observed.`,
    tags: ['INC-2024-0847', 'INC-2024-0851', 'APT29'],
  },
  ioc: {
    content: `**Critical IOCs — Last 24 Hours**\n\n**IP Addresses (C2):**\n\`185.220.101.47\` — Confirmed C2 beacon, 97% confidence\n\`45.142.212.118\` — Exfiltration endpoint, 82% confidence\n\n**Domains (Typosquatting):**\n\`update-svc.microsft-cdn.com\` — Active C2, DNS tunneling detected\n\n**File Hashes:**\n\`a3f8b2c1d4e5f6a7...\` — Cobalt Strike loader, 89% confidence\n\n**Email (Phishing):**\n\`hr-noreply@microsofit-corp.com\` — Spearphishing sender\n\nAll IOCs have been submitted to threat intel platforms. Shall I push these to your SIEM blocking rules?`,
    tags: ['IOC', 'C2', 'Phishing'],
  },
  threat: {
    content: `**Threat Correlation Analysis**\n\nBased on current TTPs, I've identified the following correlations:\n\n🎯 **APT29 (Cozy Bear)** — 78% match\nSignature spearphishing + LSASS credential dumping pattern. Russian state-sponsored.\n\n🦠 **Cobalt Strike Beacon** — 91% match\nC2 communication intervals, staging behavior, and beacon jitter match known Cobalt Strike profiles.\n\n📋 **NOBELIUM Campaign** — 65% match\nDomain typosquatting and macro-enabled document delivery align with NOBELIUM IOCs from Q3 2024.\n\n**MITRE ATT&CK Coverage:**\nT1566.001 → T1003.001 → T1021.001 → T1041\n\nThis appears to be a sophisticated, targeted intrusion. Recommend escalating to Tier 3.`,
    tags: ['APT29', 'NOBELIUM', 'Cobalt Strike'],
  },
  contain: {
    content: `**Recommended Containment Steps**\n\nBased on INC-2024-0847 analysis, execute in priority order:\n\n**Immediate (0-15 min):**\n1. ✅ Network isolate DESKTOP-7K2M9P via EDR console\n2. ✅ Disable svc_backup AD account and rotate password\n3. ✅ Block IPs: 185.220.101.47, 45.142.212.118 at perimeter firewall\n\n**Short-term (15-60 min):**\n4. 🔄 Collect memory forensics from SRV-DC-01\n5. 🔄 Reset all privileged account credentials\n6. 🔄 Deploy enhanced monitoring on remaining DCs\n\n**Ongoing:**\n7. ⏳ Full forensic acquisition of affected endpoints\n8. ⏳ Threat hunt for additional persistence mechanisms\n\nWant me to trigger the automated containment workflow for steps 1-3?`,
    tags: ['Containment', 'INC-2024-0847'],
  },
  mitre: {
    content: `**T1003.001 — OS Credential Dumping: LSASS Memory**\n\n**Description:**\nAdversaries attempt to access credential material stored in LSASS process memory. Tools like Mimikatz, ProcDump, or direct API calls can extract NTLM hashes and Kerberos tickets.\n\n**Observed in INC-2024-0847:**\nAt 03:12 UTC, suspicious LSASS memory access detected on DESKTOP-7K2M9P consistent with Mimikatz signatures.\n\n**Detection:**\n- Windows Event ID 4656 (handle request to LSASS)\n- Sysmon Event ID 10 (process access)\n- EDR behavioral detection triggered\n\n**Mitigations:**\n- Enable Windows Credential Guard\n- Configure LSASS as PPL (Protected Process Light)\n- Restrict debug privileges via GPO\n\n**Related Techniques:** T1003.002, T1558, T1555`,
    tags: ['T1003.001', 'MITRE', 'Credential Access'],
  },
  lateral: {
    content: `**Lateral Movement Analysis — INC-2024-0847**\n\n**Confirmed Movement Path:**\n\`DESKTOP-7K2M9P\` → \`SRV-DC-01\` → \`SRV-FILE-03\`\n\n**Techniques Observed:**\n- **T1550.002** Pass-the-Hash: Harvested NTLM hash used to authenticate to SRV-DC-01\n- **T1021.001** RDP: Remote desktop session opened at 03:44 UTC\n- **T1021.002** SMB: File shares accessed on SRV-FILE-03 at 04:18 UTC\n\n**Compromised Accounts:**\n- \`svc_backup\` (Domain Admin) — PRIMARY\n- \`j.morrison\` (Standard User) — Initial victim\n\n**Unconfirmed Hosts at Risk:**\nSRV-SQL-02, LAPTOP-MKT-22 showing anomalous authentication patterns.\n\nRecommend immediate credential reset for all domain admin accounts.`,
    tags: ['T1550.002', 'T1021.001', 'Lateral Movement'],
  },
};

function getAIResponse(message: string): { content: string; tags?: string[] } {
  const lower = message.toLowerCase();
  if (lower.includes('incident') || lower.includes('summary') || lower.includes('active')) return AI_RESPONSES.incident;
  if (lower.includes('ioc') || lower.includes('indicator')) return AI_RESPONSES.ioc;
  if (lower.includes('threat') || lower.includes('correlation') || lower.includes('apt')) return AI_RESPONSES.threat;
  if (lower.includes('contain') || lower.includes('remediat') || lower.includes('step')) return AI_RESPONSES.contain;
  if (lower.includes('t1003') || lower.includes('mitre') || lower.includes('technique')) return AI_RESPONSES.mitre;
  if (lower.includes('lateral') || lower.includes('movement') || lower.includes('pivot')) return AI_RESPONSES.lateral;
  return AI_RESPONSES.default;
}

function formatTime(date: Date): string {
  return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
}

function formatContent(content: string): React.ReactNode {
  const lines = content.split('\n');
  return lines.map((line, i) => {
    // Bold
    const parts = line.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
    const formatted = parts.map((part, j) => {
      if (part.startsWith('**') && part.endsWith('**')) {
        return <strong key={j} className="text-gray-100 font-semibold">{part.slice(2, -2)}</strong>;
      }
      if (part.startsWith('`') && part.endsWith('`')) {
        return <code key={j} className="font-mono text-cyan-400 bg-cyan-900/20 px-1 py-0.5 rounded text-xs">{part.slice(1, -1)}</code>;
      }
      return part;
    });

    if (line === '') return <br key={i} />;
    if (line.startsWith('🔴') || line.startsWith('🟠') || line.startsWith('🟡') || line.startsWith('✅') || line.startsWith('🔄') || line.startsWith('⏳') || line.startsWith('🎯') || line.startsWith('🦠') || line.startsWith('📋')) {
      return <div key={i} className="flex gap-2 my-1">{formatted}</div>;
    }
    if (/^\d+\./.test(line)) {
      return <div key={i} className="ml-3 my-0.5">{formatted}</div>;
    }
    if (line.startsWith('- ')) {
      return <div key={i} className="ml-3 my-0.5 flex gap-1"><span className="text-gray-600 flex-shrink-0">·</span><span>{formatted}</span></div>;
    }
    return <div key={i}>{formatted}</div>;
  });
}

const TypingIndicator: React.FC = () => (
  <div className="flex items-center gap-1 px-3 py-2">
    {[0, 1, 2].map(i => (
      <div
        key={i}
        className="w-1.5 h-1.5 rounded-full bg-cyan-400"
        style={{ animation: `typingBounce 1.2s ease-in-out ${i * 0.2}s infinite` }}
      />
    ))}
  </div>
);

const ChatPanel: React.FC = () => {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'welcome',
      role: 'assistant',
      content: `**SOC AI Assistant Online**\n\nI'm your AI-powered security analyst. I have full visibility into:\n\n- Active incidents and alerts\n- Threat intelligence feeds\n- IOC database and correlations\n- MITRE ATT&CK technique library\n- Endpoint telemetry\n\nHow can I assist with your investigation?`,
      timestamp: formatTime(new Date()),
      tags: ['Ready'],
    },
  ]);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  const sendMessage = async (text: string) => {
    const trimmed = text.trim();
    if (!trimmed || isTyping) return;

    const userMsg: Message = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: trimmed,
      timestamp: formatTime(new Date()),
    };

    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setIsTyping(true);

    await new Promise(r => setTimeout(r, 800 + Math.random() * 1200));

    const response = getAIResponse(trimmed);
    const aiMsg: Message = {
      id: `ai-${Date.now()}`,
      role: 'assistant',
      content: response.content,
      timestamp: formatTime(new Date()),
      tags: response.tags,
    };

    setIsTyping(false);
    setMessages(prev => [...prev, aiMsg]);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage(input);
    }
  };

  const handleQuickPrompt = (prompt: string) => {
    sendMessage(prompt);
  };

  return (
    <div className="flex flex-col h-full bg-gray-950 text-gray-100" style={{ minHeight: '600px' }}>
      {/* Header */}
      <div className="flex-shrink-0 bg-gray-900/60 border-b border-gray-700/50 px-4 py-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative">
              <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center">
                <svg className="w-4 h-4 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                </svg>
              </div>
              <span className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 bg-green-400 border-2 border-gray-900 rounded-full" />
            </div>
            <div>
              <div className="text-sm font-semibold text-gray-100">SOC AI Assistant</div>
              <div className="flex items-center gap-1.5 text-xs text-green-400">
                <span className="w-1 h-1 rounded-full bg-green-400 animate-pulse" />
                Online · Analyzing threats
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setMessages([{
                id: 'welcome-new',
                role: 'assistant',
                content: 'Chat cleared. How can I assist with your security investigation?',
                timestamp: formatTime(new Date()),
                tags: ['Ready'],
              }])}
              className="text-gray-600 hover:text-gray-400 transition-colors p-1.5 rounded hover:bg-gray-800/60"
              title="Clear chat"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
              </svg>
            </button>
            <div className="text-xs text-gray-600 font-mono bg-gray-800/60 border border-gray-700/40 px-2 py-1 rounded">
              {messages.filter(m => m.role === 'user').length} queries
            </div>
          </div>
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto px-4 py-4 space-y-4 scrollbar-thin">
        {messages.map(msg => (
          <div
            key={msg.id}
            className={`flex gap-3 ${msg.role === 'user' ? 'flex-row-reverse' : 'flex-row'}`}
          >
            {/* Avatar */}
            <div className="flex-shrink-0">
              {msg.role === 'assistant' ? (
                <div className="w-7 h-7 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center mt-0.5">
                  <svg className="w-3.5 h-3.5 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                  </svg>
                </div>
              ) : (
                <div className="w-7 h-7 rounded-lg bg-gray-700/60 border border-gray-600/50 flex items-center justify-center mt-0.5">
                  <svg className="w-3.5 h-3.5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                  </svg>
                </div>
              )}
            </div>

            {/* Bubble */}
            <div className={`flex flex-col gap-1.5 max-w-[85%] ${msg.role === 'user' ? 'items-end' : 'items-start'}`}>
              <div
                className={`rounded-lg px-3.5 py-2.5 text-xs leading-relaxed ${
                  msg.role === 'user'
                    ? 'bg-cyan-500/15 border border-cyan-500/30 text-gray-200 rounded-tr-sm'
                    : 'bg-gray-800/80 border border-gray-700/50 text-gray-300 rounded-tl-sm'
                }`}
              >
                {formatContent(msg.content)}
              </div>

              {/* Tags */}
              {msg.tags && msg.tags.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {msg.tags.map(tag => (
                    <span
                      key={tag}
                      className="text-xs font-mono bg-purple-900/30 text-purple-400 border border-purple-500/30 px-1.5 py-0.5 rounded"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              )}

              <span className="text-xs text-gray-600 font-mono">{msg.timestamp}</span>
            </div>
          </div>
        ))}

        {/* Typing indicator */}
        {isTyping && (
          <div className="flex gap-3">
            <div className="w-7 h-7 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center flex-shrink-0 mt-0.5">
              <svg className="w-3.5 h-3.5 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
              </svg>
            </div>
            <div className="bg-gray-800/80 border border-gray-700/50 rounded-lg rounded-tl-sm">
              <TypingIndicator />
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Quick prompts */}
      <div className="flex-shrink-0 px-4 pt-2">
        <div className="flex gap-1.5 overflow-x-auto pb-2 scrollbar-none">
          {QUICK_PROMPTS.map(prompt => (
            <button
              key={prompt}
              onClick={() => handleQuickPrompt(prompt)}
              disabled={isTyping}
              className="flex-shrink-0 text-xs bg-gray-800/60 hover:bg-gray-700/60 border border-gray-700/50 hover:border-gray-600 text-gray-400 hover:text-gray-200 px-2.5 py-1.5 rounded-lg transition-all disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {prompt}
            </button>
          ))}
        </div>
      </div>

      {/* Input */}
      <div className="flex-shrink-0 border-t border-gray-700/50 p-4">
        <div className="flex gap-2 items-end">
          <div className="flex-1 relative">
            <textarea
              ref={inputRef}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask about threats, incidents, IOCs..."
              disabled={isTyping}
              rows={1}
              className="w-full bg-gray-800/80 border border-gray-700/50 focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/30 rounded-lg px-3.5 py-2.5 text-xs text-gray-200 placeholder-gray-600 resize-none transition-all outline-none disabled:opacity-50 leading-relaxed"
              style={{ maxHeight: '120px', overflowY: 'auto' }}
              onInput={e => {
                const t = e.currentTarget;
                t.style.height = 'auto';
                t.style.height = Math.min(t.scrollHeight, 120) + 'px';
              }}
            />
          </div>
          <button
            onClick={() => sendMessage(input)}
            disabled={!input.trim() || isTyping}
            className="flex-shrink-0 w-9 h-9 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 hover:border-cyan-500/60 rounded-lg flex items-center justify-center text-cyan-400 transition-all disabled:opacity-40 disabled:cursor-not-allowed group"
          >
            {isTyping ? (
              <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
            ) : (
              <svg className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
              </svg>
            )}
          </button>
        </div>
        <div className="flex items-center justify-between mt-1.5">
          <span className="text-xs text-gray-700">Press Enter to send · Shift+Enter for newline</span>
          <span className="text-xs text-gray-700 font-mono">{input.length}/2000</span>
        </div>
      </div>

      <style>{`
        @keyframes typingBounce {
          0%, 60%, 100% { transform: translateY(0); opacity: 0.4; }
          30% { transform: translateY(-4px); opacity: 1; }
        }
        .scrollbar-none::-webkit-scrollbar { display: none; }
        .scrollbar-none { -ms-overflow-style: none; scrollbar-width: none; }
        .scrollbar-thin::-webkit-scrollbar { width: 4px; }
        .scrollbar-thin::-webkit-scrollbar-track { background: transparent; }
        .scrollbar-thin::-webkit-scrollbar-thumb { background: #374151; border-radius: 2px; }
      `}</style>
    </div>
  );
};

export default ChatPanel;
 