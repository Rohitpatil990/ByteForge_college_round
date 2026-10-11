/**
 * AgentBreak Sentinel - Local Heuristic Prompt Injection & Exfiltration Scanner
 * Evaluates text offline using transparent, deterministic rules.
 */

import { LocalScanReport, RiskLevel, ScannerRuleMatch } from './types';

export interface RuleDefinition {
  id: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  patterns: RegExp[];
  explanation: string;
  mitigation: string;
}

export const SCANNER_RULES: RuleDefinition[] = [
  {
    id: 'system_rule_override',
    name: 'System Rule Override Attempt',
    severity: 'HIGH',
    patterns: [
      /ignore\s+((all\s+|any\s+)?(previous\s+|prior\s+)?(instructions?|rules?|prompts?|constraints?|policies|policy)|(the\s+|all\s+|any\s+)?(security|safety|system|developer|model|agent)\s+(policies|policy|rules?|instructions?|prompts?|constraints?|guardrails?|guidelines?|restrictions?))/i,
      /disregard\s+((all\s+|any\s+)?(previous\s+|prior\s+)?(instructions?|rules?|system\s+prompts?|constraints?|policies|policy)|(the\s+|all\s+|any\s+)?(security|safety|system|developer|model|agent)\s+(policies|policy|rules?|instructions?|prompts?|constraints?|guardrails?|guidelines?|restrictions?))/i,
      /system\s+(prompt\s+)?override\s*[:\n]/i,
      /emergency\s+(policy\s+|system\s+)?override/i,
      /you\s+are\s+now\s+in\s+(developer|unrestricted|god)\s+mode/i,
      /bypass\s+((all\s+|the\s+)?(safety|security|policy|system)\s+(policies|policy|filters?|boundaries?|checks?|rules?|guidelines?|restrictions?|guardrails?)|(the\s+|all\s+)?security\s+policy)/i,
      /new\s+operating\s+instructions\s+supercede\s+all\s+prior/i,
      /(do\s+not|never|don't)\s+(tell|inform|alert|notify|warn)\s+(the\s+)?(user|human|operator|admin|auditor)/i,
      /override\s+(all\s+|the\s+)?(security|safety|system)\s+(policies|policy|rules?|checks?|restrictions?)/i,
    ],
    explanation: 'Contains phrasing commonly used to hijack LLM behavior and force it to ignore initial system instructions.',
    mitigation: 'Verify prompt provenance; ensure downstream agent relies on strict middleware guards rather than prompt compliance.',
  },
  {
    id: 'confidential_data_exfiltration',
    name: 'Confidential Data / Canary Exfiltration',
    severity: 'CRITICAL',
    patterns: [
      /CANARY-[a-zA-Z0-9_\-]+/i,
      /(exfiltrat(e|ing)|leak(ing)?|dump(ing)?)\s+(all\s+)?(passwords?|credentials?|secrets?|tokens?|keys?|db)/i,
      /(reveal|disclose|show|leak|extract|dump|output)\s+(all\s+|the\s+)?(synthetic\s+|internal\s+|confidential\s+|sensitive\s+|private\s+)?(canary|secret\s*keys?|api\s*keys?|tokens?|passwords?|credentials?|database|records?|private\s*keys?)/i,
      /forward\s+(all\s+)?customer\s+data\s+to\s+[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/i,
      /(attach|send|forward|upload|transfer|email)\s+((all\s+)?(confidential|sensitive|company|internal|customer)\s+(documents?|files?|data|records?)\s+.*?\s+to\s+|.*?\s+to\s+)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/i,
      /(send|forward|transmit|exfiltrate|leak)\s+(all\s+)?(confidential|sensitive|company|internal|customer)\s+(documents?|files?|data|records?|credentials?)\s+to/i,
      /send\s+(the\s+)?(canary|secret)\s+to\s+https?:\/\//i,
    ],
    explanation: 'Attempts to read or exfiltrate synthetic canary secrets, passwords, or sensitive customer credentials.',
    mitigation: 'Redact identifiers immediately; check that target agent guards reject external exfiltration domains.',
  },
  {
    id: 'tool_permission_manipulation',
    name: 'Tool Permission / Privilege Manipulation',
    severity: 'HIGH',
    patterns: [
      /(call|execute|invoke)\s+(tool\s+)?(send_email|delete_file|execute_command|write_memory|query_database)\s*\(/i,
      /(use|execute|call|run|invoke)\s+(the\s+)?([a-zA-Z0-9_]+\s+)?tool\s+(with(out)?\s+(asking\s+for\s+)?permission|without\s+(user\s+)?(approval|consent|confirmation))/i,
      /grant\s+(all\s+|unauthorized\s+|unrestricted\s+|elevated\s+|forbidden\s+|full\s+|root\s+|admin\s+|superuser\s+)*(tools?|tool)?\s*(permissions?|access|privileges?|authorization|override)/i,
      /permission\s+to\s+(access|read|modify|delete|exfiltrate)\s+confidential\s+(files?|records?|data|documents?|databases?)/i,
      /(always\s+)?(approve|grant|allow|permit)\s+(all\s+)?(requests?\s+to\s+)?(access|read|modify|delete|exfiltrate)\s+(confidential|sensitive|restricted|internal|protected)\s+(files?|records?|data|documents?|databases?)/i,
      /elevate\s+(privilege\s+level|permissions?)\s+to\s+(admin|root|system)/i,
      /recipient_domain\s*=\s*['"][^'"]*evil\.[a-z]+['"]/i,
    ],
    explanation: 'Attempts to trigger unapproved tools or elevate execution privilege inside the agent environment.',
    mitigation: 'Enforce Tool Domain Policy Guards (D1) so tools cannot execute outside authorized domain whitelists.',
  },
  {
    id: 'context_smuggling',
    name: 'Context Smuggling / Embedded Payload',
    severity: 'MEDIUM',
    patterns: [
      /<!--\s*.*?(instruction|override|execute|system).*?-->/i,
      /\[SYSTEM\s+NOTICE\s*:\s*.*?\]/i,
      /\[ADMIN\s+(DIRECTIVE|OVERRIDE|NOTICE)\s*:\s*.*?\]/i,
      /BEGIN\s+SYSTEM\s+(OVERRIDE|INSTRUCTION|DIRECTIVE)/i,
      /<<<\s*OVERRIDE\s*>>>/i,
      /IMPORTANT\s+ADMIN\s+MEMO\s*:\s*/i,
      /\{\s*"system_instruction"\s*:\s*"[^"]+"\s*\}/i,
      /\/\*\s*SYSTEM\s+(OVERRIDE|INSTRUCTION|DIRECTIVE).*?\*\//i,
    ],
    explanation: 'Disguises instructions inside comments, brackets, or structured envelopes to slip past superficial filters.',
    mitigation: 'Treat all retrieved documents and user attachments as untrusted data strings.',
  },
  {
    id: 'memory_poisoning_directive',
    name: 'Memory Poisoning Directive',
    severity: 'HIGH',
    patterns: [
      /remember\s+(this\s+|that\s+)?for\s+(all\s+)?future\s+(conversations?|sessions?|chats?|interactions?|prompts?|turns?|contexts?)\s*[:\.]?/i,
      /(admin_override|privilege_override|system_override)\s*=\s*(true|1|yes|active|enabled|all)/i,
      /store\s+in\s+(persistent\s+)?(memory|state|scratchpad|context)\s+that/i,
      /permanently\s+(update|change|set|modify)\s+your\s+(instructions?|beliefs?|persona|behavior|memory|rules?)\s+to/i,
      /write_memory\s*\(\s*(key\s*=\s*)?['"]?admin_override['"]?/i,
      /update_scratchpad\s*\(\s*privileged\s*=\s*true/i,
      /persist\s+(this\s+)?across\s+(all\s+)?(conversations?|sessions?)/i,
    ],
    explanation: 'Attempts to inject persistent directives into agent memory or scratchpad state to compromise future sessions.',
    mitigation: 'Deploy Untrusted Memory Write Guards (D2) to reject state updates originating from untrusted inputs.',
  },
];

/**
 * Executes local offline heuristic scan on text.
 */
export function scanTextLocally(text: string, maxLength: number = 16000): LocalScanReport {
  const boundedText = (text || '').slice(0, maxLength);
  const matches: ScannerRuleMatch[] = [];

  for (const rule of SCANNER_RULES) {
    for (const pattern of rule.patterns) {
      const match = pattern.exec(boundedText);
      if (match) {
        let snippet = match[0];
        if (snippet.length > 80) {
          snippet = snippet.slice(0, 77) + '...';
        }
        matches.push({
          rule_id: rule.id,
          rule_name: rule.name,
          severity: rule.severity,
          confidence: 'Heuristic Pattern Match',
          matched_snippet: snippet,
          explanation: rule.explanation,
          mitigation: rule.mitigation,
        });
        break; // Match rule once
      }
    }
  }

  let riskLevel: RiskLevel = 'CLEAN';
  if (matches.some((m) => m.severity === 'CRITICAL')) {
    riskLevel = 'CRITICAL';
  } else if (matches.some((m) => m.severity === 'HIGH')) {
    riskLevel = 'HIGH';
  } else if (matches.some((m) => m.severity === 'MEDIUM')) {
    riskLevel = 'MEDIUM';
  } else if (matches.length > 0) {
    riskLevel = 'LOW';
  }

  const summary = matches.length > 0
    ? `Heuristic scanner detected ${matches.length} suspicious pattern(s). Highest severity: ${riskLevel}. (Note: Local heuristic match; not an execution-verified exploit).`
    : 'No known prompt injection or exfiltration patterns matched. (Note: Heuristic safety check does not guarantee safety against novel vectors).';

  return {
    status: 'completed',
    risk_level: riskLevel,
    rules_matched: matches,
    summary,
    is_heuristic_only: true,
    is_trace_verified: false,
    content_length: boundedText.length,
    timestamp: new Date().toISOString(),
  };
}

/**
 * Redacts matches of synthetic secrets or custom keywords from text.
 */
export function redactSensitiveText(text: string, customTokens: string[] = []): string {
  let result = text;
  // Redact synthetic canaries
  result = result.replace(/CANARY-[a-zA-Z0-9_\-]+/gi, '[REDACTED_CANARY]');
  // Redact emails
  result = result.replace(/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/gi, '[REDACTED_EMAIL]');
  // Redact custom tokens
  for (const token of customTokens) {
    if (token && token.trim().length > 2) {
      const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      result = result.replace(new RegExp(escaped, 'gi'), '[REDACTED_USER_TEXT]');
    }
  }
  return result;
}

/**
 * Safely escapes untrusted text to prevent HTML / XSS injection.
 */
export function escapeHtml(unsafe: string): string {
  return (unsafe || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
