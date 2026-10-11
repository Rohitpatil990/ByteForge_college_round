"use strict";
(() => {
  // src/scanner.ts
  var SCANNER_RULES = [
    {
      id: "system_rule_override",
      name: "System Rule Override Attempt",
      severity: "HIGH",
      patterns: [
        /ignore\s+((all\s+|any\s+)?(previous\s+|prior\s+)?(instructions?|rules?|prompts?|constraints?|policies|policy)|(the\s+|all\s+|any\s+)?(security|safety|system|developer|model|agent)\s+(policies|policy|rules?|instructions?|prompts?|constraints?|guardrails?|guidelines?|restrictions?))/i,
        /disregard\s+((all\s+|any\s+)?(previous\s+|prior\s+)?(instructions?|rules?|system\s+prompts?|constraints?|policies|policy)|(the\s+|all\s+|any\s+)?(security|safety|system|developer|model|agent)\s+(policies|policy|rules?|instructions?|prompts?|constraints?|guardrails?|guidelines?|restrictions?))/i,
        /system\s+(prompt\s+)?override\s*[:\n]/i,
        /emergency\s+(policy\s+|system\s+)?override/i,
        /you\s+are\s+now\s+in\s+(developer|unrestricted|god)\s+mode/i,
        /bypass\s+((all\s+|the\s+)?(safety|security|policy|system)\s+(policies|policy|filters?|boundaries?|checks?|rules?|guidelines?|restrictions?|guardrails?)|(the\s+|all\s+)?security\s+policy)/i,
        /new\s+operating\s+instructions\s+supercede\s+all\s+prior/i,
        /(do\s+not|never|don't)\s+(tell|inform|alert|notify|warn)\s+(the\s+)?(user|human|operator|admin|auditor)/i,
        /override\s+(all\s+|the\s+)?(security|safety|system)\s+(policies|policy|rules?|checks?|restrictions?)/i
      ],
      explanation: "Contains phrasing commonly used to hijack LLM behavior and force it to ignore initial system instructions.",
      mitigation: "Verify prompt provenance; ensure downstream agent relies on strict middleware guards rather than prompt compliance."
    },
    {
      id: "confidential_data_exfiltration",
      name: "Confidential Data / Canary Exfiltration",
      severity: "CRITICAL",
      patterns: [
        /CANARY-[a-zA-Z0-9_\-]+/i,
        /(exfiltrat(e|ing)|leak(ing)?|dump(ing)?)\s+(all\s+)?(passwords?|credentials?|secrets?|tokens?|keys?|db)/i,
        /(reveal|disclose|show|leak|extract|dump|output)\s+(all\s+|the\s+)?(synthetic\s+|internal\s+|confidential\s+|sensitive\s+|private\s+)?(canary|secret\s*keys?|api\s*keys?|tokens?|passwords?|credentials?|database|records?|private\s*keys?)/i,
        /forward\s+(all\s+)?customer\s+data\s+to\s+[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/i,
        /(attach|send|forward|upload|transfer|email)\s+((all\s+)?(confidential|sensitive|company|internal|customer)\s+(documents?|files?|data|records?)\s+.*?\s+to\s+|.*?\s+to\s+)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/i,
        /(send|forward|transmit|exfiltrate|leak)\s+(all\s+)?(confidential|sensitive|company|internal|customer)\s+(documents?|files?|data|records?|credentials?)\s+to/i,
        /send\s+(the\s+)?(canary|secret)\s+to\s+https?:\/\//i
      ],
      explanation: "Attempts to read or exfiltrate synthetic canary secrets, passwords, or sensitive customer credentials.",
      mitigation: "Redact identifiers immediately; check that target agent guards reject external exfiltration domains."
    },
    {
      id: "tool_permission_manipulation",
      name: "Tool Permission / Privilege Manipulation",
      severity: "HIGH",
      patterns: [
        /(call|execute|invoke)\s+(tool\s+)?(send_email|delete_file|execute_command|write_memory|query_database)\s*\(/i,
        /(use|execute|call|run|invoke)\s+(the\s+)?([a-zA-Z0-9_]+\s+)?tool\s+(with(out)?\s+(asking\s+for\s+)?permission|without\s+(user\s+)?(approval|consent|confirmation))/i,
        /grant\s+(all\s+|unauthorized\s+|unrestricted\s+|elevated\s+|forbidden\s+|full\s+|root\s+|admin\s+|superuser\s+)*(tools?|tool)?\s*(permissions?|access|privileges?|authorization|override)/i,
        /permission\s+to\s+(access|read|modify|delete|exfiltrate)\s+confidential\s+(files?|records?|data|documents?|databases?)/i,
        /(always\s+)?(approve|grant|allow|permit)\s+(all\s+)?(requests?\s+to\s+)?(access|read|modify|delete|exfiltrate)\s+(confidential|sensitive|restricted|internal|protected)\s+(files?|records?|data|documents?|databases?)/i,
        /elevate\s+(privilege\s+level|permissions?)\s+to\s+(admin|root|system)/i,
        /recipient_domain\s*=\s*['"][^'"]*evil\.[a-z]+['"]/i
      ],
      explanation: "Attempts to trigger unapproved tools or elevate execution privilege inside the agent environment.",
      mitigation: "Enforce Tool Domain Policy Guards (D1) so tools cannot execute outside authorized domain whitelists."
    },
    {
      id: "context_smuggling",
      name: "Context Smuggling / Embedded Payload",
      severity: "MEDIUM",
      patterns: [
        /<!--\s*.*?(instruction|override|execute|system).*?-->/i,
        /\[SYSTEM\s+NOTICE\s*:\s*.*?\]/i,
        /\[ADMIN\s+(DIRECTIVE|OVERRIDE|NOTICE)\s*:\s*.*?\]/i,
        /BEGIN\s+SYSTEM\s+(OVERRIDE|INSTRUCTION|DIRECTIVE)/i,
        /<<<\s*OVERRIDE\s*>>>/i,
        /IMPORTANT\s+ADMIN\s+MEMO\s*:\s*/i,
        /\{\s*"system_instruction"\s*:\s*"[^"]+"\s*\}/i,
        /\/\*\s*SYSTEM\s+(OVERRIDE|INSTRUCTION|DIRECTIVE).*?\*\//i
      ],
      explanation: "Disguises instructions inside comments, brackets, or structured envelopes to slip past superficial filters.",
      mitigation: "Treat all retrieved documents and user attachments as untrusted data strings."
    },
    {
      id: "memory_poisoning_directive",
      name: "Memory Poisoning Directive",
      severity: "HIGH",
      patterns: [
        /remember\s+(this\s+|that\s+)?for\s+(all\s+)?future\s+(conversations?|sessions?|chats?|interactions?|prompts?|turns?|contexts?)\s*[:\.]?/i,
        /(admin_override|privilege_override|system_override)\s*=\s*(true|1|yes|active|enabled|all)/i,
        /store\s+in\s+(persistent\s+)?(memory|state|scratchpad|context)\s+that/i,
        /permanently\s+(update|change|set|modify)\s+your\s+(instructions?|beliefs?|persona|behavior|memory|rules?)\s+to/i,
        /write_memory\s*\(\s*(key\s*=\s*)?['"]?admin_override['"]?/i,
        /update_scratchpad\s*\(\s*privileged\s*=\s*true/i,
        /persist\s+(this\s+)?across\s+(all\s+)?(conversations?|sessions?)/i
      ],
      explanation: "Attempts to inject persistent directives into agent memory or scratchpad state to compromise future sessions.",
      mitigation: "Deploy Untrusted Memory Write Guards (D2) to reject state updates originating from untrusted inputs."
    }
  ];
  function scanTextLocally(text, maxLength = 16e3) {
    const boundedText = (text || "").slice(0, maxLength);
    const matches = [];
    for (const rule of SCANNER_RULES) {
      for (const pattern of rule.patterns) {
        const match = pattern.exec(boundedText);
        if (match) {
          let snippet = match[0];
          if (snippet.length > 80) {
            snippet = snippet.slice(0, 77) + "...";
          }
          matches.push({
            rule_id: rule.id,
            rule_name: rule.name,
            severity: rule.severity,
            confidence: "Heuristic Pattern Match",
            matched_snippet: snippet,
            explanation: rule.explanation,
            mitigation: rule.mitigation
          });
          break;
        }
      }
    }
    let riskLevel = "CLEAN";
    if (matches.some((m) => m.severity === "CRITICAL")) {
      riskLevel = "CRITICAL";
    } else if (matches.some((m) => m.severity === "HIGH")) {
      riskLevel = "HIGH";
    } else if (matches.some((m) => m.severity === "MEDIUM")) {
      riskLevel = "MEDIUM";
    } else if (matches.length > 0) {
      riskLevel = "LOW";
    }
    const summary = matches.length > 0 ? `Heuristic scanner detected ${matches.length} suspicious pattern(s). Highest severity: ${riskLevel}. (Note: Local heuristic match; not an execution-verified exploit).` : "No known prompt injection or exfiltration patterns matched. (Note: Heuristic safety check does not guarantee safety against novel vectors).";
    return {
      status: "completed",
      risk_level: riskLevel,
      rules_matched: matches,
      summary,
      is_heuristic_only: true,
      is_trace_verified: false,
      content_length: boundedText.length,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
  function redactSensitiveText(text, customTokens = []) {
    let result = text;
    result = result.replace(/CANARY-[a-zA-Z0-9_\-]+/gi, "[REDACTED_CANARY]");
    result = result.replace(/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/gi, "[REDACTED_EMAIL]");
    for (const token of customTokens) {
      if (token && token.trim().length > 2) {
        const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        result = result.replace(new RegExp(escaped, "gi"), "[REDACTED_USER_TEXT]");
      }
    }
    return result;
  }
  function escapeHtml(unsafe) {
    return (unsafe || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
  }

  // src/content.ts
  function getSupportedContext() {
    const url = window.location.href;
    const host = window.location.hostname.toLowerCase();
    if (url.includes("demo_chat.html")) {
      return {
        isSupported: true,
        contextName: "AgentBreak Synthetic Demo Chat",
        url,
        canInspectMessages: true
      };
    }
    if (host === "localhost" || host === "127.0.0.1") {
      return {
        isSupported: true,
        contextName: "Local AI Application / Dev Server",
        url,
        canInspectMessages: true
      };
    }
    if (host.includes("chatgpt.com") || host.includes("openai.com")) {
      return {
        isSupported: true,
        contextName: "ChatGPT Web Interface",
        url,
        canInspectMessages: true
      };
    }
    if (host.includes("claude.ai")) {
      return {
        isSupported: true,
        contextName: "Claude Web Interface",
        url,
        canInspectMessages: true
      };
    }
    return {
      isSupported: false,
      contextName: host || "Unsupported Website",
      url,
      canInspectMessages: false
    };
  }
  function extractVisibleMessages() {
    const messages = [];
    const demoItems = document.querySelectorAll(".agentbreak-chat-msg, [data-agentbreak-msg]");
    if (demoItems.length > 0) {
      demoItems.forEach((el, idx) => {
        const sender = el.getAttribute("data-sender") || "user";
        const text = el.innerText || el.textContent || "";
        if (text.trim()) {
          messages.push({
            id: `msg-${idx + 1}`,
            sender,
            text: text.trim().slice(0, 4e3),
            snippet: text.trim().slice(0, 80) + (text.length > 80 ? "..." : "")
          });
        }
      });
      return messages;
    }
    const chatgptBubbles = document.querySelectorAll("[data-message-author-role]");
    if (chatgptBubbles.length > 0) {
      chatgptBubbles.forEach((el, idx) => {
        const role = el.getAttribute("data-message-author-role");
        const sender = role === "assistant" ? "assistant" : "user";
        const text = el.innerText || el.textContent || "";
        if (text.trim()) {
          messages.push({
            id: `cg-${idx + 1}`,
            sender,
            text: text.trim().slice(0, 4e3),
            snippet: text.trim().slice(0, 80) + (text.length > 80 ? "..." : "")
          });
        }
      });
      return messages;
    }
    const paragraphs = document.querySelectorAll("p, .prose");
    paragraphs.forEach((p, idx) => {
      if (p.offsetParent === null) return;
      const text = p.innerText || p.textContent || "";
      if (text.trim().length > 20 && messages.length < 15) {
        messages.push({
          id: `p-${idx + 1}`,
          sender: "assistant",
          text: text.trim().slice(0, 2e3),
          snippet: text.trim().slice(0, 80) + (text.length > 80 ? "..." : "")
        });
      }
    });
    return messages;
  }
  var SentinelFloatingManager = class {
    hostEl = null;
    shadow = null;
    activeSelection = null;
    lastPromptedText = "";
    isResultsOpen = false;
    isConsentOpen = false;
    debounceTimer = null;
    currentLocalReport = null;
    currentBackendResponse = null;
    backendError = null;
    isScanningBackend = false;
    constructor() {
      this.init();
    }
    init() {
      const context = getSupportedContext();
      if (!context.isSupported) {
        return;
      }
      this.ensureHost();
      document.addEventListener("selectionchange", () => this.handleSelectionDebounced());
      document.addEventListener("mouseup", (e) => this.handleMouseUp(e));
      document.addEventListener("keyup", () => this.handleSelectionDebounced());
      document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
          this.dismissAll();
        }
      });
      document.addEventListener("mousedown", (e) => {
        if (this.hostEl && e.composedPath().includes(this.hostEl)) {
          return;
        }
        if (!this.isResultsOpen) {
          this.dismissPromptOnly();
        }
      });
    }
    ensureHost() {
      if (this.shadow && this.hostEl && document.body.contains(this.hostEl)) {
        return this.shadow;
      }
      const existing = document.getElementById("agentbreak-sentinel-host");
      if (existing) {
        existing.remove();
      }
      this.hostEl = document.createElement("div");
      this.hostEl.id = "agentbreak-sentinel-host";
      this.hostEl.style.position = "absolute";
      this.hostEl.style.top = "0";
      this.hostEl.style.left = "0";
      this.hostEl.style.zIndex = "2147483647";
      this.hostEl.style.pointerEvents = "none";
      this.shadow = this.hostEl.attachShadow({ mode: "open" });
      document.body.appendChild(this.hostEl);
      return this.shadow;
    }
    handleMouseUp(e) {
      if (this.hostEl && e.composedPath().includes(this.hostEl)) {
        return;
      }
      this.handleSelectionDebounced();
    }
    handleSelectionDebounced() {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = setTimeout(() => {
        this.evaluateSelection();
      }, 220);
    }
    evaluateSelection() {
      if (this.isResultsOpen) return;
      const selData = this.detectSelection();
      if (!selData || selData.text.length < 5) {
        this.dismissPromptOnly();
        return;
      }
      if (selData.text === this.lastPromptedText && this.activeSelection) {
        return;
      }
      this.activeSelection = selData;
      this.lastPromptedText = selData.text;
      this.showPrompt(selData);
    }
    detectSelection() {
      const activeEl = document.activeElement;
      if (activeEl instanceof HTMLTextAreaElement || activeEl instanceof HTMLInputElement && activeEl.type === "text") {
        const start = activeEl.selectionStart;
        const end = activeEl.selectionEnd;
        if (start !== null && end !== null && end > start) {
          const text2 = activeEl.value.substring(start, end).trim();
          if (text2.length >= 5) {
            const rect2 = activeEl.getBoundingClientRect();
            return {
              text: text2,
              coords: {
                x: rect2.left + window.scrollX,
                y: rect2.bottom + window.scrollY,
                width: rect2.width,
                height: rect2.height
              }
            };
          }
        }
      }
      const sel = window.getSelection();
      if (!sel || sel.isCollapsed || sel.rangeCount === 0) {
        return null;
      }
      const anchor = sel.anchorNode;
      if (anchor && anchor.parentElement) {
        const parent = anchor.parentElement;
        if (parent.closest("#agentbreak-sentinel-host") || parent.closest("button") || parent.closest('input[type="password"]') || parent.closest("nav")) {
          return null;
        }
      }
      const text = sel.toString().trim();
      if (text.length < 5) {
        return null;
      }
      const range = sel.getRangeAt(0);
      const rect = range.getBoundingClientRect();
      if (rect.width === 0 && rect.height === 0) {
        return null;
      }
      return {
        text,
        coords: {
          x: rect.left + window.scrollX,
          y: rect.bottom + window.scrollY,
          width: rect.width,
          height: rect.height
        }
      };
    }
    // Position floating container safely within viewport
    getContainerStyle(coords, popupWidth = 320) {
      const margin = 8;
      let top = coords.y + margin;
      let left = coords.x + coords.width / 2 - popupWidth / 2;
      const viewportWidth = window.innerWidth;
      const scrollX = window.scrollX;
      if (left < scrollX + 12) {
        left = scrollX + 12;
      } else if (left + popupWidth > scrollX + viewportWidth - 16) {
        left = scrollX + viewportWidth - popupWidth - 16;
      }
      return `position: absolute; top: ${top}px; left: ${left}px; pointer-events: auto;`;
    }
    showPrompt(selData) {
      const shadow = this.ensureHost();
      const style = this.getContainerStyle(selData.coords, 330);
      shadow.innerHTML = `
      <style>
        ${this.getBaseCss()}
      </style>
      <div id="sentinel-prompt-bubble" class="sentinel-box sentinel-bubble" style="${style}">
        <div class="sentinel-bubble-inner">
          <div class="sentinel-icon-badge">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <span class="sentinel-prompt-label">Analyze selected text with AgentBreak?</span>
          <div class="sentinel-bubble-actions">
            <button id="btn-analyze" class="sentinel-btn sentinel-btn-primary" title="Run local heuristic security scan">
              Analyze
            </button>
            <button id="btn-dismiss" class="sentinel-btn sentinel-btn-subtle" title="Dismiss prompt without scanning">
              Dismiss
            </button>
          </div>
        </div>
      </div>
    `;
      const bubbleEl = shadow.getElementById("sentinel-prompt-bubble");
      if (bubbleEl) {
        bubbleEl.addEventListener("mousedown", (e) => {
          e.stopPropagation();
        });
        bubbleEl.addEventListener("click", (e) => {
          e.stopPropagation();
        });
      }
      const btnAnalyze = shadow.getElementById("btn-analyze");
      if (btnAnalyze) {
        btnAnalyze.addEventListener("click", (e) => {
          e.preventDefault();
          e.stopPropagation();
          this.runAnalysis(selData.text, selData.coords);
        });
      }
      const btnDismiss = shadow.getElementById("btn-dismiss");
      if (btnDismiss) {
        btnDismiss.addEventListener("click", (e) => {
          e.preventDefault();
          e.stopPropagation();
          this.dismissAll();
        });
      }
    }
    runAnalysis(text, coords) {
      this.isResultsOpen = true;
      const shadow = this.ensureHost();
      const style = this.getContainerStyle(coords, 390);
      shadow.innerHTML = `
      <style>
        ${this.getBaseCss()}
      </style>
      <div class="sentinel-box sentinel-panel" style="${style}">
        <div class="sentinel-loading-row">
          <div class="sentinel-spinner"></div>
          <span>Analyzing selection with AgentBreak Sentinel...</span>
        </div>
      </div>
    `;
      setTimeout(() => {
        try {
          const report = scanTextLocally(text);
          this.currentLocalReport = report;
          this.currentBackendResponse = null;
          this.backendError = null;
          this.isConsentOpen = false;
          this.renderResults(coords);
        } catch (err) {
          this.renderError(err.message || "Local scanner failed", coords);
        }
      }, 120);
    }
    renderResults(coords) {
      const shadow = this.ensureHost();
      const report = this.currentLocalReport;
      if (!report) return;
      const style = this.getContainerStyle(coords, 420);
      const riskBadgeClass = `sentinel-badge-${report.risk_level.toLowerCase()}`;
      const ruleCount = report.rules_matched.length;
      shadow.innerHTML = `
      <style>
        ${this.getBaseCss()}
      </style>
      <div id="sentinel-results-panel" class="sentinel-box sentinel-panel" style="${style}">
        <!-- Panel Header -->
        <div class="sentinel-panel-header">
          <div class="sentinel-header-title">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#2563EB" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            <strong>AgentBreak Sentinel</strong>
            <span class="sentinel-risk-badge ${riskBadgeClass}">${report.risk_level}</span>
          </div>
          <button id="btn-close-panel" class="sentinel-icon-btn" title="Close results" aria-label="Close">\u2715</button>
        </div>

        <!-- Summary Row -->
        <div class="sentinel-summary-bar">
          <span><strong>${ruleCount}</strong> rule(s) matched</span>
          <span class="sentinel-tag-offline">Local Engine</span>
        </div>

        <!-- Matched Rules List -->
        <div class="sentinel-rules-container">
          ${ruleCount > 0 ? report.rules_matched.map(
        (m) => `
                <div class="sentinel-rule-card">
                  <div class="sentinel-rule-header">
                    <span class="sentinel-rule-name">${escapeHtml(m.rule_name)}</span>
                    <span class="sentinel-severity-tag sentinel-tag-${m.severity.toLowerCase()}">${m.severity}</span>
                  </div>
                  <p class="sentinel-rule-desc">${escapeHtml(m.explanation)}</p>
                  <div class="sentinel-snippet-box">
                    <span class="sentinel-snippet-label">Matched:</span>
                    <code>"${escapeHtml(m.matched_snippet)}"</code>
                  </div>
                  <div class="sentinel-mitigation-box">
                    <strong>Recommended Action:</strong> ${escapeHtml(m.mitigation)}
                  </div>
                </div>
              `
      ).join("") : `
                <div class="sentinel-clean-state">
                  <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#16A34A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                    <polyline points="22 4 12 14.01 9 11.01"/>
                  </svg>
                  <div>
                    <strong>No Known Threat Patterns Detected</strong>
                    <p style="margin: 2px 0 0 0; font-size: 11px; color: #64748B;">
                      Heuristic safety check evaluated static injection patterns. Not an execution-verified guarantee.
                    </p>
                  </div>
                </div>
              `}
        </div>

        <!-- Backend Consent & Status Area -->
        <div id="sentinel-backend-section" class="sentinel-backend-section">
          ${this.renderBackendSectionHtml()}
        </div>

        <!-- Panel Footer -->
        <div class="sentinel-panel-footer">
          <button id="btn-open-dashboard" class="sentinel-btn sentinel-btn-subtle" style="font-size: 11px;">
            Open Dashboard
          </button>
          <div style="display: flex; gap: 6px;">
            ${!this.isConsentOpen && !this.currentBackendResponse ? `<button id="btn-toggle-backend" class="sentinel-btn sentinel-btn-secondary" style="font-size: 11px;">
                    Verify with Backend
                  </button>` : ""}
            <button id="btn-panel-done" class="sentinel-btn sentinel-btn-primary" style="font-size: 11px;">
              Done
            </button>
          </div>
        </div>
      </div>
    `;
      this.attachPanelListeners(coords);
    }
    renderBackendSectionHtml() {
      if (this.currentBackendResponse) {
        const resp = this.currentBackendResponse;
        return `
        <div class="sentinel-backend-success">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
            <strong style="color: #15803D;">Backend Analysis Confirmed</strong>
            <span class="sentinel-risk-badge sentinel-badge-${resp.risk_level.toLowerCase()}">${resp.risk_level}</span>
          </div>
          <div style="font-size: 11px; color: #166534; line-height: 1.4;">
            ${escapeHtml(resp.summary)}
          </div>
          <div style="margin-top: 4px; font-size: 10px; color: #4B5563;">
            Scan ID: <code>${resp.scan_id}</code> | Ephemeral Memory Only
          </div>
        </div>
      `;
      }
      if (this.backendError) {
        return `
        <div class="sentinel-backend-error">
          <strong>Local analysis only \u2014 backend unavailable</strong>
          <p style="margin: 3px 0 0 0; font-size: 11px;">${escapeHtml(this.backendError)}</p>
        </div>
      `;
      }
      if (this.isConsentOpen && this.activeSelection) {
        return `
        <div class="sentinel-consent-card">
          <div class="sentinel-consent-header">
            <strong>Explicit Backend Transmission Consent</strong>
          </div>
          <p class="sentinel-consent-note">
            Before transmission to the AgentBreak FastAPI backend, review the exact excerpt below. You may redact sensitive values before explicit submission.
          </p>
          <textarea id="sentinel-preview-text" class="sentinel-preview-textarea" rows="3">${escapeHtml(
          this.activeSelection.text
        )}</textarea>
          <div class="sentinel-consent-toolbar">
            <button id="btn-redact-tokens" class="sentinel-btn sentinel-btn-subtle" style="font-size: 10px; padding: 3px 6px;">
              Redact Canaries / Emails
            </button>
            <span style="font-size: 10px; color: #64748B;">Never captures passwords or cookies</span>
          </div>
          <div style="display: flex; justify-content: flex-end; gap: 6px; margin-top: 8px;">
            <button id="btn-cancel-backend" class="sentinel-btn sentinel-btn-subtle" style="font-size: 11px;">
              Cancel
            </button>
            <button id="btn-confirm-backend" class="sentinel-btn sentinel-btn-primary" style="font-size: 11px;" ${this.isScanningBackend ? "disabled" : ""}>
              ${this.isScanningBackend ? "Sending..." : "Confirm & Send to Backend"}
            </button>
          </div>
        </div>
      `;
      }
      return "";
    }
    attachPanelListeners(coords) {
      const shadow = this.ensureHost();
      const panel = shadow.getElementById("sentinel-results-panel");
      if (panel) {
        panel.addEventListener("mousedown", (e) => e.stopPropagation());
        panel.addEventListener("click", (e) => e.stopPropagation());
      }
      const btnClose = shadow.getElementById("btn-close-panel");
      if (btnClose) {
        btnClose.addEventListener("click", () => this.dismissAll());
      }
      const btnDone = shadow.getElementById("btn-panel-done");
      if (btnDone) {
        btnDone.addEventListener("click", () => this.dismissAll());
      }
      const btnDashboard = shadow.getElementById("btn-open-dashboard");
      if (btnDashboard) {
        btnDashboard.addEventListener("click", () => {
          window.open("http://localhost:5173/#sentinel", "_blank");
        });
      }
      const btnToggleBackend = shadow.getElementById("btn-toggle-backend");
      if (btnToggleBackend) {
        btnToggleBackend.addEventListener("click", () => {
          this.isConsentOpen = true;
          this.renderResults(coords);
        });
      }
      const btnCancelBackend = shadow.getElementById("btn-cancel-backend");
      if (btnCancelBackend) {
        btnCancelBackend.addEventListener("click", () => {
          this.isConsentOpen = false;
          this.renderResults(coords);
        });
      }
      const btnRedact = shadow.getElementById("btn-redact-tokens");
      if (btnRedact) {
        btnRedact.addEventListener("click", () => {
          const textarea = shadow.getElementById("sentinel-preview-text");
          if (textarea) {
            textarea.value = redactSensitiveText(textarea.value);
          }
        });
      }
      const btnConfirmBackend = shadow.getElementById("btn-confirm-backend");
      if (btnConfirmBackend) {
        btnConfirmBackend.addEventListener("click", async () => {
          const textarea = shadow.getElementById("sentinel-preview-text");
          const textToSend = textarea ? textarea.value : this.activeSelection?.text || "";
          this.isScanningBackend = true;
          btnConfirmBackend.setAttribute("disabled", "true");
          btnConfirmBackend.innerText = "Transmitting...";
          try {
            const res = await new Promise((resolve) => {
              chrome.runtime.sendMessage(
                {
                  type: "SUBMIT_BACKEND_SCAN",
                  payload: {
                    text: textToSend,
                    consentGiven: true,
                    contextUrl: window.location.href
                  }
                },
                (response) => {
                  resolve(response);
                }
              );
            });
            this.isScanningBackend = false;
            if (res && res.success && res.data) {
              this.currentBackendResponse = res.data;
              this.backendError = null;
            } else {
              this.backendError = res && res.error || "Backend API server unreachable";
            }
          } catch (err) {
            this.isScanningBackend = false;
            this.backendError = err.message || "Backend network request failed";
          }
          this.isConsentOpen = false;
          this.renderResults(coords);
        });
      }
    }
    renderError(errMsg, coords) {
      const shadow = this.ensureHost();
      const style = this.getContainerStyle(coords, 340);
      shadow.innerHTML = `
      <style>
        ${this.getBaseCss()}
      </style>
      <div class="sentinel-box sentinel-panel" style="${style}">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <strong style="color: #DC2626;">Sentinel Scanning Error</strong>
          <button id="btn-err-close" class="sentinel-icon-btn">\u2715</button>
        </div>
        <p style="font-size: 12px; color: #4B5563; margin: 0 0 10px 0;">${escapeHtml(errMsg)}</p>
        <div style="display: flex; justify-content: flex-end;">
          <button id="btn-err-dismiss" class="sentinel-btn sentinel-btn-subtle">Dismiss</button>
        </div>
      </div>
    `;
      const close = () => this.dismissAll();
      shadow.getElementById("btn-err-close")?.addEventListener("click", close);
      shadow.getElementById("btn-err-dismiss")?.addEventListener("click", close);
    }
    dismissPromptOnly() {
      if (this.isResultsOpen) return;
      if (this.shadow) {
        this.shadow.innerHTML = "";
      }
      this.activeSelection = null;
    }
    dismissAll() {
      this.isResultsOpen = false;
      this.isConsentOpen = false;
      this.currentLocalReport = null;
      this.currentBackendResponse = null;
      this.backendError = null;
      this.activeSelection = null;
      if (this.shadow) {
        this.shadow.innerHTML = "";
      }
    }
    getBaseCss() {
      return `
      * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      }

      .sentinel-box {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 8px;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.12), 0 8px 10px -6px rgba(0, 0, 0, 0.08);
        color: #1E293B;
        font-size: 12px;
        line-height: 1.45;
        animation: sentinelFadeIn 0.15s ease-out;
      }

      @keyframes sentinelFadeIn {
        from { opacity: 0; transform: translateY(-4px); }
        to { opacity: 1; transform: translateY(0); }
      }

      /* Compact Floating Prompt Bubble */
      .sentinel-bubble {
        padding: 6px 10px;
        border-radius: 20px;
        box-shadow: 0 4px 14px rgba(15, 23, 42, 0.14);
      }

      .sentinel-bubble-inner {
        display: flex;
        align-items: center;
        gap: 8px;
        white-space: nowrap;
      }

      .sentinel-icon-badge {
        width: 24px;
        height: 24px;
        border-radius: 50%;
        background: #EFF6FF;
        color: #2563EB;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
      }

      .sentinel-prompt-label {
        font-size: 12px;
        font-weight: 500;
        color: #1E293B;
      }

      .sentinel-bubble-actions {
        display: flex;
        align-items: center;
        gap: 5px;
      }

      /* Buttons */
      .sentinel-btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        font-size: 11px;
        font-weight: 600;
        padding: 4px 10px;
        border-radius: 5px;
        border: 1px solid transparent;
        cursor: pointer;
        transition: all 0.12s ease;
        text-decoration: none;
      }

      .sentinel-btn:disabled {
        opacity: 0.6;
        cursor: not-allowed;
      }

      .sentinel-btn-primary {
        background: #2563EB;
        color: #FFFFFF;
      }

      .sentinel-btn-primary:hover:not(:disabled) {
        background: #1D4ED8;
      }

      .sentinel-btn-secondary {
        background: #F8FAFC;
        border-color: #CBD5E1;
        color: #334155;
      }

      .sentinel-btn-secondary:hover:not(:disabled) {
        background: #F1F5F9;
        border-color: #94A3B8;
      }

      .sentinel-btn-subtle {
        background: transparent;
        color: #64748B;
        border-color: #E2E8F0;
      }

      .sentinel-btn-subtle:hover:not(:disabled) {
        background: #F1F5F9;
        color: #1E293B;
      }

      .sentinel-icon-btn {
        background: transparent;
        border: none;
        color: #94A3B8;
        font-size: 14px;
        cursor: pointer;
        padding: 2px 4px;
        line-height: 1;
        border-radius: 4px;
      }

      .sentinel-icon-btn:hover {
        color: #1E293B;
        background: #F1F5F9;
      }

      /* Results Panel */
      .sentinel-panel {
        width: 390px;
        max-width: 92vw;
        padding: 12px;
      }

      .sentinel-panel-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding-bottom: 8px;
        border-bottom: 1px solid #F1F5F9;
        margin-bottom: 8px;
      }

      .sentinel-header-title {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 13px;
      }

      .sentinel-risk-badge {
        font-size: 10px;
        font-weight: 700;
        padding: 2px 6px;
        border-radius: 4px;
        text-transform: uppercase;
        letter-spacing: 0.3px;
      }

      .sentinel-badge-critical {
        background: #FEF2F2;
        color: #DC2626;
        border: 1px solid #FECACA;
      }

      .sentinel-badge-high {
        background: #FFF7ED;
        color: #EA580C;
        border: 1px solid #FED7AA;
      }

      .sentinel-badge-medium {
        background: #FFFBEB;
        color: #D97706;
        border: 1px solid #FDE68A;
      }

      .sentinel-badge-low {
        background: #EFF6FF;
        color: #2563EB;
        border: 1px solid #BFDBFE;
      }

      .sentinel-badge-clean {
        background: #F0FDF4;
        color: #16A34A;
        border: 1px solid #BBF7D0;
      }

      .sentinel-summary-bar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        font-size: 11px;
        color: #475569;
        margin-bottom: 8px;
      }

      .sentinel-tag-offline {
        font-size: 9px;
        font-weight: 600;
        background: #F8FAFC;
        border: 1px solid #E2E8F0;
        color: #64748B;
        padding: 1px 5px;
        border-radius: 4px;
      }

      .sentinel-rules-container {
        max-height: 240px;
        overflow-y: auto;
        display: flex;
        flex-direction: column;
        gap: 6px;
        margin-bottom: 8px;
      }

      .sentinel-rule-card {
        background: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-radius: 6px;
        padding: 8px 10px;
      }

      .sentinel-rule-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 3px;
      }

      .sentinel-rule-name {
        font-weight: 600;
        font-size: 11px;
        color: #0F172A;
      }

      .sentinel-severity-tag {
        font-size: 9px;
        font-weight: 700;
        padding: 1px 4px;
        border-radius: 3px;
      }

      .sentinel-tag-critical { background: #FEF2F2; color: #DC2626; }
      .sentinel-tag-high { background: #FFF7ED; color: #EA580C; }
      .sentinel-tag-medium { background: #FFFBEB; color: #D97706; }
      .sentinel-tag-low { background: #EFF6FF; color: #2563EB; }

      .sentinel-rule-desc {
        font-size: 11px;
        color: #475569;
        margin-bottom: 4px;
      }

      .sentinel-snippet-box {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 4px;
        padding: 3px 6px;
        font-size: 11px;
        color: #DC2626;
        word-break: break-word;
        margin-bottom: 4px;
      }

      .sentinel-snippet-label {
        font-weight: 600;
        color: #64748B;
        font-size: 10px;
        margin-right: 4px;
      }

      .sentinel-mitigation-box {
        font-size: 10px;
        color: #1E293B;
        background: #F1F5F9;
        padding: 4px 6px;
        border-radius: 4px;
      }

      .sentinel-clean-state {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 12px;
        background: #F0FDF4;
        border: 1px solid #BBF7D0;
        border-radius: 6px;
      }

      /* Backend Consent Card */
      .sentinel-backend-section {
        margin-bottom: 8px;
      }

      .sentinel-consent-card {
        background: #F8FAFC;
        border: 1px solid #CBD5E1;
        border-radius: 6px;
        padding: 8px 10px;
      }

      .sentinel-consent-header {
        font-size: 11px;
        color: #0F172A;
        margin-bottom: 2px;
      }

      .sentinel-consent-note {
        font-size: 10px;
        color: #64748B;
        margin-bottom: 6px;
      }

      .sentinel-preview-textarea {
        width: 100%;
        font-size: 11px;
        padding: 5px;
        border: 1px solid #CBD5E1;
        border-radius: 4px;
        resize: vertical;
        background: #FFFFFF;
        font-family: monospace;
      }

      .sentinel-consent-toolbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-top: 4px;
      }

      .sentinel-backend-success {
        background: #F0FDF4;
        border: 1px solid #86EFAC;
        border-radius: 6px;
        padding: 8px 10px;
      }

      .sentinel-backend-error {
        background: #FEF2F2;
        border: 1px solid #FECACA;
        border-radius: 6px;
        padding: 8px 10px;
        color: #991B1B;
      }

      .sentinel-panel-footer {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding-top: 8px;
        border-top: 1px solid #F1F5F9;
      }

      .sentinel-loading-row {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 14px 10px;
        font-size: 12px;
        font-weight: 500;
        color: #334155;
      }

      .sentinel-spinner {
        width: 16px;
        height: 16px;
        border: 2px solid #E2E8F0;
        border-top-color: #2563EB;
        border-radius: 50%;
        animation: sentinelSpin 0.7s linear infinite;
      }

      @keyframes sentinelSpin {
        to { transform: rotate(360deg); }
      }
    `;
    }
  };
  if (typeof document !== "undefined") {
    new SentinelFloatingManager();
  }
  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.type === "CHECK_SUPPORTED_STATUS") {
      const context = getSupportedContext();
      sendResponse({ success: true, data: context });
      return true;
    }
    if (message.type === "GET_SELECTED_TEXT") {
      const sel = window.getSelection();
      const selectedText = sel ? sel.toString().trim().slice(0, 16e3) : "";
      sendResponse({ success: true, data: { selectedText } });
      return true;
    }
    if (message.type === "GET_PAGE_MESSAGES") {
      const context = getSupportedContext();
      if (!context.isSupported) {
        sendResponse({
          success: false,
          error: "Current page structure is unsupported or message extraction is unavailable."
        });
        return true;
      }
      const msgs = extractVisibleMessages();
      sendResponse({ success: true, data: { messages: msgs, context } });
      return true;
    }
    return false;
  });
})();
