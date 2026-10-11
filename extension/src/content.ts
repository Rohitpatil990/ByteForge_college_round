/**
 * AgentBreak Sentinel - Content Script
 * Automatic selection analysis workflow, floating security prompt,
 * and privacy-preserving in-page inspector for supported AI interaction pages.
 */

import { scanTextLocally, redactSensitiveText, escapeHtml } from './scanner';
import {
  BackendScanResponse,
  ExtractedMessage,
  LocalScanReport,
  SupportedContextInfo,
} from './types';

// Supported site domain detection
export function getSupportedContext(): SupportedContextInfo {
  const url = window.location.href;
  const host = window.location.hostname.toLowerCase();

  if (url.includes('demo_chat.html')) {
    return {
      isSupported: true,
      contextName: 'AgentBreak Synthetic Demo Chat',
      url,
      canInspectMessages: true,
    };
  }

  if (host === 'localhost' || host === '127.0.0.1') {
    return {
      isSupported: true,
      contextName: 'Local AI Application / Dev Server',
      url,
      canInspectMessages: true,
    };
  }

  if (host.includes('chatgpt.com') || host.includes('openai.com')) {
    return {
      isSupported: true,
      contextName: 'ChatGPT Web Interface',
      url,
      canInspectMessages: true,
    };
  }

  if (host.includes('claude.ai')) {
    return {
      isSupported: true,
      contextName: 'Claude Web Interface',
      url,
      canInspectMessages: true,
    };
  }

  return {
    isSupported: false,
    contextName: host || 'Unsupported Website',
    url,
    canInspectMessages: false,
  };
}

// Extract visible chat messages from supported AI UI structures
function extractVisibleMessages(): ExtractedMessage[] {
  const messages: ExtractedMessage[] = [];

  // 1. Synthetic demo chat fixture elements
  const demoItems = document.querySelectorAll<HTMLElement>('.agentbreak-chat-msg, [data-agentbreak-msg]');
  if (demoItems.length > 0) {
    demoItems.forEach((el, idx) => {
      const sender = (el.getAttribute('data-sender') || 'user') as 'user' | 'assistant' | 'system';
      const text = el.innerText || el.textContent || '';
      if (text.trim()) {
        messages.push({
          id: `msg-${idx + 1}`,
          sender,
          text: text.trim().slice(0, 4000),
          snippet: text.trim().slice(0, 80) + (text.length > 80 ? '...' : ''),
        });
      }
    });
    return messages;
  }

  // 2. ChatGPT message elements
  const chatgptBubbles = document.querySelectorAll<HTMLElement>('[data-message-author-role]');
  if (chatgptBubbles.length > 0) {
    chatgptBubbles.forEach((el, idx) => {
      const role = el.getAttribute('data-message-author-role');
      const sender = role === 'assistant' ? 'assistant' : 'user';
      const text = el.innerText || el.textContent || '';
      if (text.trim()) {
        messages.push({
          id: `cg-${idx + 1}`,
          sender,
          text: text.trim().slice(0, 4000),
          snippet: text.trim().slice(0, 80) + (text.length > 80 ? '...' : ''),
        });
      }
    });
    return messages;
  }

  // 3. Fallback: extract visible paragraphs with reasonable length
  const paragraphs = document.querySelectorAll<HTMLElement>('p, .prose');
  paragraphs.forEach((p, idx) => {
    if (p.offsetParent === null) return;
    const text = p.innerText || p.textContent || '';
    if (text.trim().length > 20 && messages.length < 15) {
      messages.push({
        id: `p-${idx + 1}`,
        sender: 'assistant',
        text: text.trim().slice(0, 2000),
        snippet: text.trim().slice(0, 80) + (text.length > 80 ? '...' : ''),
      });
    }
  });

  return messages;
}

// ============================================================================
// Automatic Selection Detection & In-Page Floating UI
// ============================================================================

interface SelectionCoords {
  x: number;
  y: number;
  width: number;
  height: number;
}

interface CurrentSelectionData {
  text: string;
  coords: SelectionCoords;
}

class SentinelFloatingManager {
  private hostEl: HTMLElement | null = null;
  private shadow: ShadowRoot | null = null;
  private activeSelection: CurrentSelectionData | null = null;
  private lastPromptedText: string = '';
  private isResultsOpen: boolean = false;
  private isConsentOpen: boolean = false;
  private debounceTimer: any = null;
  private currentLocalReport: LocalScanReport | null = null;
  private currentBackendResponse: BackendScanResponse | null = null;
  private backendError: string | null = null;
  private isScanningBackend: boolean = false;

  constructor() {
    this.init();
  }

  private init() {
    const context = getSupportedContext();
    if (!context.isSupported) {
      return;
    }

    // Set up Shadow DOM host
    this.ensureHost();

    // Listen for selections
    document.addEventListener('selectionchange', () => this.handleSelectionDebounced());
    document.addEventListener('mouseup', (e) => this.handleMouseUp(e));
    document.addEventListener('keyup', () => this.handleSelectionDebounced());

    // Close on escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        this.dismissAll();
      }
    });

    // Dismiss prompt when clicking outside
    document.addEventListener('mousedown', (e) => {
      if (this.hostEl && e.composedPath().includes(this.hostEl)) {
        return;
      }
      if (!this.isResultsOpen) {
        this.dismissPromptOnly();
      }
    });
  }

  private ensureHost(): ShadowRoot {
    if (this.shadow && this.hostEl && document.body.contains(this.hostEl)) {
      return this.shadow;
    }

    const existing = document.getElementById('agentbreak-sentinel-host');
    if (existing) {
      existing.remove();
    }

    this.hostEl = document.createElement('div');
    this.hostEl.id = 'agentbreak-sentinel-host';
    this.hostEl.style.position = 'absolute';
    this.hostEl.style.top = '0';
    this.hostEl.style.left = '0';
    this.hostEl.style.zIndex = '2147483647';
    this.hostEl.style.pointerEvents = 'none';

    this.shadow = this.hostEl.attachShadow({ mode: 'open' });
    document.body.appendChild(this.hostEl);
    return this.shadow;
  }

  private handleMouseUp(e: MouseEvent) {
    // Avoid re-triggering if user clicks inside our own UI
    if (this.hostEl && e.composedPath().includes(this.hostEl)) {
      return;
    }
    this.handleSelectionDebounced();
  }

  private handleSelectionDebounced() {
    clearTimeout(this.debounceTimer);
    this.debounceTimer = setTimeout(() => {
      this.evaluateSelection();
    }, 220);
  }

  private evaluateSelection() {
    // Do not disrupt if results panel is actively open
    if (this.isResultsOpen) return;

    const selData = this.detectSelection();
    if (!selData || selData.text.length < 5) {
      this.dismissPromptOnly();
      return;
    }

    // Deduplicate repeated events on identical text
    if (selData.text === this.lastPromptedText && this.activeSelection) {
      return;
    }

    this.activeSelection = selData;
    this.lastPromptedText = selData.text;
    this.showPrompt(selData);
  }

  private detectSelection(): CurrentSelectionData | null {
    const activeEl = document.activeElement;

    // 1. Textarea or Input selection
    if (
      activeEl instanceof HTMLTextAreaElement ||
      (activeEl instanceof HTMLInputElement && activeEl.type === 'text')
    ) {
      const start = activeEl.selectionStart;
      const end = activeEl.selectionEnd;
      if (start !== null && end !== null && end > start) {
        const text = activeEl.value.substring(start, end).trim();
        if (text.length >= 5) {
          const rect = activeEl.getBoundingClientRect();
          return {
            text,
            coords: {
              x: rect.left + window.scrollX,
              y: rect.bottom + window.scrollY,
              width: rect.width,
              height: rect.height,
            },
          };
        }
      }
    }

    // 2. Standard DOM / Contenteditable selection
    const sel = window.getSelection();
    if (!sel || sel.isCollapsed || sel.rangeCount === 0) {
      return null;
    }

    // Avoid selections inside password or button elements
    const anchor = sel.anchorNode;
    if (anchor && anchor.parentElement) {
      const parent = anchor.parentElement;
      if (
        parent.closest('#agentbreak-sentinel-host') ||
        parent.closest('button') ||
        parent.closest('input[type="password"]') ||
        parent.closest('nav')
      ) {
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
        height: rect.height,
      },
    };
  }

  // Position floating container safely within viewport
  private getContainerStyle(coords: SelectionCoords, popupWidth: number = 320): string {
    const margin = 8;
    let top = coords.y + margin;
    let left = coords.x + coords.width / 2 - popupWidth / 2;

    const viewportWidth = window.innerWidth;
    const scrollX = window.scrollX;

    // Clamp horizontally
    if (left < scrollX + 12) {
      left = scrollX + 12;
    } else if (left + popupWidth > scrollX + viewportWidth - 16) {
      left = scrollX + viewportWidth - popupWidth - 16;
    }

    return `position: absolute; top: ${top}px; left: ${left}px; pointer-events: auto;`;
  }

  private showPrompt(selData: CurrentSelectionData) {
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

    const bubbleEl = shadow.getElementById('sentinel-prompt-bubble');
    if (bubbleEl) {
      // Prevent mousedown on the bubble from un-selecting text or triggering AI chat submit
      bubbleEl.addEventListener('mousedown', (e) => {
        e.stopPropagation();
      });
      bubbleEl.addEventListener('click', (e) => {
        e.stopPropagation();
      });
    }

    const btnAnalyze = shadow.getElementById('btn-analyze');
    if (btnAnalyze) {
      btnAnalyze.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        this.runAnalysis(selData.text, selData.coords);
      });
    }

    const btnDismiss = shadow.getElementById('btn-dismiss');
    if (btnDismiss) {
      btnDismiss.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        this.dismissAll();
      });
    }
  }

  private runAnalysis(text: string, coords: SelectionCoords) {
    this.isResultsOpen = true;
    const shadow = this.ensureHost();
    const style = this.getContainerStyle(coords, 390);

    // Render loading indicator immediately
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

    // Execute local heuristic scan
    setTimeout(() => {
      try {
        const report = scanTextLocally(text);
        this.currentLocalReport = report;
        this.currentBackendResponse = null;
        this.backendError = null;
        this.isConsentOpen = false;
        this.renderResults(coords);
      } catch (err: any) {
        this.renderError(err.message || 'Local scanner failed', coords);
      }
    }, 120);
  }

  private renderResults(coords: SelectionCoords) {
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
          <button id="btn-close-panel" class="sentinel-icon-btn" title="Close results" aria-label="Close">✕</button>
        </div>

        <!-- Summary Row -->
        <div class="sentinel-summary-bar">
          <span><strong>${ruleCount}</strong> rule(s) matched</span>
          <span class="sentinel-tag-offline">Local Engine</span>
        </div>

        <!-- Matched Rules List -->
        <div class="sentinel-rules-container">
          ${
            ruleCount > 0
              ? report.rules_matched
                  .map(
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
                  )
                  .join('')
              : `
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
              `
          }
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
            ${
              !this.isConsentOpen && !this.currentBackendResponse
                ? `<button id="btn-toggle-backend" class="sentinel-btn sentinel-btn-secondary" style="font-size: 11px;">
                    Verify with Backend
                  </button>`
                : ''
            }
            <button id="btn-panel-done" class="sentinel-btn sentinel-btn-primary" style="font-size: 11px;">
              Done
            </button>
          </div>
        </div>
      </div>
    `;

    this.attachPanelListeners(coords);
  }

  private renderBackendSectionHtml(): string {
    // 1. If backend scan succeeded
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

    // 2. If backend failed or was unreachable
    if (this.backendError) {
      return `
        <div class="sentinel-backend-error">
          <strong>Local analysis only — backend unavailable</strong>
          <p style="margin: 3px 0 0 0; font-size: 11px;">${escapeHtml(this.backendError)}</p>
        </div>
      `;
    }

    // 3. If consent workflow is actively open
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
            <button id="btn-confirm-backend" class="sentinel-btn sentinel-btn-primary" style="font-size: 11px;" ${
              this.isScanningBackend ? 'disabled' : ''
            }>
              ${this.isScanningBackend ? 'Sending...' : 'Confirm & Send to Backend'}
            </button>
          </div>
        </div>
      `;
    }

    return '';
  }

  private attachPanelListeners(coords: SelectionCoords) {
    const shadow = this.ensureHost();
    const panel = shadow.getElementById('sentinel-results-panel');
    if (panel) {
      panel.addEventListener('mousedown', (e) => e.stopPropagation());
      panel.addEventListener('click', (e) => e.stopPropagation());
    }

    const btnClose = shadow.getElementById('btn-close-panel');
    if (btnClose) {
      btnClose.addEventListener('click', () => this.dismissAll());
    }

    const btnDone = shadow.getElementById('btn-panel-done');
    if (btnDone) {
      btnDone.addEventListener('click', () => this.dismissAll());
    }

    const btnDashboard = shadow.getElementById('btn-open-dashboard');
    if (btnDashboard) {
      btnDashboard.addEventListener('click', () => {
        window.open('http://localhost:5173/#sentinel', '_blank');
      });
    }

    const btnToggleBackend = shadow.getElementById('btn-toggle-backend');
    if (btnToggleBackend) {
      btnToggleBackend.addEventListener('click', () => {
        this.isConsentOpen = true;
        this.renderResults(coords);
      });
    }

    const btnCancelBackend = shadow.getElementById('btn-cancel-backend');
    if (btnCancelBackend) {
      btnCancelBackend.addEventListener('click', () => {
        this.isConsentOpen = false;
        this.renderResults(coords);
      });
    }

    const btnRedact = shadow.getElementById('btn-redact-tokens');
    if (btnRedact) {
      btnRedact.addEventListener('click', () => {
        const textarea = shadow.getElementById('sentinel-preview-text') as HTMLTextAreaElement | null;
        if (textarea) {
          textarea.value = redactSensitiveText(textarea.value);
        }
      });
    }

    const btnConfirmBackend = shadow.getElementById('btn-confirm-backend');
    if (btnConfirmBackend) {
      btnConfirmBackend.addEventListener('click', async () => {
        const textarea = shadow.getElementById('sentinel-preview-text') as HTMLTextAreaElement | null;
        const textToSend = textarea ? textarea.value : this.activeSelection?.text || '';

        this.isScanningBackend = true;
        btnConfirmBackend.setAttribute('disabled', 'true');
        btnConfirmBackend.innerText = 'Transmitting...';

        try {
          const res = await new Promise<any>((resolve) => {
            chrome.runtime.sendMessage(
              {
                type: 'SUBMIT_BACKEND_SCAN',
                payload: {
                  text: textToSend,
                  consentGiven: true,
                  contextUrl: window.location.href,
                },
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
            this.backendError = (res && res.error) || 'Backend API server unreachable';
          }
        } catch (err: any) {
          this.isScanningBackend = false;
          this.backendError = err.message || 'Backend network request failed';
        }

        this.isConsentOpen = false;
        this.renderResults(coords);
      });
    }
  }

  private renderError(errMsg: string, coords: SelectionCoords) {
    const shadow = this.ensureHost();
    const style = this.getContainerStyle(coords, 340);

    shadow.innerHTML = `
      <style>
        ${this.getBaseCss()}
      </style>
      <div class="sentinel-box sentinel-panel" style="${style}">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <strong style="color: #DC2626;">Sentinel Scanning Error</strong>
          <button id="btn-err-close" class="sentinel-icon-btn">✕</button>
        </div>
        <p style="font-size: 12px; color: #4B5563; margin: 0 0 10px 0;">${escapeHtml(errMsg)}</p>
        <div style="display: flex; justify-content: flex-end;">
          <button id="btn-err-dismiss" class="sentinel-btn sentinel-btn-subtle">Dismiss</button>
        </div>
      </div>
    `;

    const close = () => this.dismissAll();
    shadow.getElementById('btn-err-close')?.addEventListener('click', close);
    shadow.getElementById('btn-err-dismiss')?.addEventListener('click', close);
  }

  public dismissPromptOnly() {
    if (this.isResultsOpen) return;
    if (this.shadow) {
      this.shadow.innerHTML = '';
    }
    this.activeSelection = null;
  }

  public dismissAll() {
    this.isResultsOpen = false;
    this.isConsentOpen = false;
    this.currentLocalReport = null;
    this.currentBackendResponse = null;
    this.backendError = null;
    this.activeSelection = null;
    if (this.shadow) {
      this.shadow.innerHTML = '';
    }
  }

  private getBaseCss(): string {
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
}

// Instantiate automatic selection manager
if (typeof document !== 'undefined') {
  new SentinelFloatingManager();
}

// Message listener from extension popup or options
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'CHECK_SUPPORTED_STATUS') {
    const context = getSupportedContext();
    sendResponse({ success: true, data: context });
    return true;
  }

  if (message.type === 'GET_SELECTED_TEXT') {
    const sel = window.getSelection();
    const selectedText = sel ? sel.toString().trim().slice(0, 16000) : '';
    sendResponse({ success: true, data: { selectedText } });
    return true;
  }

  if (message.type === 'GET_PAGE_MESSAGES') {
    const context = getSupportedContext();
    if (!context.isSupported) {
      sendResponse({
        success: false,
        error: 'Current page structure is unsupported or message extraction is unavailable.',
      });
      return true;
    }
    const msgs = extractVisibleMessages();
    sendResponse({ success: true, data: { messages: msgs, context } });
    return true;
  }

  return false;
});
