/**
 * AgentBreak Sentinel - Popup Controller Logic
 */

import { escapeHtml, redactSensitiveText } from '../scanner';
import {
  BackendScanResponse,
  LocalScanReport,
  MessageResponse,
  ScannerRuleMatch,
  SupportedContextInfo,
} from '../types';

document.addEventListener('DOMContentLoaded', async () => {
  // Elements
  const contextTag = document.getElementById('context-tag') as HTMLElement;
  const btnCaptureSel = document.getElementById('btn-capture-selection') as HTMLButtonElement;
  const btnInspectMsgs = document.getElementById('btn-inspect-messages') as HTMLButtonElement;
  const inputContent = document.getElementById('input-content') as HTMLTextAreaElement;
  const btnRedact = document.getElementById('btn-redact') as HTMLButtonElement;
  const btnClearInput = document.getElementById('btn-clear-input') as HTMLButtonElement;
  const charCounter = document.getElementById('char-counter') as HTMLElement;
  const chkConsent = document.getElementById('chk-consent') as HTMLInputElement;
  const btnScanLocal = document.getElementById('btn-scan-local') as HTMLButtonElement;
  const btnAnalyzeBackend = document.getElementById('btn-analyze-backend') as HTMLButtonElement;
  const resultsContainer = document.getElementById('results-container') as HTMLElement;
  const riskBanner = document.getElementById('risk-banner') as HTMLElement;
  const riskTitle = document.getElementById('risk-title') as HTMLElement;
  const riskBadge = document.getElementById('risk-score-badge') as HTMLElement;
  const resultsSummary = document.getElementById('results-summary') as HTMLElement;
  const ruleMatchesList = document.getElementById('rule-matches-list') as HTMLElement;
  const backendLinkBox = document.getElementById('backend-link-box') as HTMLElement;
  const linkDashboardAsmt = document.getElementById('link-dashboard-asmt') as HTMLAnchorElement;
  const loadingState = document.getElementById('loading-state') as HTMLElement;
  const btnClearLocal = document.getElementById('btn-clear-local') as HTMLButtonElement;
  const btnOpenOptions = document.getElementById('btn-open-options') as HTMLButtonElement;

  let activeTabUrl = '';

  // Update char counter
  function updateCharCount() {
    const len = inputContent.value.length;
    charCounter.textContent = `${len.toLocaleString()} / 16,000 characters`;
    if (len > 16000) {
      charCounter.style.color = '#dc2626';
    } else {
      charCounter.style.color = '#64748b';
    }
  }

  inputContent.addEventListener('input', updateCharCount);

  // Clear input
  btnClearInput.addEventListener('click', () => {
    inputContent.value = '';
    updateCharCount();
  });

  // Redact sensitive text
  btnRedact.addEventListener('click', () => {
    const current = inputContent.value;
    if (!current) return;
    inputContent.value = redactSensitiveText(current);
    updateCharCount();
  });

  // Open Options page
  btnOpenOptions.addEventListener('click', () => {
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      window.open(chrome.runtime.getURL('src/options/index.html'));
    }
  });

  // Clear local data
  btnClearLocal.addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'CLEAR_LOCAL_DATA' }, () => {
      inputContent.value = '';
      updateCharCount();
      resultsContainer.style.display = 'none';
      alert('Local Sentinel cache and badge cleared.');
    });
  });

  // Query Active Tab
  async function inspectActiveTab() {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tabs || tabs.length === 0) {
        contextTag.textContent = 'No Active Tab';
        contextTag.className = 'context-tag tag-unsupported';
        return;
      }

      const activeTab = tabs[0];
      const activeTabId = activeTab.id;
      if (typeof activeTabId !== 'number') {
        contextTag.textContent = 'No Active Tab ID';
        contextTag.className = 'context-tag tag-unsupported';
        return;
      }
      activeTabUrl = activeTab.url || '';

      // Send status check to content script
      chrome.tabs.sendMessage(
        activeTabId,
        { type: 'CHECK_SUPPORTED_STATUS' },
        (response: MessageResponse<SupportedContextInfo>) => {
          if (chrome.runtime.lastError || !response || !response.success || !response.data) {
            // Not supported or content script not injected
            const host = activeTabUrl ? new URL(activeTabUrl).hostname : 'Current Page';
            contextTag.textContent = `${host} (Unsupported or Idle)`;
            contextTag.className = 'context-tag tag-unsupported';
            btnInspectMsgs.disabled = true;
            return;
          }

          const ctx = response.data;
          if (ctx.isSupported) {
            contextTag.textContent = `✓ ${ctx.contextName}`;
            contextTag.className = 'context-tag tag-supported';
            btnInspectMsgs.disabled = false;
          } else {
            contextTag.textContent = `✗ ${ctx.contextName} (Unsupported)`;
            contextTag.className = 'context-tag tag-unsupported';
            btnInspectMsgs.disabled = true;
          }
        }
      );
    } catch {
      contextTag.textContent = 'Unavailable';
      contextTag.className = 'context-tag tag-unsupported';
    }
  }

  await inspectActiveTab();

  // Capture Selection
  btnCaptureSel.addEventListener('click', async () => {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tabId = tabs[0]?.id;
    if (typeof tabId !== 'number') return;

    chrome.tabs.sendMessage(tabId, { type: 'GET_SELECTED_TEXT' }, (resp) => {
      if (chrome.runtime.lastError || !resp?.data?.selectedText) {
        alert('No text currently selected on page. Highlight some text first or use "Inspect Messages".');
        return;
      }
      inputContent.value = resp.data.selectedText;
      updateCharCount();
    });
  });

  // Inspect Messages from DOM
  btnInspectMsgs.addEventListener('click', async () => {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tabId = tabs[0]?.id;
    if (typeof tabId !== 'number') return;

    chrome.tabs.sendMessage(tabId, { type: 'GET_PAGE_MESSAGES' }, (resp) => {
      if (chrome.runtime.lastError || !resp?.data?.messages || resp.data.messages.length === 0) {
        alert('No conversation message bubbles detected in current tab view.');
        return;
      }
      const msgs = resp.data.messages;
      const combined = msgs.map((m: any) => `[${m.sender.toUpperCase()}]: ${m.text}`).join('\n\n');
      inputContent.value = combined;
      updateCharCount();
    });
  });

  // Render scan results UI
  function displayResults(report: LocalScanReport | BackendScanResponse, isBackend: boolean) {
    loadingState.style.display = 'none';
    resultsContainer.style.display = 'flex';

    // Banner
    const risk = report.risk_level || 'CLEAN';
    riskBanner.className = `risk-banner banner-${risk}`;
    riskTitle.textContent = isBackend ? `BACKEND SCAN: ${risk}` : `LOCAL HEURISTIC: ${risk}`;
    riskBadge.textContent = `${risk} RISK`;
    riskBadge.className = `badge badge-${risk}`;

    resultsSummary.textContent = report.summary;

    // Matches List
    ruleMatchesList.innerHTML = '';
    const matches: ScannerRuleMatch[] = report.rules_matched || [];

    if (matches.length === 0) {
      const cleanBox = document.createElement('div');
      cleanBox.className = 'rule-match-item';
      cleanBox.style.borderLeftColor = '#16a34a';
      cleanBox.innerHTML = `
        <div class="rule-header">
          <span class="rule-title">No Suspicious Patterns Detected</span>
          <span class="badge badge-LOW">PASS</span>
        </div>
        <div class="explanation-text">
          Text passed all 5 prompt injection, secret exfiltration, tool manipulation, context smuggling, and memory tampering rules.
        </div>
      `;
      ruleMatchesList.appendChild(cleanBox);
    } else {
      matches.forEach((m) => {
        const item = document.createElement('div');
        item.className = `rule-match-item ${m.severity}`;
        item.innerHTML = `
          <div class="rule-header">
            <span class="rule-title">${escapeHtml(m.rule_name)}</span>
            <span class="badge badge-${escapeHtml(m.severity)}">${escapeHtml(m.severity)}</span>
          </div>
          <div class="snippet-box"><code>${escapeHtml(m.matched_snippet)}</code></div>
          <div class="explanation-text">${escapeHtml(m.explanation)}</div>
          <div class="mitigation-text"><b>Recommended Action:</b> ${escapeHtml(m.mitigation)}</div>
        `;
        ruleMatchesList.appendChild(item);
      });
    }

    // Backend link if available
    const bReport = report as BackendScanResponse;
    if (bReport.linked_assessment_id) {
      backendLinkBox.style.display = 'block';
      linkDashboardAsmt.href = `http://localhost:5173/?asmt=${encodeURIComponent(bReport.linked_assessment_id)}`;
      linkDashboardAsmt.textContent = `↗ View Linked Assessment (${bReport.linked_assessment_id.slice(0, 8)}...)`;
    } else {
      backendLinkBox.style.display = 'none';
    }
  }

  // Scan Locally (Offline)
  btnScanLocal.addEventListener('click', () => {
    const text = inputContent.value.trim();
    if (!text) {
      alert('Please enter or capture some text to scan.');
      return;
    }
    loadingState.style.display = 'block';
    resultsContainer.style.display = 'none';

    chrome.runtime.sendMessage(
      { type: 'RUN_LOCAL_SCAN', payload: { text } },
      (response: MessageResponse<LocalScanReport>) => {
        if (!response || !response.success || !response.data) {
          loadingState.style.display = 'none';
          alert(`Scan error: ${response?.error || 'Unknown error'}`);
          return;
        }
        displayResults(response.data, false);
      }
    );
  });

  // Analyze with AgentBreak (Backend)
  btnAnalyzeBackend.addEventListener('click', () => {
    const text = inputContent.value.trim();
    if (!text) {
      alert('Please enter or capture text before submitting for analysis.');
      return;
    }

    if (!chkConsent.checked) {
      alert('Consent Required: You must check the consent box to confirm submission.');
      return;
    }

    loadingState.style.display = 'block';
    resultsContainer.style.display = 'none';

    chrome.runtime.sendMessage(
      {
        type: 'SUBMIT_BACKEND_SCAN',
        payload: {
          text,
          consentGiven: true,
          contextUrl: activeTabUrl,
        },
      },
      (response: MessageResponse<BackendScanResponse>) => {
        loadingState.style.display = 'none';
        if (!response || !response.success || !response.data) {
          alert(`Analysis Error: ${response?.error || 'Failed to connect to backend.'}`);
          return;
        }
        displayResults(response.data, true);
      }
    );
  });
});
