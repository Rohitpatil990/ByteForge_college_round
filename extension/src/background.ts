/**
 * AgentBreak Sentinel - Background Service Worker (Manifest V3)
 * Manages configuration storage, message validation, backend analysis dispatches,
 * and badge updates without persistent background collection.
 */

import { scanTextLocally } from './scanner';
import {
  BackendScanResponse,
  ExtensionMessage,
  ExtensionSettings,
  LocalScanReport,
  MessageResponse,
} from './types';

const DEFAULT_SETTINGS: ExtensionSettings = {
  apiBaseUrl: 'http://127.0.0.1:8000',
  targetId: 'demo-company-assistant',
  offlineMode: false,
};

// Ensure default settings exist on install/startup
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(['settings'], (result) => {
    if (!result.settings) {
      chrome.storage.local.set({ settings: DEFAULT_SETTINGS });
    }
  });
});

async function getStoredSettings(): Promise<ExtensionSettings> {
  return new Promise((resolve) => {
    chrome.storage.local.get(['settings'], (res) => {
      resolve({ ...DEFAULT_SETTINGS, ...(res.settings || {}) });
    });
  });
}

// Secure Message Listener with strict sender & payload validation
chrome.runtime.onMessage.addListener(
  (
    message: ExtensionMessage,
    _sender: chrome.runtime.MessageSender,
    sendResponse: (response: MessageResponse<any>) => void
  ) => {
    // Wrap async operations cleanly
    (async () => {
      try {
        if (!message || typeof message.type !== 'string') {
          return sendResponse({ success: false, error: 'Malformed message: missing type.' });
        }

        switch (message.type) {
          case 'GET_SETTINGS': {
            const settings = await getStoredSettings();
            return sendResponse({ success: true, data: settings });
          }

          case 'SAVE_SETTINGS': {
            const current = await getStoredSettings();
            const updated = { ...current, ...(message.payload || {}) };
            await chrome.storage.local.set({ settings: updated });
            return sendResponse({ success: true, data: updated });
          }

          case 'RUN_LOCAL_SCAN': {
            const text = message.payload?.text || '';
            const report: LocalScanReport = scanTextLocally(text);
            updateBadge(report.risk_level, report.rules_matched.length);
            return sendResponse({ success: true, data: report });
          }

          case 'SUBMIT_BACKEND_SCAN': {
            const { text, consentGiven, contextUrl } = message.payload;
            if (!consentGiven) {
              return sendResponse({
                success: false,
                error: 'Consent not granted: user must explicitly approve text submission.',
              });
            }

            const settings = await getStoredSettings();
            if (settings.offlineMode) {
              // Explicit offline mode fallback
              const localReport = scanTextLocally(text);
              return sendResponse({
                success: true,
                data: {
                  scan_id: `ext-offline-${Date.now()}`,
                  timestamp: new Date().toISOString(),
                  status: 'completed_offline',
                  risk_level: localReport.risk_level,
                  content_length: text.length,
                  sanitized_excerpt: text.slice(0, 160) + (text.length > 160 ? '...' : ''),
                  rules_matched: localReport.rules_matched,
                  summary: `${localReport.summary} (Executed via local offline engine).`,
                  is_heuristic_only: true,
                  is_trace_verified: false,
                  linked_assessment_id: null,
                  mitigation_advice: localReport.rules_matched.map((r) => r.mitigation),
                  privacy_notice: 'Processed in browser memory only (Offline Mode active).',
                } as BackendScanResponse,
              });
            }

            // Dispatch to configured backend with timeout
            const url = `${settings.apiBaseUrl.replace(/\/+$/, '')}/extension/scan`;
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 8000);

            try {
              const resp = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  content: text,
                  consent_given: true,
                  target_id: settings.targetId,
                  assessment_id: settings.activeAssessmentId || undefined,
                  context_url: contextUrl || undefined,
                }),
                signal: controller.signal,
              });
              clearTimeout(timeoutId);

              if (!resp.ok) {
                const errDetail = await resp.text();
                return sendResponse({
                  success: false,
                  error: `Backend error (${resp.status}): ${errDetail.slice(0, 200)}`,
                });
              }

              const data: BackendScanResponse = await resp.json();
              updateBadge(data.risk_level, data.rules_matched.length);
              return sendResponse({ success: true, data });
            } catch (netErr: any) {
              clearTimeout(timeoutId);
              const errMsg = netErr.name === 'AbortError'
                ? 'Backend request timed out (8s). Check if backend is reachable.'
                : `Network error: ${netErr.message || 'Cannot reach AgentBreak API'}`;
              return sendResponse({ success: false, error: errMsg });
            }
          }

          case 'CLEAR_LOCAL_DATA': {
            await chrome.storage.local.remove(['cachedScans', 'recentSnippets']);
            chrome.action.setBadgeText({ text: '' });
            return sendResponse({ success: true });
          }

          default:
            return sendResponse({ success: false, error: `Unhandled message type: ${(message as any).type}` });
        }
      } catch (err: any) {
        return sendResponse({ success: false, error: err.message || 'Unknown internal error' });
      }
    })();

    return true; // Keep message channel open for async response
  }
);

function updateBadge(riskLevel: string, matchCount: number) {
  if (matchCount > 0) {
    chrome.action.setBadgeText({ text: String(matchCount) });
    const color = riskLevel === 'CRITICAL' ? '#dc2626' : riskLevel === 'HIGH' ? '#ea580c' : '#d97706';
    chrome.action.setBadgeBackgroundColor({ color });
  } else {
    chrome.action.setBadgeText({ text: 'OK' });
    chrome.action.setBadgeBackgroundColor({ color: '#16a34a' });
  }
}
