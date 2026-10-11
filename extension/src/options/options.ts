/**
 * AgentBreak Sentinel - Options Page Controller
 */

import { ExtensionSettings } from '../types';

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('settings-form') as HTMLFormElement;
  const inputApiUrl = document.getElementById('api-base-url') as HTMLInputElement;
  const inputTargetId = document.getElementById('target-id') as HTMLInputElement;
  const inputAsmtId = document.getElementById('active-asmt-id') as HTMLInputElement;
  const chkOffline = document.getElementById('chk-offline-mode') as HTMLInputElement;
  const saveStatus = document.getElementById('save-status') as HTMLElement;

  // Load current settings
  chrome.storage.local.get(['settings'], (result) => {
    const s: ExtensionSettings = result.settings || {
      apiBaseUrl: 'http://127.0.0.1:8000',
      targetId: 'demo-company-assistant',
      offlineMode: false,
    };
    inputApiUrl.value = s.apiBaseUrl || 'http://127.0.0.1:8000';
    inputTargetId.value = s.targetId || 'demo-company-assistant';
    inputAsmtId.value = s.activeAssessmentId || '';
    chkOffline.checked = !!s.offlineMode;
  });

  // Save on submit
  form.addEventListener('submit', (e) => {
    e.preventDefault();

    const updated: ExtensionSettings = {
      apiBaseUrl: inputApiUrl.value.trim() || 'http://127.0.0.1:8000',
      targetId: inputTargetId.value.trim() || 'demo-company-assistant',
      activeAssessmentId: inputAsmtId.value.trim() || undefined,
      offlineMode: chkOffline.checked,
    };

    chrome.storage.local.set({ settings: updated }, () => {
      saveStatus.style.display = 'inline';
      setTimeout(() => {
        saveStatus.style.display = 'none';
      }, 3000);
    });
  });
});
