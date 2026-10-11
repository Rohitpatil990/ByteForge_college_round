#!/usr/bin/env node
/**
 * Ensures AgentBreak-Sentinel-Chrome-Extension.zip exists and is up to date
 * before building the dashboard.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dashboardDir = path.resolve(__dirname, '..');
const repoRoot = path.resolve(dashboardDir, '..');
const publicZip = path.resolve(dashboardDir, 'public', 'AgentBreak-Sentinel-Chrome-Extension.zip');
const extPackager = path.resolve(repoRoot, 'extension', 'scripts', 'package-extension.js');
const extManifest = path.resolve(repoRoot, 'extension', 'dist', 'manifest.json');

function ensureZip() {
  let needsRebuild = false;

  if (!fs.existsSync(publicZip)) {
    console.log('[ensure-extension-zip] Extension zip missing in dashboard/public, generating...');
    needsRebuild = true;
  } else if (fs.existsSync(extManifest)) {
    const zipTime = fs.statSync(publicZip).mtimeMs;
    const manifestTime = fs.statSync(extManifest).mtimeMs;
    if (manifestTime > zipTime) {
      console.log('[ensure-extension-zip] Extension dist is newer than zip, updating package...');
      needsRebuild = true;
    }
  }

  if (needsRebuild) {
    if (fs.existsSync(extPackager)) {
      execSync(`node "${extPackager}"`, { stdio: 'inherit' });
    } else {
      console.warn('[ensure-extension-zip] Warning: extension packager script not found at', extPackager);
    }
  } else {
    console.log('[ensure-extension-zip] Extension zip verified in dashboard/public.');
  }
}

try {
  ensureZip();
} catch (err) {
  console.warn('[ensure-extension-zip] Warning during zip check:', err.message);
}
