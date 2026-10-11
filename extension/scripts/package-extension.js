#!/usr/bin/env node
/**
 * AgentBreak Sentinel Extension Packager Bridge
 * Invokes python scripts/package_extension.py or falls back to native node zip creation.
 */

import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import zlib from 'zlib';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const extDir = path.resolve(__dirname, '..');
const distDir = path.resolve(extDir, 'dist');
const repoRoot = path.resolve(extDir, '..');
const dashboardPublic = path.resolve(repoRoot, 'dashboard', 'public');
const dashboardDist = path.resolve(repoRoot, 'dashboard', 'dist');
const pyScript = path.resolve(__dirname, 'package_extension.py');

function runPythonPackager() {
  const pyCommands = ['python', 'py', 'python3'];
  for (const cmd of pyCommands) {
    try {
      execSync(`${cmd} "${pyScript}"`, { stdio: 'inherit' });
      return true;
    } catch {
      // try next command
    }
  }
  return false;
}

function nativeNodePackager() {
  console.log('[package-extension] Using native Node.js packager fallback...');
  const manifestPath = path.join(distDir, 'manifest.json');
  if (!fs.existsSync(manifestPath)) {
    throw new Error(`manifest.json not found in ${distDir}`);
  }

  const zipFilename = 'AgentBreak-Sentinel-Chrome-Extension.zip';
  const targetZip = path.join(dashboardPublic, zipFilename);
  const distZip = path.join(distDir, zipFilename);

  if (!fs.existsSync(dashboardPublic)) {
    fs.mkdirSync(dashboardPublic, { recursive: true });
  }

  // Collect all files in distDir
  function collectFiles(dir) {
    let results = [];
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        results = results.concat(collectFiles(fullPath));
      } else {
        const ext = path.extname(entry.name).toLowerCase();
        if (
          ext !== '.zip' &&
          ext !== '.ts' &&
          ext !== '.map' &&
          entry.name !== '.DS_Store' &&
          entry.name !== 'Thumbs.db'
        ) {
          results.push(fullPath);
        }
      }
    }
    return results;
  }

  const files = collectFiles(distDir);
  const entries = [];
  let offset = 0;
  const localHeaders = [];

  for (const file of files) {
    const relPath = path.relative(distDir, file).replace(/\\/g, '/');
    const data = fs.readFileSync(file);
    const uncompressedSize = data.length;
    const crc = zlib.crc32(data);
    const compressed = zlib.deflateRawSync(data);
    const compressedSize = compressed.length;

    const nameBuffer = Buffer.from(relPath, 'utf8');
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0); // signature
    header.writeUInt16LE(20, 4); // version needed
    header.writeUInt16LE(0, 6); // bit flag
    header.writeUInt16LE(8, 8); // compression: deflate
    header.writeUInt16LE(0, 10); // mod time
    header.writeUInt16LE(0, 12); // mod date
    header.writeUInt32LE(crc, 14); // crc32
    header.writeUInt32LE(compressedSize, 18); // comp size
    header.writeUInt32LE(uncompressedSize, 22); // uncomp size
    header.writeUInt16LE(nameBuffer.length, 26); // name length
    header.writeUInt16LE(0, 28); // extra length

    const localChunk = Buffer.concat([header, nameBuffer, compressed]);
    localHeaders.push(localChunk);

    entries.push({
      name: relPath,
      nameBuffer,
      crc,
      compressedSize,
      uncompressedSize,
      offset,
    });

    offset += localChunk.length;
  }

  const centralDirBuffers = [];
  let centralDirSize = 0;

  for (const entry of entries) {
    const cHeader = Buffer.alloc(46);
    cHeader.writeUInt32LE(0x02014b50, 0); // signature
    cHeader.writeUInt16LE(20, 4); // version made by
    cHeader.writeUInt16LE(20, 6); // version needed
    cHeader.writeUInt16LE(0, 8); // bit flag
    cHeader.writeUInt16LE(8, 10); // compression: deflate
    cHeader.writeUInt16LE(0, 12); // mod time
    cHeader.writeUInt16LE(0, 14); // mod date
    cHeader.writeUInt32LE(entry.crc, 16); // crc32
    cHeader.writeUInt32LE(entry.compressedSize, 20); // comp size
    cHeader.writeUInt32LE(entry.uncompressedSize, 24); // uncomp size
    cHeader.writeUInt16LE(entry.nameBuffer.length, 28); // name length
    cHeader.writeUInt16LE(0, 30); // extra length
    cHeader.writeUInt16LE(0, 32); // comment length
    cHeader.writeUInt16LE(0, 34); // disk start
    cHeader.writeUInt16LE(0, 36); // internal attr
    cHeader.writeUInt32LE(0, 38); // external attr
    cHeader.writeUInt32LE(entry.offset, 42); // local header offset

    const cChunk = Buffer.concat([cHeader, entry.nameBuffer]);
    centralDirBuffers.push(cChunk);
    centralDirSize += cChunk.length;
  }

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); // signature
  eocd.writeUInt16LE(0, 4); // disk number
  eocd.writeUInt16LE(0, 6); // start disk
  eocd.writeUInt16LE(entries.length, 8); // entries on disk
  eocd.writeUInt16LE(entries.length, 10); // total entries
  eocd.writeUInt32LE(centralDirSize, 12); // cd size
  eocd.writeUInt32LE(offset, 16); // cd offset
  eocd.writeUInt16LE(0, 20); // comment length

  const finalZipBuffer = Buffer.concat([...localHeaders, ...centralDirBuffers, eocd]);
  fs.writeFileSync(targetZip, finalZipBuffer);
  fs.writeFileSync(distZip, finalZipBuffer);

  if (fs.existsSync(dashboardDist)) {
    fs.writeFileSync(path.join(dashboardDist, zipFilename), finalZipBuffer);
  }

  console.log(`[package-extension] Packaged ${entries.length} files to ${targetZip}`);
}

import { buildSync } from 'esbuild';

function bundleContentScript() {
  try {
    const contentTs = path.resolve(extDir, 'src', 'content.ts');
    const contentJs = path.resolve(distDir, 'content.js');
    if (fs.existsSync(contentTs)) {
      buildSync({
        entryPoints: [contentTs],
        bundle: true,
        format: 'iife',
        outfile: contentJs,
        minify: false,
        sourcemap: false,
      });
      console.log('[package-extension] Bundled standalone IIFE content.js');
    }
  } catch (err) {
    console.warn('[package-extension] Warning bundling content.js:', err.message);
  }
}

function main() {
  bundleContentScript();
  const success = runPythonPackager();
  if (!success) {
    nativeNodePackager();
  }
}

main();
