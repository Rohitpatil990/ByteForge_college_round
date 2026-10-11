#!/usr/bin/env python3
"""
AgentBreak Sentinel Chrome Extension Packager
Packages the compiled extension from extension/dist into AgentBreak-Sentinel-Chrome-Extension.zip
Ensures manifest.json is at the root of the archive for Chrome's "Load unpacked" compatibility.
"""

import hashlib
import os
import shutil
import sys
import zipfile
from pathlib import Path

def package_sentinel_extension() -> Path:
    script_dir = Path(__file__).resolve().parent
    ext_dir = script_dir.parent
    dist_dir = ext_dir / "dist"
    repo_root = ext_dir.parent
    dashboard_public = repo_root / "dashboard" / "public"
    dashboard_dist = repo_root / "dashboard" / "dist"

    zip_filename = "AgentBreak-Sentinel-Chrome-Extension.zip"
    target_zip = dashboard_public / zip_filename
    dist_zip = dist_dir / zip_filename

    manifest_file = dist_dir / "manifest.json"
    if not manifest_file.is_file():
        raise FileNotFoundError(
            f"Extension manifest not found at {manifest_file}. "
            "Please run 'npm run build' in the extension directory first."
        )

    # Ensure output directories exist
    dashboard_public.mkdir(parents=True, exist_ok=True)
    temp_zip = dist_dir / f"temp_{zip_filename}"

    # Collect files to package
    packaged_files = []
    excluded_extensions = {".zip", ".ts", ".map", ".tmp"}
    excluded_names = {".DS_Store", "Thumbs.db", ".git", ".env"}

    with zipfile.ZipFile(temp_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for root, dirs, files in os.walk(dist_dir):
            # Sort for deterministic archive layout
            dirs.sort()
            files.sort()
            for filename in files:
                if filename in excluded_names:
                    continue
                file_ext = Path(filename).suffix.lower()
                if file_ext in excluded_extensions:
                    continue
                
                full_path = Path(root) / filename
                if full_path == temp_zip or full_path == dist_zip or full_path == target_zip:
                    continue

                rel_path = full_path.relative_to(dist_dir)
                arcname = str(rel_path).replace(os.sep, "/")

                # Record file
                zf.write(full_path, arcname)
                packaged_files.append(arcname)

    # Verify integrity and structure of archive
    with zipfile.ZipFile(temp_zip, "r") as zf:
        corrupt = zf.testzip()
        if corrupt:
            raise RuntimeError(f"ZIP archive corrupted: {corrupt}")
        
        namelist = zf.namelist()
        if "manifest.json" not in namelist:
            raise RuntimeError("CRITICAL: manifest.json is missing from ZIP root!")

    # Atomically replace destination files
    if dist_zip.exists():
        dist_zip.unlink()
    shutil.copy2(temp_zip, dist_zip)

    if target_zip.exists():
        target_zip.unlink()
    shutil.move(str(temp_zip), str(target_zip))

    # Also sync demo_chat.html and content.js for standalone test harness access
    content_js = dist_dir / "content.js"
    demo_html = dist_dir / "demo_chat.html"
    for dest in [dashboard_public, dashboard_dist]:
        if dest.is_dir():
            if content_js.is_file():
                shutil.copy2(content_js, dest / "content.js")
            if demo_html.is_file():
                shutil.copy2(demo_html, dest / "demo_chat.html")

    # Also copy to dashboard/dist if it exists
    if dashboard_dist.is_dir():
        dashboard_dist_zip = dashboard_dist / zip_filename
        if dashboard_dist_zip.exists():
            dashboard_dist_zip.unlink()
        shutil.copy2(target_zip, dashboard_dist_zip)

    # Compute checksum and file size
    file_size = target_zip.stat().st_size
    sha256 = hashlib.sha256(target_zip.read_bytes()).hexdigest()

    print("============================================================")
    print(" AgentBreak Sentinel Extension Packaged Successfully")
    print("============================================================")
    print(f"Archive:       {target_zip.name}")
    print(f"Location:      {target_zip}")
    print(f"File Size:     {file_size:,} bytes ({file_size / 1024:.2f} KB)")
    print(f"SHA-256:       {sha256}")
    print(f"Total Files:   {len(packaged_files)}")
    print("Packaged Assets (manifest.json at root):")
    for f in sorted(packaged_files):
        print(f"  - {f}")
    print("============================================================")

    return target_zip


if __name__ == "__main__":
    try:
        package_sentinel_extension()
    except Exception as exc:
        print(f"ERROR: Failed to package Sentinel extension: {exc}", file=sys.stderr)
        sys.exit(1)
