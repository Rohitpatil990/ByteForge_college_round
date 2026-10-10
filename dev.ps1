# AgentBreak Unified Development Boot Script for Windows PowerShell
# Starts both FastAPI Backend (port 8000) and React/Vite Dashboard (port 5173)
$ErrorActionPreference = "Stop"

$ProjectRoot = $PSScriptRoot
Set-Location -Path $ProjectRoot

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "       AgentBreak - Unified Platform Bootstrapper" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "[+] Project Root: $ProjectRoot"

# ---------------------------------------------------------------------------
# 1. Environment & Runtime Checks
# ---------------------------------------------------------------------------

# Check Python
$SystemPython = Get-Command python -ErrorAction SilentlyContinue
if (-not $SystemPython) {
    Write-Error "ERROR: 'python' was not found on PATH. Please install Python 3.10+ and add it to PATH."
    exit 1
}
$PythonVersion = & python --version 2>&1
Write-Host "[+] Detected Python: $PythonVersion"

# Check Node.js and npm
$SystemNode = Get-Command node -ErrorAction SilentlyContinue
$SystemNpm = Get-Command npm -ErrorAction SilentlyContinue
if (-not $SystemNode -or -not $SystemNpm) {
    Write-Error "ERROR: 'node' or 'npm' was not found on PATH. Please install Node.js 18+ to run the dashboard."
    exit 1
}
$NodeVersion = & node --version 2>&1
$NpmVersion = & npm --version 2>&1
Write-Host "[+] Detected Node.js: $NodeVersion (npm: $NpmVersion)"

# ---------------------------------------------------------------------------
# 2. Python Virtual Environment & Dependencies
# ---------------------------------------------------------------------------
$VenvDir = Join-Path $ProjectRoot ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host "[+] Creating virtual environment at .venv..." -ForegroundColor Yellow
    & python -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Error "ERROR: Failed to create virtual environment."
        exit 1
    }
    Write-Host "[+] Virtual environment created." -ForegroundColor Green
} else {
    Write-Host "[+] Virtual environment verified at .venv"
}

$ReqFile = Join-Path $ProjectRoot "requirements.txt"
if (Test-Path $ReqFile) {
    Write-Host "[+] Verifying Python dependencies..." -ForegroundColor Yellow
    & $VenvPython -m pip install -q -r $ReqFile
}

# ---------------------------------------------------------------------------
# 3. Dashboard Dependencies Setup
# ---------------------------------------------------------------------------
$DashboardDir = Join-Path $ProjectRoot "dashboard"
$NodeModulesDir = Join-Path $DashboardDir "node_modules"

if (-not (Test-Path $NodeModulesDir)) {
    Write-Host "[+] Installing dashboard npm dependencies..." -ForegroundColor Yellow
    Push-Location $DashboardDir
    & npm install
    Pop-Location
} else {
    Write-Host "[+] Dashboard dependencies verified in dashboard/node_modules"
}

# ---------------------------------------------------------------------------
# 4. Start Servers (FastAPI Backend + Vite Dashboard)
# ---------------------------------------------------------------------------
$BackendUrl = "http://127.0.0.1:8000"
$FrontendUrl = "http://127.0.0.1:5173"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  AgentBreak Platform Starting" -ForegroundColor Green
Write-Host "  Backend API:    $BackendUrl" -ForegroundColor Green
Write-Host "  Swagger Docs:   ${BackendUrl}/docs" -ForegroundColor Green
Write-Host "  Target Configs: ${BackendUrl}/target/configs" -ForegroundColor Green
Write-Host "  Web Dashboard:  $FrontendUrl" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Fallback separate commands:" -ForegroundColor Gray
Write-Host "  Backend:  python -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload" -ForegroundColor Gray
Write-Host "  Frontend: cd dashboard; npm run dev" -ForegroundColor Gray
Write-Host ""
Write-Host "Press Ctrl+C to terminate both servers." -ForegroundColor Yellow
Write-Host ""

$BackendProcess = $null
$FrontendProcess = $null

try {
    # Launch Backend
    $BackendProcess = Start-Process -FilePath $VenvPython `
        -ArgumentList "-m uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload" `
        -WorkingDirectory $ProjectRoot `
        -PassThru

    # Launch Frontend
    $NpmCmd = (Get-Command npm.cmd -ErrorAction SilentlyContinue).Source
    if (-not $NpmCmd) { $NpmCmd = "npm" }

    $FrontendProcess = Start-Process -FilePath $NpmCmd `
        -ArgumentList "run dev" `
        -WorkingDirectory $DashboardDir `
        -PassThru

    # Monitor and wait
    while ($true) {
        Start-Sleep -Seconds 1
        if ($BackendProcess.HasExited) {
            Write-Warning "Backend process stopped unexpectedly."
            break
        }
        if ($FrontendProcess.HasExited) {
            Write-Warning "Frontend process stopped unexpectedly."
            break
        }
    }
}
finally {
    Write-Host "`nStopping AgentBreak processes..." -ForegroundColor Yellow
    if ($BackendProcess -and -not $BackendProcess.HasExited) {
        Stop-Process -Id $BackendProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($FrontendProcess -and -not $FrontendProcess.HasExited) {
        Stop-Process -Id $FrontendProcess.Id -Force -ErrorAction SilentlyContinue
    }
    Write-Host "All processes cleanly stopped." -ForegroundColor Green
}
