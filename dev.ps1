# AgentBreak Development Boot Script for Windows PowerShell
$ErrorActionPreference = "Stop"

# 1. Resolve project root from script location
$ProjectRoot = $PSScriptRoot
Set-Location -Path $ProjectRoot

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "  AgentBreak - Local Development Environment" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "[+] Project Root: $ProjectRoot"

# 2. Check Python availability
$SystemPython = Get-Command python -ErrorAction SilentlyContinue
if (-not $SystemPython) {
    Write-Error "ERROR: 'python' was not found on PATH. Please install Python 3.10+ and add it to PATH."
    exit 1
}

$PythonVersion = & python --version 2>&1
Write-Host "[+] Detected Python: $PythonVersion"

# 3. Virtual environment setup
$VenvDir = Join-Path $ProjectRoot ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host "[+] Creating virtual environment at .venv..." -ForegroundColor Yellow
    & python -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Error "ERROR: Failed to create virtual environment."
        exit 1
    }
    Write-Host "[+] Virtual environment created successfully." -ForegroundColor Green
} else {
    Write-Host "[+] Using existing virtual environment at .venv"
}

# 4. Install requirements.txt
$ReqFile = Join-Path $ProjectRoot "requirements.txt"
if (Test-Path $ReqFile) {
    Write-Host "[+] Verifying dependencies from requirements.txt..." -ForegroundColor Yellow
    & $VenvPython -m pip install -r $ReqFile
    if ($LASTEXITCODE -ne 0) {
        Write-Error "ERROR: Failed to install dependencies from requirements.txt."
        exit 1
    }
}

# 5. Start FastAPI development server using Uvicorn
$HostAddress = "127.0.0.1"
$Port = 8000
$ServerUrl = "http://${HostAddress}:${Port}"

Write-Host ""
Write-Host "=================================================" -ForegroundColor Green
Write-Host "  AgentBreak API Server Starting" -ForegroundColor Green
Write-Host "  Local URL:    $ServerUrl" -ForegroundColor Green
Write-Host "  Swagger Docs: ${ServerUrl}/docs" -ForegroundColor Green
Write-Host "  Health Check: ${ServerUrl}/health" -ForegroundColor Green
Write-Host "  Configs:      ${ServerUrl}/target/configs" -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Green
Write-Host ""

& $VenvPython -m uvicorn api.main:app --host $HostAddress --port $Port --reload
