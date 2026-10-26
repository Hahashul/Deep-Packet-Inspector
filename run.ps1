# Windows launcher: run from an Administrator PowerShell in the project folder.
$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script from an Administrator PowerShell (capture, RST injection and firewall rules need it)."
}
if (-not (Test-Path venv)) { python -m venv venv }
& .\venv\Scripts\Activate.ps1
pip install -q -r requirements.txt
Write-Host "Starting on http://127.0.0.1:8000  (localhost only; token is generated per run)"
uvicorn server:app --host 127.0.0.1 --port 8000
