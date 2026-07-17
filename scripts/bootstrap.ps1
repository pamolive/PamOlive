$ErrorActionPreference = "Stop"

& powershell -ExecutionPolicy Bypass -File .\install.ps1
if ($env:PAMOLIVE_BOOTSTRAP_PREPARE_ONLY -eq "true") {
    Write-Host "PAM-olive environment prepared without starting Docker."
    exit 0
}
docker compose up --build -d
Write-Host "PAM-olive is starting at http://localhost:8000"
Write-Host "PAM-olive RDP is starting at http://localhost:8081"
