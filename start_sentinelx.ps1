Write-Host "==========================================================================" -ForegroundColor Magenta
Write-Host "                   WEBSENTINEL AI CYBER DEFENSE PLATFORM                  " -ForegroundColor Cyan
Write-Host "              AI-Powered Web Threat Detection & Intelligence              " -ForegroundColor White
Write-Host "                  Detect. Investigate. Understand. Verify.                " -ForegroundColor Yellow
Write-Host "==========================================================================" -ForegroundColor Magenta

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "[*] Launching Backend Server on http://127.0.0.1:8000..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$scriptDir\backend'; python run_backend.py"

Start-Sleep -Seconds 2

Write-Host "[*] Launching Frontend Server on http://localhost:5173..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$scriptDir\frontend'; npm run dev"

Write-Host ""
Write-Host "[✓] Both services are running in their dedicated terminals!" -ForegroundColor Green
Write-Host "    Frontend Dashboard : http://localhost:5173" -ForegroundColor White
Write-Host "    Backend API Docs   : http://127.0.0.1:8000/docs" -ForegroundColor White

