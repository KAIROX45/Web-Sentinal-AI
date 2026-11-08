@echo off
title WebSentinel AI Cyber Threat Intelligence Platform
echo ==========================================================================
echo                    WEBSENTINEL AI CYBER DEFENSE PLATFORM
echo               AI-Powered Web Threat Detection & Intelligence
echo                   Detect. Investigate. Understand. Verify.
echo ==========================================================================
echo Starting Backend and Frontend servers...

start "WebSentinel AI Backend (FastAPI :8000)" cmd /k "cd /d %~dp0backend && python run_backend.py"
start "WebSentinel AI Frontend (Vite :5173)" cmd /k "cd /d %~dp0frontend && npm run dev"

echo ==========================================================================
echo Both servers are launching in separate windows!
echo   Frontend UI : http://localhost:5173
echo   Backend API : http://127.0.0.1:8000
echo   API Docs    : http://127.0.0.1:8000/docs
echo ==========================================================================
pause

