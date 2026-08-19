@echo off
title AI Security Agent SaaS
echo ==========================================================
echo    Launching AI Security Agent SaaS (Multi-Container)
echo ==========================================================
echo.
echo Building and starting all microservices...
echo - PostgreSQL Database
echo - Rust AST Scanner
echo - Python AI Engine (Gemini)
echo - Next.js Web Dashboard
echo.

docker-compose up --build

echo.
echo Containers have stopped.
pause
