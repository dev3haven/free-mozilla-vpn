@echo off
chcp 65001 >nul
cd /d "%~dp0"
if %errorlevel% neq 0 (
    py mozvpn_no_externals.py --local-proxy --no-save
)
