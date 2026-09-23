@echo off
chcp 65001 >nul
cd /d "%~dp0"
py mozvpn_beta.py
echo.
echo === Готово. Нажмите любую клавишу для выхода. ===
pause >nul
