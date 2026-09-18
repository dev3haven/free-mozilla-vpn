@echo off
chcp 65001 >nul
cd /d "%~dp0"
py mozvpn.py --use-sing-box --no-save
echo.
echo === Готово. Нажмите любую клавишу для выхода. ===
pause >nul
