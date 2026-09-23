#!/bin/bash
cd "$(dirname "$(readlink -f "$0")")" || exit 1

python -u mozvpn_beta.py

echo
read -n 1 -s -r -p "=== Готово. Нажмите любую клавишу для выхода. ==="
echo
