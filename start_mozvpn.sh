#!/bin/bash
cd "$(dirname "$(readlink -f "$0")")" || exit 1

python -u mozvpn.py --use-sing-box --no-save

echo
read -n 1 -s -r -p "=== Готово. Нажмите любую клавишу для выхода. ==="
echo
