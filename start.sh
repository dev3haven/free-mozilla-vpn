#!/bin/bash
cd "$(dirname "$(readlink -f "$0")")" || exit 1

py -u mozvpn_no_externals.py --local-proxy --no-save

echo
read -n 1 -s -r -p "=== Готово. Нажмите любую клавишу для выхода. ==="
echo
