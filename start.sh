#!/bin/bash
cd "$(dirname "$(readlink -f "$0")")" || exit 1
python3 mozvpn_no_externals.py --local-proxy --no-save
