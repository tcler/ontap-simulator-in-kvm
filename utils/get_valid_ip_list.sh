#!/bin/bash

IPCALC=ipcalc; command -v ipcalc-ng &>/dev/null && { IPCALC=ipcalc-ng; }
command -v $IPCALC >/dev/null && command -v nmap >/dev/null || { echo "[WARN] command $IPCALC and nmap is required!" >&2; exit 127; }

IFS=/ read ip netmasklen < <(get-default-ip.sh -m)
netaddr=$(get-net-addr.sh $ip/$netmasklen)
scan_result=$(nmap -PA22,80,113,443 -sn -nv $netaddr/$netmasklen 2>/dev/null)

#echo "$scan_result"
if test -z "$1"; then
	echo "$scan_result" | awk '/host.down/{print $5}'
else
	echo "$scan_result"
fi
