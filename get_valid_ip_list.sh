#!/bin/bash

getIp4() {
	local ret
	local nic=$1
	local ipaddr=`ip addr show $nic`;
	ret=$(echo "$ipaddr" |
		awk '/inet .* dynamic/{match($0,"inet ([0-9.]+/[0-9]+)",M); print M[1]}');

	echo "$ret"
	[ -z "$ret" ] && return 1 || return 0
}
getDefaultNic() { ip route | awk '/default/{match($0,"dev ([^ ]+)",M); print M[1]; exit}'; }
getDefaultIp4() {
	local nic=$(getDefaultNic)
	[ -z "$nic" ] && return 1
	getIp4 "$nic"
}

IFS=/ read ip netmasklen < <(getDefaultIp4)
IFS== read key netaddr < <(ipcalc -n $ip/$netmasklen)
which nmap &>/dev/null || yum install -y nmap >/dev/null
scan_result=$(nmap -v -n -sn $netaddr/$netmasklen 2>/dev/null)

#echo "$scan_result"
echo "$scan_result" | awk '/host.down/{print $5}'
