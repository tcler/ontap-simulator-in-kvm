#!/bin/bash
#configure ontap simulator 9.7 as single cluster

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
getDefaultGateway() { ip route show | awk '$1=="default"{print $3}'; }

vncget() {
	local _vncaddr=$1
	[[ -z "$_vncaddr" ]] && return 1
	vncdo -s ${_vncaddr} capture _screen.png
	convert _screen.png  -threshold 30%  _screen2.png
	gocr -i _screen2.png 2>/dev/null
}
vncput() {
	local _vncaddr=$1
	[[ -z "$_vncaddr" ]] && return 1
	shift
	[[ $# -gt 0 ]] && vncdo -s ${_vncaddr} type "$*"
}
vncputln() {
	local _vncaddr=$1
	[[ -z "$_vncaddr" ]] && return 1
	shift
	[[ $# -gt 0 ]] && vncdo -s ${_vncaddr} type "$*"
	vncdo -s ${_vncaddr} key enter
}
vncputkey() {
	local _vncaddr=$1
	[[ -z "$_vncaddr" ]] && return 1
	shift
	[[ $# -gt 0 ]] && vncdo -s ${_vncaddr} key "$*"
}

ocrgrep() {
	local pattern=$1
	local ignored_charset=${2:-ifk}
	pattern=$(sed "s,[${ignored_charset}],.,g" <<<"${pattern}")
	grep -i "${pattern}"
}

##please change/cusotmize bellow default configration at first
cluster_name=fsqe-sn-01
password=fsqe2020

vmnode=ontap-single
node_managementif_port=e0c
node_managementif_addr=
node_managementif_mask=$(ipcalc -m $(getDefaultIp4)|sed 's/.*=//')
node_managementif_gateway=$(getDefaultGateway)
cluster_managementif_port=e0a
cluster_managementif_addr=192.168.10.11
cluster_managementif_mask=255.255.255.0
cluster_managementif_gateway=192.168.10.1
dns_domain=192.168.10.1
dns_addr=192.168.10.1
controller_located=raycom

:; echo -e "\n\033[1;30m================================================================================\033[0m"
:; echo -e "\033[1;30m=>" "creating network ...""\033[0m"
netin=ontap-single
vm netcreate netname=$netin brname=br-ontap subnet=10
vm net | grep -w $netin >/dev/null || vm netstart $netin

:; echo -e "\n\033[1;30m================================================================================\033[0m"
:; echo -e "\033[1;30m=>" "node vm start ...""\033[0m"
vm -n $vmnode ONTAP-simulator -i vsim-NetAppDOT-simulate-disk1.qcow2 \
	--disk=vsim-NetAppDOT-simulate-disk{2..4}.qcow2,bus=ide \
	--net=$netin,e1000  --net=$netin,e1000 --net-macvtap=-,e1000 --net-macvtap=-,e1000 \
	--noauto --force --nocloud --osv freebsd11.2 --bus=ide --msize $((6*1024)) --cpus 2

read vncaddr <<<"$(vm vnc $vmnode)"
vncaddr=${vncaddr/:/::}
[[ -z "$vncaddr" ]] && {
	echo "{WARN}: something is wrong, exit ..." >&2
	exit 1
}

:; echo -e "\n\033[1;36m=>" waiting: Hit [Enter] to boot immediately prompt ..."\033[0m"
while sleep 0.5; do vncget $vncaddr | ocrgrep "Hit .Enter. to boot immediately" && break; done
vncputln ${vncaddr}

:; echo -e "\n\033[1;36m=>" waiting: login prompt ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep ^login: && break; done
[[ -z "$node_managementif_addr" ]] &&
	node_managementif_addr=$(vncget $vncaddr | sed -nr '/^.*https:..([0-9.]+).*$/{s//\1/; p}')
vncputln ${vncaddr} "admin"
sleep 2
vncputln ${vncaddr} "reboot"

:; echo -e "\n\033[1;36m=>" waiting: reboot confirm prompt ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep "Are you sure you want to reboot node.*? {y|n}:" && break; done
vncputln ${vncaddr} "y"

:; echo -e "\n\033[1;36m=>" waiting: Hit [Enter] to boot immediately prompt ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep "Hit .Enter. to boot immediately" && break; done
vncputln ${vncaddr}

: <<'COMM'
:; echo -e "\n\033[1;36m=>" waiting: Boot Menu ask prompt ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep "Press Ctrl-C for Boot Menu." && break; done
vncputkey ${vncaddr} ctrl-c

:; echo -e "\n\033[1;36m=>" waiting: Boot Menu list ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep "Selection (1-9)?" && break; done
vncputln ${vncaddr} "4"

:; echo -e "\n\033[1;36m=>" waiting: Zero disks, reset config and install a new file system? prompt ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep "Zero disks, reset config and install a new file system?" && break; done
vncputln ${vncaddr} "yes"

:; echo -e "\n\033[1;36m=>" waiting: This will erase all the data on the disks, are you sure? prompt ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep "This will erase all the data on the disks, are you sure?" && break; done
vncputln ${vncaddr} "yes"

:; echo -e "\n\033[1;36m=>" waiting: Hit [Enter] to boot immediately prompt ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep "Hit .Enter. to boot immediately" && break; done
vncputln ${vncaddr}
COMM

:; echo -e "\n\033[1;36m=>" waiting: '"Type yes to confirm and continue {yes}:" ...'"\033[0m"
while sleep 10; do vncget $vncaddr | ocrgrep "Type yes to confirm and continue {yes}:" && break; done
vncputln ${vncaddr} "yes"

:; echo -e "\n\033[1;36m=>" waiting: node management interface port prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the node management interface port" && break; done
vncputln ${vncaddr} "${node_managementif_port}"

:; echo -e "\n\033[1;36m=>" waiting: node management interface ip address prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the node management interface .. address" && break; done
vncputln ${vncaddr} "$node_managementif_addr"

:; echo -e "\n\033[1;36m=>" waiting: node management interface ip netmask prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the node management interface netmask" && break; done
vncputln ${vncaddr} "$node_managementif_mask"

:; echo -e "\n\033[1;36m=>" waiting: node management interface gateway prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the node management interface default gateway" && break; done
vncputln ${vncaddr} "$node_managementif_gateway"

:; echo -e "\n\033[1;36m=>" waiting: cluster setup prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "cluster setup using the command line" && break; done
vncputln ${vncaddr}

:; echo -e "\n\033[1;36m=>" waiting: create a new cluster or join an existing cluster? prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "create a new cluster or join an" && break; done
vncputln ${vncaddr} "create"

:; echo -e "\n\033[1;36m=>" waiting: as a single node cluster? prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "used as a single node cluster?" && break; done
vncputln ${vncaddr} "yes"

:; echo -e "\n\033[1;36m=>" waiting: 'administrators(username "admin") password prompt ...'"\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "administrator.* password:" && break; done
vncputln ${vncaddr} "$password"

:; echo -e "\n\033[1;36m=>" waiting: password retype prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Retype the password:" && break; done
vncputln ${vncaddr} "$password"

:; echo -e "\n\033[1;36m=>" waiting: cluster name ask prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the cluster name:" && break; done
vncputln ${vncaddr} "$cluster_name"

:; echo -e "\n\033[1;36m=>" waiting: license key prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter an additional license key" && break; done
vncputln ${vncaddr}

:; echo -e "\n\033[1;36m=>" waiting: cluster management interface port prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the cluster management interface port" && break; done
vncputln ${vncaddr} "${cluster_managementif_port}"

:; echo -e "\n\033[1;36m=>" waiting: cluster management interface ip address prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the cluster management interface .. address" && break; done
vncputln ${vncaddr} "$cluster_managementif_addr"

:; echo -e "\n\033[1;36m=>" waiting: cluster management interface ip netmask prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the cluster management interface netmask" && break; done
vncputln ${vncaddr} "$cluster_managementif_mask"

:; echo -e "\n\033[1;36m=>" waiting: cluster management interface gateway prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the cluster management interface default gateway" && break; done
vncputln ${vncaddr} "$cluster_managementif_gateway"

:; echo -e "\n\033[1;36m=>" waiting: DNS domain names ask prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the DNS domain names" && break; done
vncputln ${vncaddr} "$dns_domain"

:; echo -e "\n\033[1;36m=>" waiting: name server IP addresses ask prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the name server .. addresses" && break; done
vncputln ${vncaddr} "$dns_addr"

:; echo -e "\n\033[1;36m=>" waiting: where is the controller located prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "controller located" && break; done
vncputln ${vncaddr} "$controller_located"

:; echo -e "\n\033[1;36m=>" waiting: backup destination address prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "backup destination address" && break; done
vncputln ${vncaddr}
sleep 2

:; echo -e "\n\033[1;36m------------------------------------------------------\033[0m"
vncget $vncaddr | GREP_COLORS='ms=01;36' grep --color .
:; echo -e "\n\033[1;36m------------------------------------------------------\033[0m"

:; echo -e "\n\033[1;36m=>" "now ssh(admin@$node_managementif_addr and admin@$cluster_managementif_addr) is available,\n please complete other configurations in ssh session ...""\033[0m"