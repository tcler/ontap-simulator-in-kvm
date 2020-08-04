#!/bin/bash
#install and configure two inode cluster with ontap simulator 9.7

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

:; echo -e "\n\033[1;30m================================================================================\033[0m"
:; echo -e "\033[1;30m=>" "creating networks ...""\033[0m"
netcluster=ontap2-cluster
vm netcreate netname=$netcluster brname=br-ontap2 subnet=20
vm net | grep -w $netcluster >/dev/null || vm netstart $netcluster

netdata=ontap2-data
vm netcreate netname=$netdata brname=br-ontap2-data subnet=21
vm net | grep -w $netdata >/dev/null || vm netstart $netdata

netha=ontap2-ha
vm netcreate netname=$netha brname=br-ontap2-ha forward=
vm net | grep -w $netha >/dev/null || vm netstart $netha


#===============================================================================
#cluster
cluster_name=fsqe-2n-01
password=fsqe2020

#===============================================================================
#node1
vmnode1=ontap-node1
node1_managementif_port=e0c
node1_managementif_addr=
node1_managementif_mask=$(ipcalc -m $(getDefaultIp4)|sed 's/.*=//')
node1_managementif_gateway=$(getDefaultGateway)
cluster_managementif_port=e0d
cluster_managementif_addr=192.168.21.11
cluster_managementif_mask=255.255.255.0
cluster_managementif_gateway=192.168.21.1
dns_domain=192.168.21.1
dns_addr=192.168.21.1
controller_located=raycom

:; echo -e "\n\033[1;30m================================================================================\033[0m"
:; echo -e "\033[1;30m=>" "[node1] start ...""\033[0m"
vm -n $vmnode1 ONTAP-simulator -i vsim-NetAppDOT-simulate-disk1.qcow2 \
	--disk=vsim-NetAppDOT-simulate-disk{2..4}.qcow2,bus=ide \
	--net=$netcluster,e1000 --net=$netcluster,e1000 --net-macvtap=-,e1000 --net=$netdata,e1000 --net=$netha,e1000 \
	--noauto --force --nocloud --osv freebsd11.2 --bus=ide --msize $((6*1024)) --cpus 2

read vncaddr <<<"$(vm vnc $vmnode1)"
vncaddr=${vncaddr/:/::}
[[ -z "$vncaddr" ]] && {
	echo "{WARN}: something is wrong, exit ..." >&2
	exit 1
}

:; echo -e "\n\033[1;36m=> [node1]" waiting: Hit [Enter] to boot immediately prompt ..."\033[0m"
while sleep 0.5; do vncget $vncaddr | ocrgrep "Hit .Enter. to boot immediately" && break; done
vncputln ${vncaddr}

:; echo -e "\n\033[1;36m=> [node1]" waiting: login prompt ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep ^login: && break; done
[[ -z "$node1_managementif_addr" ]] &&
	node1_managementif_addr=$(vncget $vncaddr | sed -nr '/^.*https:..([0-9.]+).*$/{s//\1/; p}')
vncputln ${vncaddr} "admin"
sleep 2
vncputln ${vncaddr} "reboot"

:; echo -e "\n\033[1;36m=> [node1]" waiting: reboot confirm prompt ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep "Are you sure you want to reboot node.*? {y|n}:" && break; done
vncputln ${vncaddr} "y"

:; echo -e "\n\033[1;36m=> [node1]" waiting: Hit [Enter] to boot immediately prompt ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep "Hit .Enter. to boot immediately" && break; done
vncputln ${vncaddr}

: <<'COMM'
:; echo -e "\n\033[1;36m=> [node1]" waiting: Boot Menu ask prompt ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep "Press Ctrl-C for Boot Menu." && break; done
vncputkey ${vncaddr} ctrl-c

:; echo -e "\n\033[1;36m=> [node1]" waiting: Boot Menu list ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep "Selection (1-9)?" && break; done
vncputln ${vncaddr} "4"

:; echo -e "\n\033[1;36m=> [node1]" waiting: Zero disks, reset config and install a new file system? prompt ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep "Zero disks, reset config and install a new file system?" && break; done
vncputln ${vncaddr} "yes"

:; echo -e "\n\033[1;36m=> [node1]" waiting: This will erase all the data on the disks, are you sure? prompt ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep "This will erase all the data on the disks, are you sure?" && break; done
vncputln ${vncaddr} "yes"

:; echo -e "\n\033[1;36m=> [node1]" waiting: Hit [Enter] to boot immediately prompt ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep "Hit .Enter. to boot immediately" && break; done
vncputln ${vncaddr}
COMM

:; echo -e "\n\033[1;36m=> [node1]" waiting: '"Type yes to confirm and continue {yes}:" ...'"\033[0m"
while sleep 10; do vncget $vncaddr | ocrgrep "Type yes to confirm and continue {yes}:" && break; done
vncputln ${vncaddr} "yes"

:; echo -e "\n\033[1;36m=> [node1]" waiting: node management interface port prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the node management interface port" && break; done
vncputln ${vncaddr} "${node1_managementif_port}"

:; echo -e "\n\033[1;36m=> [node1]" waiting: node management interface ip address prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the node management interface .. address" && break; done
vncputln ${vncaddr} "$node1_managementif_addr"

:; echo -e "\n\033[1;36m=> [node1]" waiting: node management interface ip netmask prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the node management interface netmask" && break; done
vncputln ${vncaddr} "$node1_managementif_mask"

:; echo -e "\n\033[1;36m=> [node1]" waiting: node management interface gateway prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the node management interface default gateway" && break; done
vncputln ${vncaddr} "$node1_managementif_gateway"

:; echo -e "\n\033[1;36m=> [node1]" waiting: cluster setup prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "cluster setup using the command line" && break; done
vncputln ${vncaddr}

:; echo -e "\n\033[1;36m=> [node1]" waiting: create a new cluster or join an existing cluster? prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "create a new cluster or join an" && break; done
vncputln ${vncaddr} "create"

:; echo -e "\n\033[1;36m=> [node1]" waiting: as a single node cluster? prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "used as a single node cluster?" && break; done
vncputln ${vncaddr} "no"


:; echo -e "\n\033[1;36m=> [node1]" waiting: Do you want to use this configuration? ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Do you want to use this configuration?" && break; done
node1_private_ips=$(vncget $vncaddr|sed -nr '/^.*(169.254.[0-9]+.[0-9]+).*$/{s//\1/; p}')
vncputln ${vncaddr} "yes"

:; echo -e "\n\033[1;36m=> [node1]" waiting: 'administrators(username "admin") password prompt ...'"\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "administrator.* password:" && break; done
vncputln ${vncaddr} "$password"

:; echo -e "\n\033[1;36m=> [node1]" waiting: password retype prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Retype the password:" && break; done
vncputln ${vncaddr} "$password"

:; echo -e "\n\033[1;36m=> [node1]" waiting: cluster name ask prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the cluster name:" && break; done
vncputln ${vncaddr} "$cluster_name"

:; echo -e "\n\033[1;36m=> [node1]" waiting: license key prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter an additional license key" && break; done
vncputln ${vncaddr}

:; echo -e "\n\033[1;36m=> [node1]" waiting: cluster management interface port prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the cluster management interface port" && break; done
vncputln ${vncaddr} "${cluster_managementif_port}"

:; echo -e "\n\033[1;36m=> [node1]" waiting: cluster management interface ip address prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the cluster management interface .. address" && break; done
vncputln ${vncaddr} "$cluster_managementif_addr"

:; echo -e "\n\033[1;36m=> [node1]" waiting: cluster management interface ip netmask prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the cluster management interface netmask" && break; done
vncputln ${vncaddr} "$cluster_managementif_mask"

:; echo -e "\n\033[1;36m=> [node1]" waiting: cluster management interface gateway prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the cluster management interface default gateway" && break; done
vncputln ${vncaddr} "$cluster_managementif_gateway"

:; echo -e "\n\033[1;36m=> [node1]" waiting: DNS domain names ask prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the DNS domain names" && break; done
vncputln ${vncaddr} "$dns_domain"

:; echo -e "\n\033[1;36m=> [node1]" waiting: name server IP addresses ask prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the name server .. addresses" && break; done
vncputln ${vncaddr} "$dns_addr"

:; echo -e "\n\033[1;36m=> [node1]" waiting: where is the controller located prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "controller located" && break; done
vncputln ${vncaddr} "$controller_located"
sleep 2

:; echo -e "\n\033[1;36m--------------------------------------------------------------------------------\033[0m"
vncget $vncaddr | GREP_COLORS='ms=01;36' grep --color .
:; echo -e "\n\033[1;36m--------------------------------------------------------------------------------\033[0m"

:; echo -e "\n\033[1;36m=>" "now ssh(admin@$node1_managementif_addr and admin@$cluster_managementif_addr) is available,\n please complete other configurations in ssh session ...""\033[0m"

#===============================================================================
#node2
vmnode2=ontap-node2
node2_managementif_port=e0c
node2_managementif_addr=
node2_managementif_mask=$(ipcalc -m $(getDefaultIp4)|sed 's/.*=//')
node2_managementif_gateway=$(getDefaultGateway)

:; echo -e "\n\033[1;30m================================================================================\033[0m"
:; echo -e "\033[1;30m=>" "[node2] start ...""\033[0m"
vm -n $vmnode2 ONTAP-simulator -i vsim-NetAppDOT-simulate-disk1.qcow2 \
	--disk=vsim-NetAppDOT-simulate-disk{2..4}.qcow2,bus=ide \
	--net=$netcluster,e1000 --net=$netcluster,e1000 --net-macvtap=-,e1000 --net=$netdata,e1000 --net=$netha,e1000 \
	--noauto --force --nocloud --osv freebsd11.2 --bus=ide --msize $((6*1024)) --cpus 2

read vncaddr <<<"$(vm vnc $vmnode2)"
vncaddr=${vncaddr/:/::}
[[ -z "$vncaddr" ]] && {
	echo "{WARN}: something is wrong, exit ..." >&2
	exit 1
}

:; echo -e "\n\033[1;36m=> [node2]" waiting: Hit [Enter] to boot immediately prompt ..."\033[0m"
while sleep 0.5; do vncget $vncaddr | ocrgrep "Hit .Enter. to boot immediately" && break; done
vncput ${vncaddr} " "
while sleep 0.5; do vncget $vncaddr | ocrgrep "VLOADER>" && break; done
vncputln ${vncaddr} "setenv SYS_SERIAL_NUM 4034389-06-2"
sleep 1
vncputln ${vncaddr} "setenv bootarg.nvram.sysid 4034389062"
sleep 1
vncputln ${vncaddr} "printenv SYS_SERIAL_NUM"
sleep 1
vncputln ${vncaddr} "printenv bootarg.nvram.sysid"
sleep 1
vncputln ${vncaddr} "boot"

:; echo -e "\n\033[1;36m=> [node2]" waiting: login prompt ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep ^login: && break; done
[[ -z "$node2_managementif_addr" ]] &&
	node2_managementif_addr=$(vncget $vncaddr | sed -nr '/^.*https:..([0-9.]+).*$/{s//\1/; p}')
vncputln ${vncaddr} "admin"
sleep 2
vncputln ${vncaddr} "reboot"

:; echo -e "\n\033[1;36m=> [node2]" waiting: reboot confirm prompt ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep "Are you sure you want to reboot node.*? {y|n}:" && break; done
vncputln ${vncaddr} "y"

:; echo -e "\n\033[1;36m=> [node2]" waiting: Hit [Enter] to boot immediately prompt ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep "Hit .Enter. to boot immediately" && break; done
vncdo -s ${vncaddr} key enter

: <<'COMM'
:; echo -e "\n\033[1;36m=> [node2]" waiting: Boot Menu ask prompt ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep "Press Ctrl-C for Boot Menu." && break; done
vncputkey ${vncaddr} ctrl-c

:; echo -e "\n\033[1;36m=> [node2]" waiting: Boot Menu list ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep "Selection (1-9)?" && break; done
vncputln ${vncaddr} "4"

:; echo -e "\n\033[1;36m=> [node2]" waiting: Zero disks, reset config and install a new file system? prompt ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep "Zero disks, reset config and install a new file system?" && break; done
vncputln ${vncaddr} "yes"

:; echo -e "\n\033[1;36m=> [node2]" waiting: This will erase all the data on the disks, are you sure? prompt ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep "This will erase all the data on the disks, are you sure?" && break; done
vncputln ${vncaddr} "yes"

:; echo -e "\n\033[1;36m=> [node2]" waiting: Hit [Enter] to boot immediately prompt ..."\033[0m"
while sleep 5; do vncget $vncaddr | ocrgrep "Hit .Enter. to boot immediately" && break; done
vncputln ${vncaddr}
COMM

:; echo -e "\n\033[1;36m=> [node2]" waiting: '"Type yes to confirm and continue {yes}:" ...'"\033[0m"
while sleep 10; do vncget $vncaddr | ocrgrep "Type yes to confirm and continue {yes}:" && break; done
vncputln ${vncaddr} "yes"

:; echo -e "\n\033[1;36m=> [node2]" waiting: node management interface port prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the node management interface port" && break; done
vncputln ${vncaddr} "${node2_managementif_port}"

:; echo -e "\n\033[1;36m=> [node2]" waiting: node management interface ip address prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the node management interface .. address" && break; done
vncputln ${vncaddr} "$node2_managementif_addr"

:; echo -e "\n\033[1;36m=> [node2]" waiting: node management interface ip netmask prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the node management interface netmask" && break; done
vncputln ${vncaddr} "$node2_managementif_mask"

:; echo -e "\n\033[1;36m=> [node2]" waiting: node management interface gateway prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Enter the node management interface default gateway" && break; done
vncputln ${vncaddr} "$node2_managementif_gateway"

:; echo -e "\n\033[1;36m=> [node2]" waiting: cluster setup prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "cluster setup using the command line" && break; done
vncputln ${vncaddr}

:; echo -e "\n\033[1;36m=> [node2]" waiting: create a new cluster or join an existing cluster? prompt ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "create a new cluster or join an" && break; done
vncputln ${vncaddr} "join"

:; echo -e "\n\033[1;36m=> [node2]" waiting: Do you want to use this configuration? ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "Do you want to use this configuration?" && break; done
vncputln ${vncaddr} "yes"

:; echo -e "\n\033[1;36m=> [node2]" waiting: cluster you want to join: ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "cluster you want to join:" && break; done
read node1_private_ip <<<"$node1_private_ips"
vncputln ${vncaddr} "$node1_private_ip"

:; echo -e "\n\033[1;36m=> [node2]" waiting: This node has been joined to cluster ..."\033[0m"
while sleep 2; do vncget $vncaddr | ocrgrep "This node has been joined to cluster" && break; done

:; echo -e "\n\033[1;36m--------------------------------------------------------------------------------\033[0m"
vncget $vncaddr | GREP_COLORS='ms=01;36' grep --color .
:; echo -e "\n\033[1;36m--------------------------------------------------------------------------------\033[0m"

:; echo -e "\n\033[1;36m=>" "now ssh(admin@$node1_managementif_addr, admin@$node2_managementif_addr and admin@$cluster_managementif_addr) is available,\n please complete other configurations in ssh session ...""\033[0m"
