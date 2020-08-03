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

##please change/cusotmize bellow default configration at first
vmname=ontap-single
password=fsqe2020
cluster_name=fsqe-sn-01
managementif_port=e0c
managementif_addr=
managementif_mask=$(ipcalc -m $(getDefaultIp4)|sed 's/.*=//')
managementif_gateway=$(getDefaultGateway)
cluster_managementif_port=e0a
cluster_managementif_addr=192.168.10.11
cluster_managementif_mask=255.255.255.0
cluster_managementif_gateway=192.168.10.1
dns_domain=192.168.10.1
dns_addr=192.168.10.1
controller_located=raycom

vnc_screen_text() {
	local _vncaddr=$1
	vncdo -s ${_vncaddr} capture _screen.png
	convert _screen.png  -threshold 30%  _screen2.png
	gocr -i _screen2.png 2>/dev/null
}

ocrgrep() {
	local pattern=$1
	local ignored_charset=${2:-ifk}
	pattern=$(sed "s,[${ignored_charset}],.,g" <<<"${pattern}")
	grep -i "${pattern}"
}

netname=ontap-isolate
vm netcreate netname=$netname brname=br-ontap subnet=10
vm -n $vmname ONTAP-simulator -i vsim-NetAppDOT-simulate-disk1.qcow2 \
	--disk=vsim-NetAppDOT-simulate-disk{2..4}.qcow2,bus=ide \
	--net=$netname,e1000  --net=$netname,e1000 --net-macvtap=-,e1000 --net-macvtap=-,e1000 \
	--noauto --force --nocloud --osv freebsd11.2 --bus=ide --msize $((6*1024)) --cpus 2

read vncaddr <<<"$(vm vnc $vmname)"
vncaddr=${vncaddr/:/::}
[[ -z "$vncaddr" ]] && {
	echo "{WARN}: something is wrong, exit ..." >&2
	exit 1
}

:; echo -e "\n\033[1;36m=>" waiting: Hit [Enter] to boot immediately prompt ..."\033[0m"
while sleep 0.5; do vnc_screen_text $vncaddr | ocrgrep "Hit .Enter. to boot immediately" && break; done
vncdo -s ${vncaddr} key enter

:; echo -e "\n\033[1;36m=>" waiting: login prompt ..."\033[0m"
while sleep 5; do vnc_screen_text $vncaddr | ocrgrep ^login: && break; done
[[ -z "$managementif_addr" ]] &&
	managementif_addr=$(vnc_screen_text $vncaddr | sed -nr '/^.*https:..([0-9.]+).*$/{s//\1/; p}')
vncdo -s ${vncaddr} type "admin"
vncdo -s ${vncaddr} key enter
sleep 2
vncdo -s ${vncaddr} type "reboot"
vncdo -s ${vncaddr} key enter

:; echo -e "\n\033[1;36m=>" waiting: reboot confirm prompt ..."\033[0m"
while sleep 5; do vnc_screen_text $vncaddr | ocrgrep "Are you sure you want to reboot node.*? {y|n}:" && break; done
vncdo -s ${vncaddr} type "y"
vncdo -s ${vncaddr} key enter

:; echo -e "\n\033[1;36m=>" waiting: Hit [Enter] to boot immediately prompt ..."\033[0m"
while sleep 5; do vnc_screen_text $vncaddr | ocrgrep "Hit .Enter. to boot immediately" && break; done
vncdo -s ${vncaddr} key enter

: <<'COMM'
:; echo -e "\n\033[1;36m=>" waiting: Boot Menu ask prompt ..."\033[0m"
while sleep 5; do vnc_screen_text $vncaddr | ocrgrep "Press Ctrl-C for Boot Menu." && break; done
vncdo -s ${vncaddr} key ctrl-c

:; echo -e "\n\033[1;36m=>" waiting: Boot Menu list ..."\033[0m"
while sleep 5; do vnc_screen_text $vncaddr | ocrgrep "Selection (1-9)?" && break; done
vncdo -s ${vncaddr} type "4"
vncdo -s ${vncaddr} key ctrl-c

:; echo -e "\n\033[1;36m=>" waiting: Zero disks, reset config and install a new file system? prompt ..."\033[0m"
while sleep 5; do vnc_screen_text $vncaddr | ocrgrep "Zero disks, reset config and install a new file system?" && break; done
vncdo -s ${vncaddr} type "yes"
vncdo -s ${vncaddr} key ctrl-c

:; echo -e "\n\033[1;36m=>" waiting: This will erase all the data on the disks, are you sure? prompt ..."\033[0m"
while sleep 5; do vnc_screen_text $vncaddr | ocrgrep "This will erase all the data on the disks, are you sure?" && break; done
vncdo -s ${vncaddr} type "yes"
vncdo -s ${vncaddr} key ctrl-c

:; echo -e "\n\033[1;36m=>" waiting: Hit [Enter] to boot immediately prompt ..."\033[0m"
while sleep 5; do vnc_screen_text $vncaddr | ocrgrep "Hit .Enter. to boot immediately" && break; done
vncdo -s ${vncaddr} key enter
COMM

:; echo -e "\n\033[1;36m=>" waiting: '"Type yes to confirm and continue {yes}:" ...'"\033[0m"
while sleep 10; do vnc_screen_text $vncaddr | ocrgrep "Type yes to confirm and continue {yes}:" && break; done
vncdo -s ${vncaddr} type "yes"
vncdo -s ${vncaddr} key enter

:; echo -e "\n\033[1;36m=>" waiting: node management interface port prompt ..."\033[0m"
while sleep 2; do vnc_screen_text $vncaddr | ocrgrep "Enter the node management interface port" && break; done
vncdo -s ${vncaddr} type "${managementif_port}"
vncdo -s ${vncaddr} key enter

:; echo -e "\n\033[1;36m=>" waiting: node management interface ip address prompt ..."\033[0m"
while sleep 2; do vnc_screen_text $vncaddr | ocrgrep "Enter the node management interface .. address" && break; done
vncdo -s ${vncaddr} type "$managementif_addr"
vncdo -s ${vncaddr} key enter

:; echo -e "\n\033[1;36m=>" waiting: node management interface ip netmask prompt ..."\033[0m"
while sleep 2; do vnc_screen_text $vncaddr | ocrgrep "Enter the node management interface netmask" && break; done
vncdo -s ${vncaddr} type "$managementif_mask"
vncdo -s ${vncaddr} key enter

:; echo -e "\n\033[1;36m=>" waiting: node management interface gateway prompt ..."\033[0m"
while sleep 2; do vnc_screen_text $vncaddr | ocrgrep "Enter the node management interface default gateway" && break; done
vncdo -s ${vncaddr} type "$managementif_gateway"
vncdo -s ${vncaddr} key enter

:; echo -e "\n\033[1;36m=>" waiting: cluster setup prompt ..."\033[0m"
while sleep 2; do vnc_screen_text $vncaddr | ocrgrep "cluster setup using the command line" && break; done
vncdo -s ${vncaddr} key enter

:; echo -e "\n\033[1;36m=>" waiting: create a new cluster or join an existing cluster? prompt ..."\033[0m"
while sleep 2; do vnc_screen_text $vncaddr | ocrgrep "create a new cluster or join an" && break; done
vncdo -s ${vncaddr} type "create"
vncdo -s ${vncaddr} key enter

:; echo -e "\n\033[1;36m=>" waiting: as a single node cluster? prompt ..."\033[0m"
while sleep 2; do vnc_screen_text $vncaddr | ocrgrep "used as a single node cluster?" && break; done
vncdo -s ${vncaddr} type "yes"
vncdo -s ${vncaddr} key enter

:; echo -e "\n\033[1;36m=>" waiting: 'administrators(username "admin") password prompt ...'"\033[0m"
while sleep 2; do vnc_screen_text $vncaddr | ocrgrep "administrator.* password:" && break; done
vncdo -s ${vncaddr} type "$password"
vncdo -s ${vncaddr} key enter

:; echo -e "\n\033[1;36m=>" waiting: password retype prompt ..."\033[0m"
while sleep 2; do vnc_screen_text $vncaddr | ocrgrep "Retype the password:" && break; done
vncdo -s ${vncaddr} type "$password"
vncdo -s ${vncaddr} key enter

:; echo -e "\n\033[1;36m=>" waiting: cluster name ask prompt ..."\033[0m"
while sleep 2; do vnc_screen_text $vncaddr | ocrgrep "Enter the cluster name:" && break; done
vncdo -s ${vncaddr} type "$cluster_name"
vncdo -s ${vncaddr} key enter

:; echo -e "\n\033[1;36m=>" waiting: license key prompt ..."\033[0m"
while sleep 2; do vnc_screen_text $vncaddr | ocrgrep "Enter an additional license key" && break; done
vncdo -s ${vncaddr} key enter

:; echo -e "\n\033[1;36m=>" waiting: cluster management interface port prompt ..."\033[0m"
while sleep 2; do vnc_screen_text $vncaddr | ocrgrep "Enter the cluster management interface port" && break; done
vncdo -s ${vncaddr} type "${cluster_managementif_port}"
vncdo -s ${vncaddr} key enter

:; echo -e "\n\033[1;36m=>" waiting: cluster management interface ip address prompt ..."\033[0m"
while sleep 2; do vnc_screen_text $vncaddr | ocrgrep "Enter the cluster management interface .. address" && break; done
vncdo -s ${vncaddr} type "$cluster_managementif_addr"
vncdo -s ${vncaddr} key enter

:; echo -e "\n\033[1;36m=>" waiting: cluster management interface ip netmask prompt ..."\033[0m"
while sleep 2; do vnc_screen_text $vncaddr | ocrgrep "Enter the cluster management interface netmask" && break; done
vncdo -s ${vncaddr} type "$cluster_managementif_mask"
vncdo -s ${vncaddr} key enter

:; echo -e "\n\033[1;36m=>" waiting: cluster management interface gateway prompt ..."\033[0m"
while sleep 2; do vnc_screen_text $vncaddr | ocrgrep "Enter the cluster management interface default gateway" && break; done
vncdo -s ${vncaddr} type "$cluster_managementif_gateway"
vncdo -s ${vncaddr} key enter

:; echo -e "\n\033[1;36m=>" waiting: DNS domain names ask prompt ..."\033[0m"
while sleep 2; do vnc_screen_text $vncaddr | ocrgrep "Enter the DNS domain names" && break; done
vncdo -s ${vncaddr} type "$dns_domain"
vncdo -s ${vncaddr} key enter

:; echo -e "\n\033[1;36m=>" waiting: name server IP addresses ask prompt ..."\033[0m"
while sleep 2; do vnc_screen_text $vncaddr | ocrgrep "Enter the name server .. addresses" && break; done
vncdo -s ${vncaddr} type "$dns_addr"
vncdo -s ${vncaddr} key enter

:; echo -e "\n\033[1;36m=>" waiting: where is the controller located prompt ..."\033[0m"
while sleep 2; do vnc_screen_text $vncaddr | ocrgrep "controller located" && break; done
vncdo -s ${vncaddr} type "$controller_located"
vncdo -s ${vncaddr} key enter

:; echo -e "\n\033[1;36m=>" waiting: backup destination address prompt ..."\033[0m"
while sleep 2; do vnc_screen_text $vncaddr | ocrgrep "backup destination address" && break; done
vncdo -s ${vncaddr} key enter
sleep 2

:; echo -e "\n\033[1;36m------------------------------------------------------\033[0m"
vnc_screen_text $vncaddr | GREP_COLORS='ms=01;36' grep --color .
:; echo -e "\n\033[1;36m------------------------------------------------------\033[0m"

:; echo -e "\n\033[1;36m=>" "now ssh(admin@$managementif_addr and admin@$cluster_managementif_addr) is available,\n please complete other configurations in ssh session ...""\033[0m"
