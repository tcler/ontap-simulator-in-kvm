#!/bin/bash
#configure ontap simulator 9.7 as single cluster

rundir=/tmp/ontap-simulator-s-$$
mkdir -p $rundir
clean() { rm -rf $rundir; }
trap "clean" EXIT

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
	vncdo -s ${_vncaddr} capture $rundir/_screen.png
	convert $rundir/_screen.png  -threshold 30%  $rundir/_screen2.png
	gocr -i $rundir/_screen2.png 2>/dev/null
}

vncput() {
	local vncport=$1
	shift

	which vncdo >/dev/null || {
		echo "{WARN} could not find command 'vncdo'" >&2
		return 1
	}

	local msgArray=()
	for msg; do
		if [[ -n "$msg" ]]; then
			if [[ "$msg" = key:* ]]; then
				msgArray+=("$msg")
			else
				regex='[~@#$%^&*()_+|}{":?><!]'
				_msg="${msg#type:}"
				if [[ "$_msg" =~ $regex ]]; then
					while IFS= read -r line; do
						[[ "$line" =~ $regex ]] || line="type:$line"
						msgArray+=("$line")
					done < <(sed -r -e 's;[~!@#$%^&*()_+|}{":?><]+;&\n;g' -e 's;[~!@#$%^&*()_+|}{":?><];\nkey:shift-&;g' <<<"$_msg")
				else
					msgArray+=("$msg")
				fi
			fi
			msgArray+=("")
		else
			msgArray+=("$msg")
		fi

	done
	for msg in "${msgArray[@]}"; do
		if [[ -n "$msg" ]]; then
			if [[ "$msg" = key:* ]]; then
				vncdo -s $vncport key "${msg#key:}"
			else
				vncdo -s $vncport type "${msg#type:}"
			fi
		else
			sleep 1
		fi
	done
}
vncputln() {
	vncput "$@" "key:enter"
}

ocrgrep() {
	local pattern=$1
	local ignored_charset=${2:-ifk[}
	pattern=$(sed "s,[${ignored_charset}],.,g" <<<"${pattern}")
	grep -i "${pattern}"
}
vncwait() {
	local addr=$1
	local pattern="$2"
	local tim=${3:-1}
	local ignored_charset="$4"

	echo -e "\n=> waiting: \033[1;36m$pattern\033[0m prompt ..."
	while true; do vncget $addr | ocrgrep "$pattern" "$ignored_charset" && break; sleep $tim; done
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
:; echo -e "\033[1;30m=> creating network ...\033[0m"
netin=ontap-single
vm netcreate netname=$netin brname=br-ontap subnet=10
vm net | grep -w $netin >/dev/null || vm netstart $netin

:; echo -e "\n\033[1;30m================================================================================\033[0m"
:; echo -e "\033[1;30m=> node vm start ...\033[0m"
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

vncwait ${vncaddr} "Hit [Enter] to boot immediately" 0.5
vncputln ${vncaddr}

vncwait ${vncaddr} "^login:" 5
[[ -z "$node_managementif_addr" ]] &&
	node_managementif_addr=$(vncget $vncaddr | sed -nr '/^.*https:..([0-9.]+).*$/{s//\1/; p}')
vncputln ${vncaddr} "admin" ""
vncputln ${vncaddr} "reboot"

vncwait ${vncaddr} "Are you sure you want to reboot node.*? {y|n}:" 5
vncputln ${vncaddr} "y"

vncwait ${vncaddr} "Hit [Enter] to boot immediately" 5
vncputln ${vncaddr}

: <<'COMM'
vncwait ${vncaddr} "Press Ctrl-C for Boot Menu." 5
vncput ${vncaddr} key:ctrl-c

vncwait ${vncaddr} "Selection (1-9)?" 5
vncputln ${vncaddr} "4"

vncwait ${vncaddr} "Zero disks, reset config and install a new file system?" 5
vncputln ${vncaddr} "yes"

vncwait ${vncaddr} "This will erase all the data on the disks, are you sure?" 5
vncputln ${vncaddr} "yes"

vncwait ${vncaddr} "Hit [Enter] to boot immediately" 5
vncputln ${vncaddr}
COMM

vncwait ${vncaddr} "Type yes to confirm and continue {yes}:" 10
vncputln ${vncaddr} "yes"

vncwait ${vncaddr} "Enter the node management interface port" 2
vncputln ${vncaddr} "${node_managementif_port}"

vncwait ${vncaddr} "Enter the node management interface .. address" 2
vncputln ${vncaddr} "$node_managementif_addr"

vncwait ${vncaddr} "Enter the node management interface netmask" 2
vncputln ${vncaddr} "$node_managementif_mask"

vncwait ${vncaddr} "Enter the node management interface default gateway" 2
vncputln ${vncaddr} "$node_managementif_gateway"

vncwait ${vncaddr} "complete cluster setup using the command line" 2
vncputln ${vncaddr}

vncwait ${vncaddr} "create a new cluster or join an existing cluster?" 2
vncputln ${vncaddr} "create"

vncwait ${vncaddr} "used as a single node cluster?" 2
vncputln ${vncaddr} "yes"

vncwait ${vncaddr} "administrator.* password:" 2
vncputln ${vncaddr} "$password"

vncwait ${vncaddr} "Retype the password:" 2
vncputln ${vncaddr} "$password"

vncwait ${vncaddr} "Enter the cluster name:" 2
vncputln ${vncaddr} "$cluster_name"

vncwait ${vncaddr} "Enter an additional license key" 2
vncputln ${vncaddr}

vncwait ${vncaddr} "Enter the cluster management interface port" 2
vncputln ${vncaddr} "${cluster_managementif_port}"

vncwait ${vncaddr} "Enter the cluster management interface .. address" 2
vncputln ${vncaddr} "$cluster_managementif_addr"

vncwait ${vncaddr} "Enter the cluster management interface netmask" 2
vncputln ${vncaddr} "$cluster_managementif_mask"

vncwait ${vncaddr} "Enter the cluster management interface default gateway" 2
vncputln ${vncaddr} "$cluster_managementif_gateway"

vncwait ${vncaddr} "Enter the DNS domain names" 2
vncputln ${vncaddr} "$dns_domain"

vncwait ${vncaddr} "Enter the name server .. addresses" 2
vncputln ${vncaddr} "$dns_addr"

vncwait ${vncaddr} "where is the controller located" 2
vncputln ${vncaddr} "$controller_located"

vncwait ${vncaddr} "backup destination address" 2
vncputln ${vncaddr}
sleep 2

:; echo -e "\n\033[1;36m------------------------------------------------------\033[0m"
vncget $vncaddr | GREP_COLORS='ms=01;36' grep --color .
:; echo -e "\n\033[1;36m------------------------------------------------------\033[0m"

:; echo -e "\n\033[1;36m=> now ssh(admin@$node_managementif_addr and admin@$cluster_managementif_addr) is available,\n please complete other configurations in ssh session ...\033[0m"

:; echo -e "\n\033[1;30m================================================================================\033[0m"
:; echo -e "\033[1;30m=> Delete snapshots ...\033[0m"
vncwait ${vncaddr} "^login:" 1
vncputln ${vncaddr} "admin"
vncputln ${vncaddr} "${password}"

nodename=${cluster_name}-01
vncwait ${vncaddr} "${cluster_name}::>" 1
vncputln ${vncaddr} "run -node ${nodename}"
vncwait ${vncaddr} "${nodename}>" 1
vncputln ${vncaddr} "snap delete -a -f vol0"
vncputln ${vncaddr} "snap sched vol0 0 0 0"
vncputln ${vncaddr} "snap autodelete vol0 on"
vncputln ${vncaddr} "snap autodelete vol0 target_free_space 35"
vncputln ${vncaddr} "snap autodelete vol0"
vncputln ${vncaddr} "exit"

:; echo -e "\n\033[1;30m================================================================================\033[0m"
:; echo -e "\033[1;30m=> Unlock user diag and set password ...\033[0m"
diagpasswd=d1234567
vncwait ${vncaddr} "${cluster_name}::>" 1
vncputln ${vncaddr} "security login unlock -username diag"
vncputln ${vncaddr} "security login password -username diag"
vncwait ${vncaddr} "Enter a new password:" 1
vncputln ${vncaddr} "${diagpasswd}"
vncwait ${vncaddr} "Enter it again:" 1
vncputln ${vncaddr} "${diagpasswd}"

:; echo -e "\n\033[1;30m================================================================================\033[0m"
:; echo -e "\033[1;30m=> Add disks and create aggregate ...\033[0m"
vncputln ${vncaddr} "set -privilege diag"
vncwait ${vncaddr} "Do you want to continue? {y|n}:" 1
vncputln ${vncaddr} "y"
vncwait ${vncaddr} "${cluster_name}::.>" 1
vncputln ${vncaddr} "systemshell -node ${nodename}"
vncwait ${vncaddr} "password:" 1
vncputln ${vncaddr} "${diagpasswd}"

vncwait ${vncaddr} "${nodename}%" 1
vncputln ${vncaddr} 'setenv PATH "${PATH}:/usr/sbin"'
vncputln ${vncaddr} 'echo $PATH'
vncputln ${vncaddr} 'cd /sim/dev'
vncputln ${vncaddr} 'ls ,disks/'
vncget ${vncaddr}
vncputln ${vncaddr} 'vsim_makedisks -h'
vncget ${vncaddr}
vncputln ${vncaddr} 'sudo vsim_makedisks -n 14 -t 37 -a 2'
vncputln ${vncaddr} 'sudo vsim_makedisks -n 14 -t 37 -a 3'
vncputln ${vncaddr} 'exit'
vncwait ${vncaddr} "${cluster_name}::.>" 1
vncputln ${vncaddr} "system node reboot -node ${nodename}"
vncwait ${vncaddr} "Are you sure you want to reboot node" 1
vncputln ${vncaddr} "y"

vncwait ${vncaddr} "Hit [Enter] to boot immediately" 0.5
vncputln ${vncaddr}

vncwait ${vncaddr} "^login:" 1
vncputln ${vncaddr} "admin"
vncputln ${vncaddr} "${password}"
vncwait ${vncaddr} "${cluster_name}::>" 1
while true; do
	vncputln ${vncaddr} "cluster show"
	vncget ${vncaddr} | grep "$nodename  *true" && break
	sleep 5
done
vncputln ${vncaddr} "disk assign -all true -node ${nodename}"

vncwait ${vncaddr} "${cluster_name}::>" 1
vncputln ${vncaddr} "aggr create -aggregate aggr1 -node ${nodename} -disksize 9 -diskcount 28"
vncputln ${vncaddr} "q"
vncputln ${vncaddr} "y"
vncget ${vncaddr}

vncwait ${vncaddr} "${cluster_name}::>" 1
vncputln ${vncaddr} "aggr create -aggregate aggr2 -node ${nodename} -disksize 1 -diskcount 16"
vncputln ${vncaddr} "q"
vncputln ${vncaddr} "y"
vncget ${vncaddr}

vncwait ${vncaddr} "${cluster_name}::>" 1
vncputln ${vncaddr} "aggr add-disks -aggregate aggr0_${nodename//-/_} -diskcount 9"
vncputln ${vncaddr} "y"
vncputln ${vncaddr} "y"

vncwait ${vncaddr} "${cluster_name}::>" 1
vncputln ${vncaddr} "vol modify -vserver ${nodename} -volume vol0 -size 4G"

vncwait ${vncaddr} "${cluster_name}::>" 1
vncputln ${vncaddr} "aggr show"
vncwait ${vncaddr} "${cluster_name}::>" 1
vncputln ${vncaddr} "vol show"
vncget ${vncaddr}

vncwait ${vncaddr} "${cluster_name}::>" 1
vncputln ${vncaddr} "network port show"
vncwait ${vncaddr} "${cluster_name}::>" 1
vncputln ${vncaddr} "network interface show"
vncget ${vncaddr}

:; echo -e "\n\033[1;36m=> now ssh(admin@$node_managementif_addr and admin@$cluster_managementif_addr) is available,\n please complete other configurations in ssh session ...\033[0m"

expect -c "spawn ssh admin@$cluster_managementif_addr
	expect {Password:} {
		send \"${password}\\r\"
	}

	expect {${cluster_name}::>} {
		send \"system license add -license-code SMKQROWJNQYQSDAAAAAAAAAAAAAA\r\"
	}
	expect {${cluster_name}::>} {
		send \"system license add -license-code YVUCRRRRYVHXCFABGAAAAAAAAAAA,MBXNQRRRYVHXCFABGAAAAAAAAAAA\r\"
	}
	expect {${cluster_name}::>} {
		send \"exit\r\"
	}
	exit
"
