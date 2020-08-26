#!/bin/bash
#configure ontap simulator 9.7 as single cluster

#
#     /-> 192.168.10.0/24       /-> switch that your host connected to. e.g: 10.X.Y.0/23
#     +---------------------+   +---------------------+
#     | vnet: ontap-data    |   | physical switch     |
#     +---------------------+   +---------------------+
#        ^           ^   ^        ^   ^            ^
#        |           |   |        |   |            |
#        |         +--------------------+          |
#        |         |e0a e0b      e0c e0d|          |
#        |         |        ontap       |          |
#        |         |        NODE        |          |
#        |         +--------------------+          |
# ---------------------------------------------------------------
#        |                                         |
#     +-----------+                       +-----------+
#     | RHEL-N in |                       | RHEL-N in |
#     | KVM       |                       | bare-metal|
#     +-----------+                       +-----------+
#     e.g: vm rhel-8.3% -net=ontap-data
#

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
getDefaultIp4Mask() { ipcalc -m $(getDefaultIp4) | sed 's/.*=//'; }
freeIpList() {
	IFS=/ read ip netmasklen < <(getDefaultIp4)
	IFS== read key netaddr < <(ipcalc -n $ip/$netmasklen)
	which nmap &>/dev/null || yum install -y nmap >/dev/null
	local scan_result=$(nmap -v -n -sn $netaddr/$netmasklen 2>/dev/null)

	echo "$scan_result" | awk '/host.down/{print $5}' | sed '1d;$d'
}

getDefaultGateway() { ip route show | awk '$1=="default"{print $3}'; }
dns_domain_names() { sed -n '/^search */{s///; s/ /,/g; p}' /etc/resolv.conf; }
dns_addrs() { sed -n '/^nameserver */{s///; p}' /etc/resolv.conf|paste -sd ,; }

ConvertCmd="gm convert"
if ! which gm &>/dev/null; then
	if ! which convert &>/dev/null; then
		echo "{WARN} command gm or convert are needed" >&2
		exit 1
	else
		ConvertCmd=convert
	fi
fi
if ! which gocr &>/dev/null; then
	echo "{WARN} command gocr is needed" >&2
	exit 1
fi
vncget() {
	local _vncaddr=$1

	[[ -z "$_vncaddr" ]] && return 1
	vncdo -s ${_vncaddr} capture $rundir/_screen.png
	$ConvertCmd $rundir/_screen.png  -threshold 30%  $rundir/_screen2.png
	gocr -i $rundir/_screen2.png 2>/dev/null
}
colorvncget() { vncget "$@" | GREP_COLORS='ms=01;30;47' grep --color .; }

vncput() {
	local vncport=$1
	shift

	which vncdo >/dev/null || {
		echo "{WARN} could not find command 'vncdo'" >&2
		return 1
	}

	[[ -n "$*" ]] && echo -e "\033[1;33m[vncput>$vncport] $*\033[0m"

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
	local ignored_charset=${2:-ijkfwe[|:}
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
cluster_name=fsqe-snc1
password=fsqe2020

vmnode=ontap-single
node_managementif_port=e0c
node_managementif_addr= #10.66.12.108
node_managementif_mask=$(ipcalc -m $(getDefaultIp4)|sed 's/.*=//')
node_managementif_gateway=$(getDefaultGateway)
cluster_managementif_port=e0a
cluster_managementif_addr=192.168.10.11
cluster_managementif_mask=255.255.255.0
cluster_managementif_gateway=192.168.10.1
dns_domains=$(dns_domain_names)
dns_addrs=$(dns_addrs)
read controller_located _ < <(hostname -A)

:; echo -e "\n\033[1;30m================================================================================\033[0m"
:; echo -e "\033[1;30m=> creating network ...\033[0m"
netdata=ontap-data
vm netcreate netname=$netdata brname=br-ontap subnet=10
vm net | grep -w $netdata >/dev/null || vm netstart $netdata

:; echo -e "\n\033[1;30m================================================================================\033[0m"
:; echo -e "\033[1;30m=> node vm start ...\033[0m"
vm -n $vmnode ONTAP-simulator -i vsim-NetAppDOT-simulate-disk1.qcow2 \
	--disk=vsim-NetAppDOT-simulate-disk{2..4}.qcow2,bus=ide \
	--net=$netdata,e1000  --net=$netdata,e1000 --net-macvtap=-,e1000 --net-macvtap=-,e1000 \
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
[[ -z "$node_managementif_addr" ]] &&
	node_managementif_addr=$(freeIpList|sort -R|tail -1)
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
vncputln ${vncaddr} "$dns_domains"

vncwait ${vncaddr} "Enter the name server .. addresses" 2
vncputln ${vncaddr} "$dns_addrs"

vncwait ${vncaddr} "where is the controller located" 2
vncputln ${vncaddr} "$controller_located"

vncwait ${vncaddr} "backup destination address" 2
vncputln ${vncaddr}
sleep 2

:; echo -e "\n\033[1;36m------------------------------------------------------\033[0m"
colorvncget $vncaddr
:; echo -e "\n\033[1;36m------------------------------------------------------\033[0m"

:; echo -e "\n\033[1;36m=> now ssh(admin@$node_managementif_addr and admin@$cluster_managementif_addr) is available,\n please complete other configurations in ssh session ...\033[0m"

:; echo -e "\n\033[1;30m================================================================================\033[0m"
:; echo -e "\033[1;30m=> Delete snapshots and add disk shelf ...\033[0m"

vncwait ${vncaddr} "^login:" 1

nodename=${cluster_name}-01
diagpasswd=d1234567
expect -c "spawn ssh admin@$cluster_managementif_addr
	expect {Password:} { send \"${password}\\r\" }
	expect {${cluster_name}::>} { send \"run -node ${nodename}\\r\" }
	expect {${nodename}>} { send \"snap delete -a -f vol0\\r\" }
	expect {${nodename}>} { send \"snap sched vol0 0 0 0\\r\" }
	expect {${nodename}>} { send \"snap autodelete vol0 on\\r\" }
	expect {${nodename}>} { send \"snap autodelete vol0 target_free_space\\r\" }
	expect {${nodename}>} { send \"snap autodelete vol0\\r\" }
	expect {${nodename}>} { send \"exit\\r\" }

	expect {${cluster_name}::>} { send \"security login unlock -username diag\\r\" }
	expect {${cluster_name}::>} { send \"security login password -username diag\\r\" }
	expect {Enter a new password:} { send \"$diagpasswd\\r\" }
	expect {Enter it again:} { send \"$diagpasswd\\r\" }

	expect {${cluster_name}::>} { send \"\\r\" }
	expect {${cluster_name}::>} { send \"set -privilege diag\\r\" }
	expect {Do you want to continue? {y|n}:} { send \"y\\r\" }
	expect {${cluster_name}::*>} { send \"systemshell -node ${nodename}\\r\" }
	expect {diag@127.0.0.1's password:} { send \"${diagpasswd}\\r\" }

	expect {${nodename}%} { send {setenv PATH \"\${PATH}:/usr/sbin\"}; send \"\\r\" }
	expect {${nodename}%} { send \"echo \\\$PATH\\r\" }
	expect {${nodename}%} { send \"cd /sim/dev\\r\" }
	expect {${nodename}%} { send \"ls ,disks/\\r\" }
	expect {${nodename}%} { send \"vsim_makedisks -h\\r\" }
	expect {${nodename}%} { send \"sudo vsim_makedisks -n 14 -t 37 -a 2\\r\" }
	expect {${nodename}%} { send \"sudo vsim_makedisks -n 14 -t 37 -a 3\\r\" }
	expect {${nodename}%} { send \"exit\\r\" }
	expect {${cluster_name}::*>} { send \"system node reboot -node ${nodename}\\r\" }
	expect {Are you sure you want to reboot node} { send \"y\\r\"}
	expect eof
"

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
vncputln ${vncaddr} "exit"

#LicenseCode=SMKQROWJNQYQSDAAAAAAAAAAAAAA,YVUCRRRRYVHXCFABGAAAAAAAAAAA,MBXNQRRRYVHXCFABGAAAAAAAAAAA
expect -c "spawn ssh admin@$cluster_managementif_addr
	expect {Password:} { send \"${password}\\r\" }
	expect {${cluster_name}::>} { send \"disk assign -all true -node ${nodename}\\r\" }
	after 1000
	expect {${cluster_name}::>} {
		send \"aggr create -aggregate aggr1 -node ${nodename} -disksize 9 -diskcount 28\\r\"
		send \"y\\r\"
		expect {Job succeeded: DONE} {}
	}
	expect {${cluster_name}::>} {
		send \"aggr create -aggregate aggr2 -node ${nodename} -disksize 1 -diskcount 16\\r\"
		send \"y\\r\"
		expect {Job succeeded: DONE} {}
	}
	expect {${cluster_name}::>} {
		send \"aggr add-disks -aggregate aggr0_${nodename//-/_} -diskcount 9\\r\"
		send \"y\\r\"
		send \"y\\r\"
	}
	expect {${cluster_name}::>} { send \"aggr show\\r\" }
	after 1000
	expect {${cluster_name}::>} { send \"vol modify -vserver ${nodename} -volume vol0 -size 4G\\r\" }

	expect {${cluster_name}::>} { send \"system license add -license-code $(sed -n '/^#LicenseCode=/{s/.*=//;p}' $0)\\r\" }
	expect {${cluster_name}::>} { send \"aggr show\\r\" }
	expect {${cluster_name}::>} { send \"vol show\\r\" }
	expect {${cluster_name}::>} { send \"network port show\\r\" }
	expect {${cluster_name}::>} { send \"network interface show\\r\" }
	expect {${cluster_name}::>} { send \"exit\\r\" }
	expect eof
"

VS=vs1
VS_AGGR=aggr1
PolicyName=fs_export
Gateway=$(getDefaultGateway)
testIp=$(getDefaultIp4|sed 's;/.*$;;')

LIF1_0_NAME=lif1.0
LIF1_0_ADDR=192.168.10.21
LIF1_0_MASK=255.255.255.0
LIF1_0_NODE=${cluster_name}-01
LIF1_0_PORT=e0b

LIF1_1_NAME=lif1.1
LIF1_1_ADDR=$(freeIpList|sort -R|head -1)
LIF1_1_MASK=$(getDefaultIp4Mask)
LIF1_1_NODE=${cluster_name}-01
LIF1_1_PORT=e0d

VOL1=vol1
VOL1_AGGR=aggr1
VOL1_SIZE=80G
VOL1_JUNCTION_PATH=/share1

VOL2=vol2
VOL2_AGGR=aggr1
VOL2_SIZE=80G
VOL2_JUNCTION_PATH=/share2

#ref1: https://library.netapp.com/ecmdocs/ECMP1366832/html/vserver/export-policy/create.html
#ref2: https://library.netapp.com/ecmdocs/ECMP1366832/html/vserver/export-policy/rule/create.html

expect -c "spawn ssh admin@$cluster_managementif_addr
	expect {Password:} {
		send \"${password}\\r\"
	}

	expect {${cluster_name}::>} {
		send \"vserver create -vserver $VS -subtype default -rootvolume ${VS}_root -rootvolume-security-style mixed -language C.UTF-8 -snapshot-policy default -data-services data-iscsi,data-nfs,data-cifs,data-flexcache -foreground true -aggregate $VS_AGGR\\r\"
		expect {Vserver creation completed} {send_user {Vserver creation completed}}
	}

	expect {${cluster_name}::>} {
		send \"vserver export-policy create -vserver $VS -policyname $PolicyName\\r\"
	}
	expect {${cluster_name}::>} {
		send \"vserver export-policy rule create -vserver $VS -policyname $PolicyName -protocol cifs,nfs,nfs3,nfs4,flexcache -clientmatch 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 -rorule any -rwrule krb5,sys,ntlm -anon 65534 -allow-suid true -allow-dev true\\r\"
	}
	expect {${cluster_name}::>} {
		send \"volume modify -vserver $VS -volume ${VS}_root -policy $PolicyName\\r\"
	}
	expect {${cluster_name}::>} {
		send \"volume create -volume $VOL1 -aggregate $VOL1_AGGR -size $VOL1_SIZE -state online -unix-permissions ---rwxrwxrwx -type RW -snapshot-policy default -foreground true -tiering-policy none -vserver $VS -junction-path $VOL1_JUNCTION_PATH -policy $PolicyName\\r\"
	}
	expect {${cluster_name}::>} {
		send \"volume create -volume $VOL2 -aggregate $VOL2_AGGR -size $VOL2_SIZE -state online -unix-permissions ---rwxrwxrwx -type RW -snapshot-policy default -foreground true -tiering-policy none -vserver $VS -junction-path $VOL2_JUNCTION_PATH -policy $PolicyName\\r\"
	}
	expect {${cluster_name}::>} {
		send \"network interface create -vserver $VS -lif $LIF1_0_NAME -service-policy default-data-files -role data -data-protocol nfs,cifs,fcache -address $LIF1_0_ADDR -netmask $LIF1_0_MASK -home-node $LIF1_0_NODE -home-port $LIF1_0_PORT -status-admin up -failover-policy system-defined -firewall-policy data -auto-revert true -failover-group Default\\r\"
	}
	expect {${cluster_name}::>} {
		send \"network interface create -vserver $VS -lif $LIF1_1_NAME -service-policy default-data-files -role data -data-protocol nfs,cifs,fcache -address $LIF1_1_ADDR -netmask $LIF1_1_MASK -home-node $LIF1_1_NODE -home-port $LIF1_1_PORT -status-admin up -failover-policy system-defined -firewall-policy data -auto-revert true -failover-group Default\\r\"
	}
	expect {${cluster_name}::>} {
		send \"network route create -vserver $VS  -destination 0.0.0.0/0 -gateway $Gateway\\r\"
	}
	expect {${cluster_name}::>} {
		send \"dns create -domains $dns_domains -name-servers $dns_addrs -timeout 2 -attempts 1 -vserver $VS\\r\"
	}
	expect {${cluster_name}::>} {
		send \"vserver nfs create -access true -v3 enabled -v4.0 disabled -tcp enabled -v4.0-acl enabled -v4.0-read-delegation enabled -v4.0-write-delegation enabled -v4-id-domain defaultv4iddomain.com -v4-grace-seconds 45 -v4-acl-preserve enabled -v4.1 enabled -rquota enabled -v4.1-acl enabled -vstorage enabled -v4-numeric-ids enabled -v4.1-read-delegation enabled -v4.1-write-delegation enabled -mount-rootonly disabled -nfs-rootonly disabled -permitted-enc-types des,des3,aes-128,aes-256 -showmount enabled -name-service-lookup-protocol udp\\r\"
	}
	expect {${cluster_name}::>} {
		send \"vserver export-policy check-access -vserver $VS -volume $VOL1 -client-ip $testIp -authentication-method sys -protocol nfs4 -access-type read-write\\r\"
	}
	expect {${cluster_name}::>} {
		send \"vserver export-policy check-access -vserver $VS -volume $VOL2 -client-ip $testIp -authentication-method sys -protocol nfs4 -access-type read-write\\r\"
	}
	expect {${cluster_name}::>} {
		send \"network interface show\\r\"
	}

	expect {${cluster_name}::>} {
		send \"exit\\r\"
	}
	expect eof
"
