#!/bin/bash
#install and configure two inode cluster with ontap simulator 9.7

#                                                        |
#                                                        |
#                             .--------------------------|-----,
#                             |                          |     |
#        .----------------,   |   .----------------,     |     |
#        |   .---------,  |   |   | .---------,    |     |   +-----------+
#        |   |         v  v   v   v v         |    |     |   | RHEL-N in |
#        |   |      +-------------------+     |    |     |   | bare-metal|
#        |   |      | physical switch   |     |    |     |   +-----------+
#        |   |      +-------------------+     |    |     |
#        |   |                                |    |     |
#        |   |                      .--------------------|-----,
#        |   |                      |         |    |     |     |
#        |   |                      v         |    |     |     |
#        |   |      +-------------------+     |    |     |   +-----------+
#        |   |      | vnet: ontap2-data |     |    |     |   | RHEL-N in |
#        |   |      +-------------------+     |    |     |   | KVM       |
#        |   |        ^   ^       ^   ^       |    |     |   +-----------+
#        |   |        |   |       |   |       |    |         e.g: vm rhel-8.3% -net=ontap2-data
#      +--------------------+   +--------------------+
#      |e0f e0c      e0d e0e|   |e0d e0e      e0f e0c|
#      |       ontap        |   |       ontap        |
#      |       NODE1        |   |       NODE2        |
#      |             e0a e0b|   |e0a e0b             |
#      +--------------------+   +--------------------+
#                     |   |       |   |
#                     v   v       v   v
#                  +----------------------+
#                  | vnet: ontap2-ci      |
#                  +----------------------+
#

# command line parse
P=${0##*/}
Usage() {
	cat <<-EOF
	Usage:
	  $P [OPTIONs]

	Options:
	  -h, --help                         #Display this help.
	  --dnsaddrs <ip[,ip2]>              #e.g: 192.168.10.1 or 192.168.1.1,192.168.2.1
	  --dnsdomains <domain1[,domain2]>   #e.g: test.a.com or test.a.com,devel.a.com
	  --node1-pubaddr <ip>               #node1 management address for public access
	  --node2-pubaddr <ip>               #node2 management address for public access
	  --lif1-pubaddr <ip>                #default lif1.1 address for public access
	  --lif2-pubaddr <ip>                #default lif2.1 address for public access
	  --vserver-name <NetBIOS>           #NetBIOS(or host name) of vserver, used by krb5 configuring
	  --cifs-workgroup <NetBIOS>         #Workgroup Name, This parameter specifies the name of the workgroup (up to 15 characters).
	  --ad-hostname <FQDN>               #Fully Qualified Domain Name, This parameter specifies the name of window servers.
	  --ad-ip <ip>                       #window servers ip.
	  --ad-ip-hostonly <ip>              #window servers ip used to connect from VM HOST.
	  --ssh-bind-ip <ip>                 #another ip address used for ssh to KVM guest from host
	  --ad-admin <user>                  #Active Directory admin user name
	  --ad-passwd <passwd>               #Active Directory admin password
	  --ntp-server <addr>                #ntp server address
	EOF
}

#cifs option: https://docs.netapp.com/ontap-9/index.jsp?topic=%2Fcom.netapp.doc.dot-cm-cmpr-910%2Fvserver__cifs__create.html

_at=`getopt -o h \
	--long help \
	--long dnsaddrs: \
	--long dnsdomains: \
	--long node1-pubaddr: \
	--long node2-pubaddr: \
	--long lif1-pubaddr: \
	--long lif2-pubaddr: \
	--long vserver-name: \
	--long cifs-workgroup: \
	--long ad-hostname: \
	--long ad-ip: \
	--long ad-ip-hostonly: \
	--long ssh-bind-ip: \
	--long ad-admin: \
	--long ad-passwd: \
	--long ntp-server: \
    -a -n "$0" -- "$@"`
[[ $? != 0 ]] && { exit 1; }
eval set -- "$_at"
while true; do
	case "$1" in
	-h|--help) Usage; shift 1; exit 0;;
	--dnsaddrs)       DNS_ADDRS=$2; shift 2;;
	--dnsdomains)     DNS_DOMAINS=$2; shift 2;;
	--node1-pubaddr)  node1_managementif_addr=$2; shift 2;;
	--node2-pubaddr)  node2_managementif_addr=$2; shift 2;;
	--lif1-pubaddr)   LIF1_1_ADDR=$2; shift 2;;
	--lif2-pubaddr)   LIF2_1_ADDR=$2; shift 2;;
	--vserver-name)   NAS_SERVER_NAME=$2; shift 2;;
	--cifs-workgroup) CIFS_WORKGROUP=$2; shift 2;;
	--ad-hostname)    AD_NAME=$2; shift 2;;
	--ad-ip)          AD_IP=$2; shift 2;;
	--ad-ip-hostonly) AD_IP_HOSTONLY=$2; SSH_BIND_IP=; shift 2;;
	--ssh-bind-ip)    SSH_BIND_IP=$2; AD_IP_HOSTONLY=; shift 2;;
	--ad-admin)       AD_ADMIN=$2; shift 2;;
	--ad-passwd)      AD_PASSWD=$2; shift 2;;
	--ntp-server)     NTP_SERVER=$2; shift 2;;
	--) shift; break;;
	esac
done


#__main__
Rundir=/tmp/ontap-simulator-t-$$
mkdir -p $Rundir
clean() { rm -rf $Rundir; }
trap "clean" EXIT

getIp4() {
	local ret
	local nic=$1
	local ipaddr=`ip addr show $nic`;
	ret=$(echo "$ipaddr" |
		awk '/inet .* global dynamic/{match($0,"inet ([0-9.]+/[0-9]+)",M); print M[1]}');

	if [[ -n "$ret" ]]; then
		echo "$ret"
		return 0
	else
		return 1
	fi
}
getDefaultNic() {
	local nics=$(ip route | awk '/default/{match($0,"dev ([^ ]+)",M); print M[1]}')
	for nic in $nics; do
		[[ -z "$(ip -d link show  dev $nic|sed -n 3p)" ]] && {
			break
		}
	done
	[[ -n "$nic" ]] && echo "$nic"
}
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

getDefaultGateway() { ip route show | awk '$1=="default"{print $3; exit}'; }
dns_domain_names() { sed -rn -e '/^search */{s///; s/( |^)local( |$)//; s/ /,/g; p}' /etc/resolv.conf; }
dns_addrs() {
	if grep -q 127.0.0.53 /etc/resolv.conf; then
		systemd-resolve --status -4 $(getDefaultNic) | sed 's/:/:\n/' |
			sed -n '/^ *DNS Servers:/,/^ *DNS/ {/DNS.*:/d; s/ //g; p}' | paste -sd ,;
	else
		sed -rn '/^nameserver */{s///; s/ *#.*$//; p}' /etc/resolv.conf | paste -sd ,;
	fi
}

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
	vncdo -s ${_vncaddr} capture $Rundir/_screen.png
	$ConvertCmd $Rundir/_screen.png  -threshold 30%  $Rundir/_screen2.png
	gocr -i $Rundir/_screen2.png 2>/dev/null
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

:; echo -e "\n\033[1;30m================================================================================\033[0m"
:; echo -e "\033[1;30m=> creating networks ...\033[0m"
netcluster=ontap2-ci  #e0a e0b
vm netcreate netname=$netcluster brname=br-ontap2-ci forward=
vm net | grep -w $netcluster >/dev/null || vm netstart $netcluster

netdata=ontap2-data  #e0d #e0e
vm netcreate netname=$netdata brname=br-ontap2-data subnet=20
vm net | grep -w $netdata >/dev/null || vm netstart $netdata

:; echo -e "\n\033[1;30m================================================================================\033[0m"
:; echo -e "\033[1;30m=> creating macvlan if mv-ontap ...\033[0m"
netns host,mv-ontap,dhcp

#===============================================================================
#cluster
cluster_name=fsqe-2nc1
password=fsqe2020
NTP_SERVER=${NTP_SERVER:-192.168.20.1}

#===============================================================================
#node1
vmnode1=ontap-node1
node1_managementif_port=e0c
node1_managementif_addr=$node1_managementif_addr #10.66.12.176
node1_managementif_mask=$(ipcalc -m $(getDefaultIp4)|sed 's/.*=//')
node1_managementif_gateway=$(getDefaultGateway)
cluster_managementif_port=e0d
cluster_managementif_addr=192.168.20.11
cluster_managementif_mask=255.255.255.0
cluster_managementif_gateway=192.168.20.1
dns_domains=$(dns_domain_names)
[[ -n "$DNS_DOMAINS" && $dns_domains != ${DNS_DOMAINS},* ]] &&
	dns_domains=$(echo "${DNS_DOMAINS},${dns_domains}"|awk -F, -v OFS=, '{if(NF>3) {print $1,$2,$3} else print}')
dns_addrs=$(dns_addrs)
[[ -n "$DNS_ADDRS" && $dns_addrs != ${DNS_ADDRS},* ]] &&
	dns_addrs=$(echo "${DNS_ADDRS},${dns_addrs}"|awk -F, -v OFS=, '{if(NF>3) {print $1,$2,$3} else print}')
read controller_located _ < <(hostname -A)

:; echo -e "\n\033[1;30m================================================================================\033[0m"
:; echo -e "\033[1;30m=> [$vmnode1] start ...\033[0m"
vm -n $vmnode1 ONTAP-simulator -i vsim-NetAppDOT-simulate-disk1.qcow2 --disable-guest-hypv \
	--disk=vsim-NetAppDOT-simulate-disk{2..4}.qcow2,bus=ide \
	--net=$netcluster,e1000 --net=$netcluster,e1000 \
	--net-macvtap=-,e1000 \
	--net=$netdata,e1000 --net=$netdata,e1000 \
	--net-macvtap=-,e1000 \
	--noauto --force --nocloud --osv freebsd11.2 --bus=ide --msize $((6*1024)) --cpus 2,cores=2

read vncaddr <<<"$(vm vnc $vmnode1)"
vncaddr=${vncaddr/:/::}
[[ -z "$vncaddr" ]] && {
	echo "{WARN}: something is wrong, exit ..." >&2
	exit 1
}

vncwait ${vncaddr} "Hit [Enter] to boot immediately" 0.5
vncputln ${vncaddr}

vncwait ${vncaddr} "^login:" 5
[[ -z "$node1_managementif_addr" ]] &&
	node1_managementif_addr=$(vncget $vncaddr | sed -nr '/^.*https:..([0-9.]+).*$/{s//\1/; p}')
[[ -z "$node1_managementif_addr" ]] &&
	node1_managementif_addr=$(freeIpList|sort -R|tail -1)
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
vncputln ${vncaddr} "${node1_managementif_port}"

vncwait ${vncaddr} "Enter the node management interface .. address" 2
vncputln ${vncaddr} "$node1_managementif_addr"

vncwait ${vncaddr} "Enter the node management interface netmask" 2
vncputln ${vncaddr} "$node1_managementif_mask"

vncwait ${vncaddr} "Enter the node management interface default gateway" 2
vncputln ${vncaddr} "$node1_managementif_gateway"

vncwait ${vncaddr} "complete cluster setup using the command line" 2
vncputln ${vncaddr}

vncwait ${vncaddr} "create a new cluster or join an existing cluster?" 2
vncputln ${vncaddr} "create"

vncwait ${vncaddr} "used as a single node cluster?" 2
vncputln ${vncaddr} "no"


vncwait ${vncaddr} "Do you want to use this configuration?" 2
node1_private_ips=$(vncget $vncaddr|sed -nr '/^.*(169.254.[0-9]+.[0-9]+).*$/{s//\1/; p}')
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
sleep 2

:; echo -e "\n\033[1;36m--------------------------------------------------------------------------------\033[0m"
colorvncget $vncaddr
:; echo -e "\n\033[1;36m--------------------------------------------------------------------------------\033[0m"

:; echo -e "\n\033[1;36m=> now ssh(admin@$node1_managementif_addr and admin@$cluster_managementif_addr) is available,\n please complete other configurations in ssh session ...\033[0m"

#===============================================================================
#node2
vmnode2=ontap-node2
node2_managementif_port=e0c
node2_managementif_addr=$node2_managementif_addr #10.66.12.160
node2_managementif_mask=$(ipcalc -m $(getDefaultIp4)|sed 's/.*=//')
node2_managementif_gateway=$(getDefaultGateway)

:; echo -e "\n\033[1;30m================================================================================\033[0m"
:; echo -e "\033[1;30m=> [$vmnode2] start ...\033[0m"
vm -n $vmnode2 ONTAP-simulator -i vsim-NetAppDOT-simulate-disk1.qcow2 --disable-guest-hypv \
	--disk=vsim-NetAppDOT-simulate-disk{2..4}.qcow2,bus=ide \
	--net=$netcluster,e1000 --net=$netcluster,e1000 \
	--net-macvtap=-,e1000 \
	--net=$netdata,e1000 --net=$netdata,e1000 \
	--net-macvtap=-,e1000 \
	--noauto --force --nocloud --osv freebsd11.2 \
	--bus=ide --msize $((6*1024)) --cpus 2,cores=2 --vncput-after-install "x"

read vncaddr <<<"$(vm vnc $vmnode2)"
vncaddr=${vncaddr/:/::}
[[ -z "$vncaddr" ]] && {
	echo "{WARN}: something is wrong, exit ..." >&2
	exit 1
}

vncwait ${vncaddr} "Hit [Enter] to boot immediately" 0.5
vncput ${vncaddr} " "
vncwait ${vncaddr} "VLOADER>" 0.5
vncputln ${vncaddr} "setenv SYS_SERIAL_NUM 4034389-06-2"
vncputln ${vncaddr} "setenv bootarg.nvram.sysid 4034389062"
vncputln ${vncaddr} "printenv SYS_SERIAL_NUM"
vncputln ${vncaddr} "printenv bootarg.nvram.sysid"
vncputln ${vncaddr} "boot"

vncwait ${vncaddr} "^login:" 5
[[ -z "$node2_managementif_addr" ]] &&
	node2_managementif_addr=$(vncget $vncaddr | sed -nr '/^.*https:..([0-9.]+).*$/{s//\1/; p}')
[[ -z "$node2_managementif_addr" ]] &&
	node2_managementif_addr=$(freeIpList|sort -R|tail -1)
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
vncputln ${vncaddr} "${node2_managementif_port}"

vncwait ${vncaddr} "Enter the node management interface .. address" 2
vncputln ${vncaddr} "$node2_managementif_addr"

vncwait ${vncaddr} "Enter the node management interface netmask" 2
vncputln ${vncaddr} "$node2_managementif_mask"

vncwait ${vncaddr} "Enter the node management interface default gateway" 2
vncputln ${vncaddr} "$node2_managementif_gateway"

vncwait ${vncaddr} "complete cluster setup using the command line" 2
vncputln ${vncaddr}

vncwait ${vncaddr} "create a new cluster or join an existing cluster?" 2
vncputln ${vncaddr} "join"

vncwait ${vncaddr} "Do you want to use this configuration?" 2
vncputln ${vncaddr} "yes"

vncwait ${vncaddr} "cluster you want to join:" 2
read node1_private_ip <<<"$node1_private_ips"
vncputln ${vncaddr} "$node1_private_ip"

vncwait ${vncaddr} "This node has been joined to cluster" 2

:; echo -e "\n\033[1;36m--------------------------------------------------------------------------------\033[0m"
colorvncget $vncaddr
:; echo -e "\n\033[1;36m--------------------------------------------------------------------------------\033[0m"

:; echo -e "\n\033[1;36m=> now ssh(admin@$node1_managementif_addr, admin@$node2_managementif_addr and admin@$cluster_managementif_addr) is available,\n please complete other configurations in ssh session ...\033[0m"

idx=1
for vmnode in $vmnode1 $vmnode2; do
	read vncaddr <<<"$(vm vnc $vmnode)"
	vncaddr=${vncaddr/:/::}
	:; echo -e "\n\033[1;30m================================================================================\033[0m"
	:; echo -e "\033[1;30m=> [$vmnode] Delete snapshots and add disk shelf ...\033[0m"
	vncwait ${vncaddr} "^login:" 1

	nodename=${cluster_name}-0$idx
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
		expect -re {diag@[0-9.]+'s password:} { send \"${diagpasswd}\\r\" }

		expect {${nodename}%} { send {setenv PATH \"\${PATH}:/usr/sbin\"}; send \"\\r\" }
		expect {${nodename}%} { send \"echo \\\$PATH\\r\" }
		expect {${nodename}%} { send \"cd /sim/dev\\r\" }
		expect {${nodename}%} { send \"ls ,disks/\\r\" }
		expect {${nodename}%} { send \"vsim_makedisks -h\\r\" }
		expect {${nodename}%} { send \"sudo vsim_makedisks -n 14 -t 37 -a 2\\r\" }
		expect {${nodename}%} { send \"sudo vsim_makedisks -n 14 -t 37 -a 3\\r\" }
		expect {${nodename}%} { send \"exit\\r\" }
		expect {${cluster_name}::*>} { send \"system node reboot -node ${nodename} -ignore-quorum-warnings\\r\" }
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

	expect -c "spawn ssh admin@$cluster_managementif_addr
		expect {Password:} { send \"${password}\\r\" }
		expect {${cluster_name}::>} { send \"disk assign -all true -node ${nodename}\\r\" }
		after 1000
		expect {${cluster_name}::>} {
			send \"aggr create -aggregate aggr${idx}_1 -node ${nodename} -disksize 9 -diskcount 28\\r\"
			send \"y\\r\"
			expect {Job succeeded: DONE} {}
		}
		expect {${cluster_name}::>} {
			send \"aggr create -aggregate aggr${idx}_2 -node ${nodename} -disksize 1 -diskcount 16\\r\"
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
		expect {${cluster_name}::>} { send \"exit\\r\" }
		expect eof
	"

	let idx++
done

#LicenseCode=SMKQROWJNQYQSDAAAAAAAAAAAAAA,YVUCRRRRYVHXCFABGAAAAAAAAAAA,MBXNQRRRYVHXCFABGAAAAAAAAAAA,MHEYKUNFXMSMUCEZFAAAAAAAAAAA,ANGJKUNFXMSMUCEZFAAAAAAAAAAA
expect -c "spawn ssh admin@$cluster_managementif_addr
	expect {Password:} { send \"${password}\\r\" }
	expect {${cluster_name}::>} { send \"system license add -license-code $(sed -n '/^#LicenseCode=/{s/.*=//;p}' $0)\\r\" }
	expect {${cluster_name}::>} { send \"aggr show\\r\" }
	expect {${cluster_name}::>} { send \"vol show\\r\" }
	expect {${cluster_name}::>} { send \"network port show\\r\" }
	expect {${cluster_name}::>} { send \"network interface show\\r\" }
	expect {${cluster_name}::>} { send \"exit\\r\" }
	expect eof
"

VS=vs1
VS_AGGR=aggr1_1
PolicyName=fs_export
Gateway=$(getDefaultGateway)
testIp=$(getDefaultIp4|sed 's;/.*$;;')

VOL1=vol1
VOL1_AGGR=aggr1_1
VOL1_SIZE=90G
VOL1_JUNCTION_PATH=/share1
LIF1_0_NAME=lif1.0
LIF1_0_ADDR=192.168.20.21
LIF1_0_MASK=255.255.255.0
LIF1_0_NODE=${cluster_name}-01
LIF1_0_PORT=e0e
LIF1_1_NAME=lif1.1
[[ -z "$LIF1_1_ADDR" ]] && LIF1_1_ADDR=$(freeIpList|sort -R|head -1)
LIF1_1_MASK=$(getDefaultIp4Mask)
LIF1_1_NODE=${cluster_name}-01
LIF1_1_PORT=e0f

VOL2=vol2
VOL2_AGGR=aggr2_1
VOL2_SIZE=90G
VOL2_JUNCTION_PATH=/share2
LIF2_0_NAME=lif2.0
LIF2_0_ADDR=192.168.20.22
LIF2_0_MASK=255.255.255.0
LIF2_0_NODE=${cluster_name}-02
LIF2_0_PORT=e0e
LIF2_1_NAME=lif2.1
[[ -z "$LIF2_1_ADDR" ]] && LIF2_1_ADDR=$(freeIpList|sort -R|head -1)
LIF2_1_MASK=$(getDefaultIp4Mask)
LIF2_1_NODE=${cluster_name}-02
LIF2_1_PORT=e0f

[[ -z "$NAS_SERVER_NAME" ]] && {
	read A B C D N < <(getDefaultIp4|sed 's;[./]; ;g')
	NAS_SERVER_NAME=ontap2-$(printf %02x%02x $C $D)
}
CIFS_WORKGROUP=${CIFS_WORKGROUP:-FSQE}
LOCAL_USER=root
LOCAL_USER_PASSWD=Sesame~0pen
cifsOption="-workgroup $CIFS_WORKGROUP"
AD_DOMAIN=${AD_NAME#*.}
[[ -n "$AD_DOMAIN" ]] && cifsOption="-domain $AD_DOMAIN"
AD_REALM=$(echo ${AD_DOMAIN} | tr [:lower:] [:upper:])
AD_ADMIN=${AD_ADMIN:-administrator}
AD_PASSWD=${AD_PASSWD:-fsqe2015!}
CIFSVOL1=cifsvol1
CIFSVOL1_AGGR=aggr1_1
CIFSVOL1_SIZE=60G
CIFSVOL1_PATH=/cifs1
SHARENAME=cifs1

CIFSVOL2=cifsvol2
CIFSVOL2_AGGR=aggr2_1
CIFSVOL2_SIZE=60G
CIFSVOL2_PATH=/cifs2
SHARENAME2=cifs2
#ref1: https://library.netapp.com/ecmdocs/ECMP1366832/html/vserver/export-policy/create.html
#ref2: https://library.netapp.com/ecmdocs/ECMP1366832/html/vserver/export-policy/rule/create.html
#ref3: https://tcler.github.io/2017/08/24/NetApp-pnfs-mds-ds-config

[[ -n "$SSH_BIND_IP" ]] && SSH_BIND_OPT="-b $SSH_BIND_IP"
expect -c "spawn ssh $SSH_BIND_IP -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $AD_ADMIN@${AD_IP_HOSTONLY:-$AD_IP}
	expect {password:} { send \"${AD_PASSWD}\\r\" }
	expect {>} { send \"powershell\\r\" }
	expect {>} {
		send \"Add-DnsServerResourceRecordA -Name "$NAS_SERVER_NAME" -ZoneName "$AD_DOMAIN" -AllowUpdateAny -IPv4Address '$LIF1_1_ADDR'\\r\"
	}
        expect {>} { send \"exit\\r\" }
        expect {>} { send \"exit\\r\" }
        expect eof
"

expect -c "spawn ssh admin@$cluster_managementif_addr
	set timeout 120
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
		send \"vserver export-policy rule create -vserver $VS -policyname $PolicyName -protocol cifs,nfs,nfs3,nfs4,flexcache -clientmatch 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 -rorule any -rwrule any -anon 65534 -allow-suid true -allow-dev true\\r\"
	}
	expect {${cluster_name}::>} {
		send \"volume modify -vserver $VS -volume ${VS}_root -policy $PolicyName -group 0 -user 0\\r\"
	}
	expect {${cluster_name}::>} {
		send \"volume create -volume $VOL1 -aggregate $VOL1_AGGR -size $VOL1_SIZE -state online -unix-permissions ---rwxrwxrwx -type RW -snapshot-policy default -foreground true -tiering-policy none -vserver $VS -junction-path $VOL1_JUNCTION_PATH -policy $PolicyName -group 0 -user 0\\r\"
	}
	expect {${cluster_name}::>} {
		send \"network interface create -vserver $VS -lif $LIF1_0_NAME -service-policy default-data-files -role data -data-protocol nfs,cifs,fcache -address $LIF1_0_ADDR -netmask $LIF1_0_MASK -home-node $LIF1_0_NODE -home-port $LIF1_0_PORT -status-admin up -failover-policy system-defined -firewall-policy data -auto-revert true -failover-group Default\\r\"
	}
	expect {${cluster_name}::>} {
		send \"network interface create -vserver $VS -lif $LIF1_1_NAME -service-policy default-data-files -role data -data-protocol nfs,cifs,fcache -address $LIF1_1_ADDR -netmask $LIF1_1_MASK -home-node $LIF1_1_NODE -home-port $LIF1_1_PORT -status-admin up -failover-policy system-defined -firewall-policy data -auto-revert true -failover-group Default\\r\"
	}
	expect {${cluster_name}::>} {
		send \"volume create -volume $VOL2 -aggregate $VOL2_AGGR -size $VOL2_SIZE -state online -unix-permissions ---rwxrwxrwx -type RW -snapshot-policy default -foreground true -tiering-policy none -vserver $VS -junction-path $VOL2_JUNCTION_PATH -policy $PolicyName -group 0 -user 0\\r\"
	}
	expect {${cluster_name}::>} {
		send \"network interface create -vserver $VS -lif $LIF2_0_NAME -service-policy default-data-files -role data -data-protocol nfs,cifs,fcache -address $LIF2_0_ADDR -netmask $LIF2_0_MASK -home-node $LIF2_0_NODE -home-port $LIF2_0_PORT -status-admin up -failover-policy system-defined -firewall-policy data -auto-revert true -failover-group Default\\r\"
	}
	expect {${cluster_name}::>} {
		send \"network interface create -vserver $VS -lif $LIF2_1_NAME -service-policy default-data-files -role data -data-protocol nfs,cifs,fcache -address $LIF2_1_ADDR -netmask $LIF2_1_MASK -home-node $LIF2_1_NODE -home-port $LIF2_1_PORT -status-admin up -failover-policy system-defined -firewall-policy data -auto-revert true -failover-group Default\\r\"
	}
	expect {${cluster_name}::>} {
		send \"network route create -vserver $VS  -destination 0.0.0.0/0 -gateway $Gateway\\r\"
	}
	expect {${cluster_name}::>} {
		send \"dns create -domains $dns_domains -name-servers $dns_addrs -timeout 8 -attempts 4 -skip-config-validation -vserver $VS\\r\"
	}
	expect {${cluster_name}::>} {
		send \"vserver nfs create -access true -v3 enabled -v4.0 enabled -tcp enabled -v4.0-acl enabled -v4.0-read-delegation enabled -v4.0-write-delegation enabled -v4-id-domain defaultv4iddomain.com -v4-grace-seconds 45 -v4-acl-preserve enabled -v4.1 enabled -rquota enabled -v4.1-acl enabled -vstorage enabled -v4-numeric-ids enabled -v4.1-read-delegation enabled -v4.1-write-delegation enabled -mount-rootonly disabled -nfs-rootonly disabled -permitted-enc-types des,des3,aes-128,aes-256 -showmount enabled -name-service-lookup-protocol udp\\r\"
	}
	expect {${cluster_name}::>} {
		send \"unix-user create -vserver $VS -user nfs -id 500 -primary-gid 0\\r\"
	}
	expect {${cluster_name}::>} {
		send \"vserver export-policy check-access -vserver $VS -volume $VOL1 -client-ip $testIp -authentication-method sys -protocol nfs4 -access-type read-write\\r\"
	}
	expect {${cluster_name}::>} {
		send \"vserver export-policy check-access -vserver $VS -volume $VOL2 -client-ip $testIp -authentication-method sys -protocol nfs4 -access-type read-write\\r\"
	}
	expect {${cluster_name}::>} {
		send \"volume create -volume $CIFSVOL1 -aggregate $CIFSVOL1_AGGR -size $CIFSVOL1_SIZE -state online -unix-permissions ---rwxrwxrwx -type RW -vserver $VS -junction-path $CIFSVOL1_PATH -policy $PolicyName -group 0 -user 0\\r\"
	}
	expect {${cluster_name}::>} {
		send \"volume create -volume $CIFSVOL2 -aggregate $CIFSVOL2_AGGR -size $CIFSVOL2_SIZE -state online -unix-permissions ---rwxrwxrwx -type RW  -vserver $VS -junction-path $CIFSVOL2_PATH -policy $PolicyName -group 0 -user 0\\r\"
	}
	expect {${cluster_name}::>} {
		send \"ntp server create -server $NTP_SERVER\\r\"
	}
	expect {${cluster_name}::>} {
		send \"cifs create -vserver $VS -cifs-server $NAS_SERVER_NAME $cifsOption\\r\"
		expect {
			{Enter the user name:} {
				send \"${AD_ADMIN}\\r\"
				expect {Enter the password:} { send \"${AD_PASSWD}\\r\" }
				expect {
					{Ok to reuse this account? {y|n}:} { send \"y\\r\" }
					{${cluster_name}::>} { send \"\\r\" }
				}
			}
			{${cluster_name}::>} {
				send \"vserver cifs users-and-groups local-user create -vserver $VS -user-name $NAS_SERVER_NAME\\\\${LOCAL_USER} -full-name ${LOCAL_USER}\\r\"
				expect {Enter the password:} { send \"${LOCAL_USER_PASSWD}\\r\" }
				expect {Confirm the password:} { send \"${LOCAL_USER_PASSWD}\\r\" }
			}
		}
	}
	expect {${cluster_name}::>} {
		send \"cifs security modify -is-aes-encryption-enabled true -vserver $VS\\r\"
	}
	expect {${cluster_name}::>} {
		send \"vserver cifs share create -share-name $SHARENAME -vserver $VS -path $CIFSVOL1_PATH\\r\"
	}
	expect {${cluster_name}::>} {
		send \"vserver cifs share create -share-name $SHARENAME2 -vserver $VS -path $CIFSVOL2_PATH\\r\"
	}
	expect {${cluster_name}::>} { send \"set -privilege advanced\\r\" }
	expect {Do you want to continue? {y|n}:} { send \"y\\r\" }
	expect {${cluster_name}::*>} { send \"vserver cifs options modify -vserver $VS -is-trusted-domain-enum-search-enabled false\\r\" }
	expect {${cluster_name}::*>} { send \"set -privilege admin\\r\" }
	expect {${cluster_name}::>} {
		send \"cifs share show -vserver $VS\\r\"
	}

	expect {${cluster_name}::>} {
		send \"network interface show\\r\"
		expect {
		{'q' to quit...} { send \"q\\r\" }
		{${cluster_name}::>} { send \"\\r\" }
		}
	}

	expect {${cluster_name}::>} {
		send \"exit\\r\"
	}
	expect eof
"
LogOutPut=$(expect -c "spawn ssh admin@$cluster_managementif_addr
        set timeout 120
        expect {Password:} { send \"${password}\\r\" }
        expect {${cluster_name}::>} { send \"cifs show  -vserver $VS -fields domain-workgroup\\r\" }
        expect {${cluster_name}::>} { send \"exit\\r\" }
        expect eof
        ")

NETBIOS_WIN=`echo "$LogOutPut" |grep -A 2 domain-workgroup | awk 'END{print $2}'`

TimeZone=$(timedatectl | awk '/Time zone:/{print $3}')
expect -c "spawn ssh admin@$cluster_managementif_addr
	set timeout 120
	expect {Password:} { send \"${password}\\r\" }
	expect {${cluster_name}::>} { send \"cluster date modify -timezone ${TimeZone:-America/New_York}\\r\" }
	expect {${cluster_name}::>} { send \"cluster date modify -date \\\"$(date '+%m/%d/%Y %H:%M:%S')\\\"\\r\" }
	expect {${cluster_name}::>} {
		send \"vserver name-mapping  create -vserver $VS -direction krb-unix -position 1 -pattern (.+)\\\\\$@$AD_REALM  -replacement root\\r\"
	}
	expect {${cluster_name}::>} {
		send \"vserver name-mapping  create -vserver $VS -direction unix-win -position 1 -pattern root -replacement $NETBIOS_WIN\\\\\\\\${AD_ADMIN}\\r\"
	}
	expect {${cluster_name}::>} {
		send \"kerberos realm create  -realm $AD_REALM -adserver-ip $AD_IP -adminserver-ip $AD_IP -kdc-ip $AD_IP -vserver $VS  -kdc-vendor Microsoft  -adserver-name $AD_NAME\\r\"
	}
	expect {${cluster_name}::>} {
		send \"kerberos interface enable -lif $LIF1_1_NAME -admin-username ${AD_ADMIN} -spn nfs/${NAS_SERVER_NAME}.${AD_DOMAIN}@${AD_REALM}\\r\"
		expect {Password:} { send \"${AD_PASSWD}\\r\" }
	}
	expect {${cluster_name}::>} { send \"exit\\r\" }
	expect eof
"
expect -c "spawn ssh $SSH_BIND_OPT -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $AD_ADMIN@${AD_IP_HOSTONLY:-$AD_IP}
	expect {password:} { send \"${AD_PASSWD}\\r\" }
	expect {>} { send \"powershell\\r\" }
	expect {>} {
		send \"Set-ADComputer NFS-${NAS_SERVER_NAME} -KerberosEncryptionType AES256,AES128,DES,RC4\\r\"
}
	expect {>} { send \"exit\\r\" }
	expect {>} { send \"exit\\r\" }
	expect eof
"

cifs_delete() {
	expect -c "spawn ssh admin@$cluster_managementif_addr
		set timeout 120
		expect {Password:} { send \"${password}\\r\" }
		expect {${cluster_name}::>} { send \"vserver cifs delete -vserver $VS\\r\" }
		expect {
			{Enter the user name:} {
				send \"${AD_ADMIN}\\r\"
				expect {Enter the password:} { send \"${AD_PASSWD}\\r\" }
			}
			{Warning: There are one or more shares} {}
		}
		expect \"Do you really want to delete * shares? {y|n}:\" { send \"y\\r\" }
		expect {${cluster_name}::>} {
			send \"exit\\r\"
		}
		expect eof
	"
}

OntapInfo=/tmp/ontap2info.env
cat << EOF | tee $OntapInfo
NETAPP_NAS_HOSTNAME=${NAS_SERVER_NAME}.${AD_DOMAIN}
NETAPP_NAS_IP=$LIF1_1_ADDR
NETAPP_NAS_IP_LOC=$LIF1_0_ADDR
NETAPP_NFS_SHARE=$VOL1_JUNCTION_PATH
NETAPP_NFS_SHARE2=$VOL2_JUNCTION_PATH
NETAPP_CIFS_SHARE=$SHARENAME
NETAPP_CIFS_SHARE2=$SHARENAME2
EOF

