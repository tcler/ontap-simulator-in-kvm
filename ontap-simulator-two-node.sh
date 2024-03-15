#!/bin/bash
#install and configure two inode cluster with ontap simulator 9.{7..13}

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

CPID=$$
PROG=$0
ARGS=("$@")
trap_vmpanic() {
	echo "[Error] got panic in VM, try again:";
	echo '----------------------------------------------------------------'
	VMPANIC=yes exec $PROG "${ARGS[@]}";
}
trap trap_vmpanic SIGALRM SIGUSR2
[[ "$VMPANIC" = yes ]] && {
	qemucpuOpt=--qemucpu=Icelake-Server
	PATH=/usr/libexec:$PATH qemu-kvm -cpu ?|grep -q Icelake-Server ||
		qemucpuOpt=--qemucpu=Skylake-Server
}

# command line parse
P=${0##*/}
Usage() {
	cat <<-EOF
	Usage:
	  $P --image <image-file> --license-file <license-file> [otherOPTIONs]

	Options:
	  -h, --help                         #Display this help.
	  --image <path>                     #specify image(ova) file path; e.g: --image=/path/vsim-netapp-DOT9.8-cm_nodar.ova
	  --license-file <path>              #specify the license file path; e.g: --license-file=/path/CMode_licenses_9.8.txt
	  --dnsaddrs <ip[,ip2]>              #e.g: 192.168.10.1 or 192.168.1.1,192.168.2.1
	  --dnsdomains <domain1[,domain2]>   #e.g: test.a.com or test.a.com,devel.a.com
	  --node1-pubaddr <ip>               #node1 management address for public access
	  --node2-pubaddr <ip>               #node2 management address for public access
	  --lif1-pubaddr <ip>                #default lif1.1 address for public access
	  --lif2-pubaddr <ip>                #default lif2.1 address for public access
	  --vserver-name <NetBIOS>           #NetBIOS(or host name) of vserver, used by krb5 configuring
	  --cifs-workgroup <NetBIOS>         #Workgroup Name, This parameter specifies the name of the workgroup (up to 15 characters).
	  --ad-hostname <FQDN>               #Fully Qualified Domain Name, This parameter specifies the name of window servers.
	  --ad-vm <vmname>                   #windows servers vm name.
	  --ad-ip <ip>                       #windows servers ip.
	  --ad-admin <user>                  #Active Directory admin user name
	  --ad-passwd <passwd>               #Active Directory admin password
	  --ntp-server, --time-server <addr> #ntp/time server hostname/address
	  --raw                              #Don't do any pre-configuration, after ONTAP cluster is initialized
	EOF
}

#cifs option: https://docs.netapp.com/ontap-9/index.jsp?topic=%2Fcom.netapp.doc.dot-cm-cmpr-910%2Fvserver__cifs__create.html

_at=`getopt -o h \
	--long help \
	--long image: \
	--long license-file: \
	--long dnsaddrs: \
	--long dnsdomains: \
	--long node1-pubaddr: \
	--long node2-pubaddr: \
	--long lif1-pubaddr: \
	--long lif2-pubaddr: \
	--long vserver-name: \
	--long cifs-workgroup: \
	--long ad-hostname: \
	--long ad-vm: \
	--long ad-ip: \
	--long ad-ip-hostonly: \
	--long ssh-bind-ip: \
	--long ad-admin: \
	--long ad-passwd: \
	--long ntp-server: --long time-server: \
	--long raw \
    -a -n "$0" -- "$@"`
[[ $? != 0 ]] && { exit 1; }
eval set -- "$_at"
while true; do
	case "$1" in
	-h|--help) Usage; shift 1; exit 0;;
	--image)          ImageFile=$2; shift 2;;
	--license-file)   LicenseFile=$2; shift 2;;
	--dnsaddrs)       DNS_ADDRS=$2; shift 2;;
	--dnsdomains)     DNS_DOMAINS=$2; shift 2;;
	--node1-pubaddr)  node1_managementif_addr=$2; shift 2;;
	--node2-pubaddr)  node2_managementif_addr=$2; shift 2;;
	--lif1-pubaddr)   LIF1_1_ADDR=$2; shift 2;;
	--lif2-pubaddr)   LIF2_1_ADDR=$2; shift 2;;
	--vserver-name)   NAS_SERVER_NAME=$2; shift 2;;
	--cifs-workgroup) CIFS_WORKGROUP=$2; shift 2;;
	--ad-hostname)    AD_NAME=$2; shift 2;;
	--ad-vm)          AD_VM=$2; shift 2;;
	--ad-ip)          AD_IP=$2; shift 2;;
	--ad-ip-hostonly) AD_IP_HOSTONLY=$2; SSH_BIND_IP=; shift 2;;
	--ssh-bind-ip)    SSH_BIND_IP=$2; AD_IP_HOSTONLY=; shift 2;;
	--ad-admin)       AD_ADMIN=$2; shift 2;;
	--ad-passwd)      AD_PASSWD=$2; shift 2;;
	--ntp-server|--time-server) TIME_SERVER=$2; shift 2;;
	--raw)            RAW=yes; shift 1;;
	--) shift; break;;
	esac
done

#__main__
Rundir=/tmp/ontap-simulator-t-$$
mkdir -p $Rundir
clean() { rm -rf $Rundir; }
trap "clean" EXIT

if [[ -z "$ImageFile" || -z "$LicenseFile" ]]; then
	Usage >&2
	exit 1
fi
if [[ ! -f "$ImageFile" ]]; then
	echo "{WARN} image file '${ImageFile}' does not exist." >&2
	exit 1
fi
if [[ ! -f $LicenseFile ]]; then
	echo "{WARN} license file '${LicenseFile}' does not exist." >&2
	exit 1
fi

#get ontap version
_fname=${ImageFile##*/}
ontapver=${_fname/vsim-netapp-DOT/}

#convert image file to qcow2 files
_dir=$(dirname $ImageFile); [[ ! -w "$_dir" ]] && _dir=/tmp
tar vxf $ImageFile -C $_dir || exit 1
for i in {1..4}; do
    qemu-img convert -f vmdk -O qcow2 $_dir/vsim-NetAppDOT-simulate-disk${i}.vmdk $_dir/vsim-NetAppDOT-simulate-disk${i}.qcow2
done

# install dependency
command -v ipcalc && command -v nmap || {
	sudo yum install -y ipcalc nmap
}

getIp4() {
	local ret
	local nic=$1
	local ipaddr=`ip addr show $nic`;
	ret=$(echo "$ipaddr" |
		awk '/inet .* (global|host lo)/{match($0,"inet ([0-9.]+/[0-9]+)",M); print M[1]}')

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
getDefaultGateway() { ip route show | awk '$1=="default"{print $3; exit}'; }
getIp4Mask() { local ip4="$1"; ipcalc -m $ip4 | sed 's/.*=//'; }
freeIpList() {
	local nic="$1"
	local excludeIpList="$*"
	IFS=/ read ip netmasklen < <(getIp4 $nic)
	IFS== read key netaddr < <(ipcalc -n $ip/$netmasklen)
	local scan_result=$(nmap -v -n -sn $netaddr/$netmasklen 2>/dev/null)

	if [[ -n "$excludeIpList" ]]; then
		echo "$scan_result" | awk '/host.down/{print $5}' | sed '1d;$d' |
			grep -E -v "^${excludeIpList// /|}$"
	else
		echo "$scan_result" | awk '/host.down/{print $5}' | sed '1d;$d'
	fi
}
ExcludeIpList=($AD_IP)
extconnif=$(getDefaultNic)
extNetOpt="--net-macvtap=-"
gateWay=$(getDefaultGateway)
[[ -d /sys/class/net/$extconnif/wireless ]] && {
	extconnif=virbr-kissalt
	extNetOpt="--net=kissaltnet"
	gateWay=$(getIp4 $extconnif|awk -F/ '{print $1}')
}

############################## Assert ##############################
if [[ -n "$AD_IP" ]]; then
	echo -e "Assert 1: ping windows AD server: $AD_IP ..."
	ping -c 4 $AD_IP || {
		if [[ -n "$AD_VM" ]]; then
			ipinfo=$(vm exec -v $AD_VM -u "${AD_ADMIN}:${AD_PASSWD}" -- ipconfig)
			if ! grep "\<$AD_IP\>" <<<"$ipinfo"; then
				exit 1
			fi
		else
			exit 1
		fi
	}
fi
############################## Assert ##############################

dns_domain_names() { sed -rn -e '/^search */{s///; s/( |^)local( |$)//; s/ /,/g; p}' /etc/resolv.conf; }
dns_addrs() {
	local netif="$1" _dnslist=
	if grep -q 127.0.0.53 /etc/resolv.conf; then
		_dnslist=$(systemd-resolve --status -4 ${netif} |
			awk -v RS= 'match($0, /Current DNS Server: ([^\n]+)/, M) {print M[1]}'|paste -sd ,;)
	else
		_dnslist=$(sed -rn '/^nameserver */{s///; s/ *#.*$//; p}' /etc/resolv.conf | paste -sd ,;)
	fi
	[[ -n "$_dnslist" ]] && echo $_dnslist || return 1
}

image_binarize() {
	local srcf=${1}
	local dstf=${2:-new-${srcf}}

	if command -v anytopnm >/dev/null; then
		anytopnm $srcf | ppmtopgm | pgmtopbm -threshold | pnmtopng > $dstf
	else
		local ConvertCmd="gm convert"
		! command -v gm >/dev/null && {
			if ! command -v convert >/dev/null; then
				echo "{VM:WARN} command gm or convert are needed by 'vncget' function!" >&2
				return 1
			else
				ConvertCmd=convert
			fi
		}
		$ConvertCmd $srcf -threshold 30% $dstf
	fi

	return 0
}

if ! which gocr &>/dev/null; then
	echo "{WARN} command gocr is needed" >&2
	exit 1
fi

vncget() {
	local _vncaddr=$1
	[[ -z "$_vncaddr" ]] && return 1
	vncdo -s ${_vncaddr} capture $Rundir/_screen.png
	image_binarize $Rundir/_screen.png $Rundir/_screen2.png || return 1
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
	local pattern=${1}
	local ignored_charset=${2:-ijkfwevy[|:}
	pattern=$(sed "s,[${ignored_charset}],.,g" <<<"${pattern,,}")
	grep -i "${pattern}"
}
vncwait() {
	local addr=$1
	local pattern="$2"
	local tim=${3:-1}
	local ignored_charset="$4"
	local maxloop=60
	local loop=0
	local screentext=

	echo -e "\n=> waiting: \033[1;36m$pattern\033[0m prompt ..."
	screentext=$(vncget $addr)
	if echo "$screentext"|grep -E '^(PANIC *:|vpanic)'; then
		kill -SIGALRM $CPID
	fi
	while true; do
		vncget $addr | ocrgrep "$pattern" "$ignored_charset" && break
		sleep $tim
		let loop++
		if [[ $loop = $maxloop ]]; then
			echo "{WARN}: vncwait has been waiting for more than $(bc <<< "600*$tim") seconds"
			screentext=$(vncget $addr)
			if echo "$screentext"|grep -E '^(PANIC *:|vpanic)'; then
				kill -SIGALRM $CPID
			elif echo "$screentext"|grep -E 'Waiting until daemon ktlsd starts up'; then
				kill -SIGALRM $CPID
			else
				echo "$screentext"
			fi
			loop=0
		fi
	done
}

vercmp() {
	[ $# != 3 ] && {
		usage
		return 1
	}
	vl=$1
	cmpType=$2
	vr=$3
	res=1

	[ "$vl" = "$vr" ] && eq=1
	vmax=$(echo -e "$vl\n$vr" | sort -V | tail -n 1)

	case "$cmpType" in
	=|eq) [ "$eq" = 1 ] && res=0;;
	\>|gt) [ "$eq" != 1 -a "$vl" = "$vmax" ] && res=0;;
	\<|lt) [ "$eq" != 1 -a "$vr" = "$vmax" ] && res=0;;
	\>=|ge) [ "$vl" = "$vmax" ] && res=0;;
	\<=|le) [ "$vr" = "$vmax" ] && res=0;;
	*) echo "$vl" | grep -E -q "$vr"; res=$?;;
	esac
	return $res
}

:; echo -e "\n\033[1;30m================================================================================\033[0m"
:; echo -e "\033[1;30m=> creating networks ...\033[0m"
netcluster=ontap2-ci  #e0a e0b
vm netcreate netname=$netcluster brname=br-ontap2-ci forward=
vm netls | grep -w $netcluster >/dev/null || vm netstart $netcluster

netdata=ontap2-data  #e0d #e0e
vm netcreate netname=$netdata brname=br-ontap2-data subnet=20
vm netls | grep -w $netdata >/dev/null || vm netstart $netdata

#===============================================================================
#cluster
cluster_name=fsqe-2nc1
password=fsqe2020
TIME_SERVER=${TIME_SERVER:-time.windows.com}

#===============================================================================
#node1
vmnode1=ontap-node1
node1_managementif_port=e0c
node1_managementif_addr=$node1_managementif_addr
node1_managementif_mask=$(ipcalc -m $(getIp4 $extconnif)|sed 's/.*=//')
node1_managementif_gateway=$gateWay
cluster_managementif_port=e0d
cluster_managementif_addr=192.168.20.11
cluster_managementif_mask=255.255.255.0
cluster_managementif_gateway=192.168.20.1

dns_domains=$(dns_domain_names)
[[ -n "$DNS_DOMAINS" && $dns_domains != ${DNS_DOMAINS},* ]] && dns_domains=${DNS_DOMAINS},${dns_domains}
dns_domains=$(echo "${dns_domains}"|awk -F, -v OFS=, '{if(NF>3) {print $1,$2,$3} else print}')

dns_addrs=$(dns_addrs $extconnif||dns_addrs)
[[ -n "$DNS_ADDRS" && $dns_addrs != ${DNS_ADDRS},* ]] && dns_addrs=${DNS_ADDRS},${dns_addrs}
dns_addrs=$(echo "${dns_addrs}"|awk -F, -v OFS=, '{if(NF>3) {print $1,$3,$3} else print}')
dns_addrs=${dns_addrs%,}

read controller_located _ < <(hostname -A)

:; echo -e "\n\033[1;30m================================================================================\033[0m"
:; echo -e "\033[1;30m=> [$vmnode1] start ...\033[0m"
OSV=freebsd11.2
vm create -n $vmnode1 ONTAP-simulator -i $_dir/vsim-NetAppDOT-simulate-disk1.qcow2 \
	--diskbus=ide \
	--disk=$_dir/vsim-NetAppDOT-simulate-disk{2..4}.qcow2,bus=ide \
	--net=$netcluster,e1000 --net=$netcluster,e1000 \
	${extNetOpt},e1000 \
	--net=$netdata,e1000 --net=$netdata,e1000 \
	${extNetOpt},e1000 \
	--noauto --nocloud --video auto --osv $OSV \
	--msize $((6*1024)) --cpus 2,cores=2 \
	--vncput-after-install key:enter  --force  $qemucpuOpt

read vncaddr <<<"$(vm vnc $vmnode1)"
vncaddr=${vncaddr/:/::}
[[ -z "$vncaddr" ]] && {
	echo "{WARN}: something is wrong, exit ..." >&2
	exit 1
}

echo; expect -c "spawn virsh console $vmnode1
	set timeout 8
	expect {
		-exact {Hit [Enter] to boot immediately} { send \"\\r\"; send_user \" #exit#\\n\"; exit }
		{cryptomod_fips:} { send_user \" #exit#\\n\"; exit }
	}"
vncwait ${vncaddr} "^login:" 5
[[ -z "$node1_managementif_addr" ]] &&
	node1_managementif_addr=$(vncget $vncaddr | sed -nr '/^.*https:..([0-9.]+).*$/{s//\1/; p}')
[[ -z "$node1_managementif_addr" ]] &&
	node1_managementif_addr=$(freeIpList $extconnif "${ExcludeIpList[@]}"|sort -R|tail -1)
if [[ -z "$node1_managementif_addr" ]]; then
	node1_managementif_addr=169.254.20.11
	node1_managementif_mask=16
	node1_managementif_gateway=169.254.20.1
fi
ExcludeIpList+=($node1_managementif_addr)
vncputln ${vncaddr} "admin" ""
vncputln ${vncaddr} "reboot"

vncwait ${vncaddr} ".re you sure you want to reboot node.*? .y.n.:" 5
vncputln ${vncaddr} "y"

: <<'COMM'
vncwait ${vncaddr} "Press Ctrl-C for Boot Menu." 5
vncput ${vncaddr} key:ctrl-c

vncwait ${vncaddr} "Selection (1-9)?" 5
vncputln ${vncaddr} "4"

vncwait ${vncaddr} "Zero disks, reset config and install a new file system?" 5
vncputln ${vncaddr} "yes"

vncwait ${vncaddr} "This will erase all the data on the disks, are you sure?" 5
vncputln ${vncaddr} "yes"
COMM

echo "{debug} ontapver: $ontapver"
if vercmp "$ontapver" lt 9.13; then
	echo; expect -c "spawn virsh console $vmnode1
		set timeout 120
		expect {
			-exact {Hit [Enter] to boot immediately} { send \"\\r\"; send_user \" #exit#\\n\"; exit }
			{cryptomod_fips:} { send_user \" #exit#\\n\"; exit }
		}"

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
	node1_private_ips=$(vncget $vncaddr|sed -nr '/^.*(169.254.[0-9]+.[0-9]+).*$/{s//\1/; p}'|grep -v '169\.254\.20\.')
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

	vncwait ${vncaddr} "Where is the controller located" 2
	vncputln ${vncaddr} "$controller_located"
	sleep 2
else
	echo
	expect -c 'spawn virsh console '"$vmnode1"'
		set timeout 120
		expect {
			-exact {Hit [Enter] to boot immediately} { send "\r"; }
			{cryptomod_fips:} { send_user " #missing Hit ...#\n"; }
		}
		set timeout 300
		expect -exact {Type yes to confirm and continue {yes}:} { send "yes\r"; }
		expect -re "Enter the node management interface port" { send "'${node1_managementif_port}'\r"; }
		expect -re "Enter the node management interface .. address" { send "'$node1_managementif_addr'\r"; }
		expect -re "Enter the node management interface netmask" { send "'$node1_managementif_mask'\r"; }
		expect -re "Enter the node management interface default gateway" { send "'$node1_managementif_gateway'\r"; }
		expect -re "complete cluster setup using the command line" { send "\r"; }
		expect     "create a new cluster or join an existing cluster?" { send "create\r"; }
		expect     "used as a single node cluster?" { send "no\r"; }
		expect     "Do you want to use this configuration?" { send "yes\r"; }
		expect -re "administrator.* password:" { send "'$password'\r"; }
		expect     "Retype the password:" { send "'$password'\r"; }
		expect     "Enter the cluster name:" { send "'$cluster_name'\r"; }
		expect     "Enter an additional license key" { send "\r"; }
		expect     "Enter the cluster management interface port" { send "'${cluster_managementif_port}'\r"; }
		expect -re "Enter the cluster management interface .. address" { send "'$cluster_managementif_addr'\r"; }
		expect     "Enter the cluster management interface netmask" { send "'$cluster_managementif_mask'\r"; }
		expect     "Enter the cluster management interface default gateway" { send "'$cluster_managementif_gateway'\r"; }
		expect     "Enter the DNS domain names" { send "'$dns_domains'\r"; }
		expect -re "Enter the name server .. addresses" { send "'$dns_addrs'\r"; }
		expect     "Where is the controller located" { send "'$controller_located'\r"; }
		sleep 2
		expect     "*\r" { send_user "#exit#\r"; }
		exit
	' > >(tee /tmp/.ontap2-std-console.log)
	node1_private_ips=$(sed -nr '/^.*(169.254.[0-9]+.[0-9]+).*$/{s//\1/; p}' /tmp/.ontap2-std-console.log|grep -v '169\.254\.20\.')
fi

:; echo -e "\n\033[1;36m--------------------------------------------------------------------------------\033[0m"
colorvncget $vncaddr
:; echo -e "\n\033[1;36m--------------------------------------------------------------------------------\033[0m"

:; echo -e "\n\033[1;36m=> now ssh(admin@$node1_managementif_addr and admin@$cluster_managementif_addr) is available,\n please complete other configurations in ssh session ...\033[0m"

#===============================================================================
#node2
vmnode2=ontap-node2
node2_managementif_port=e0c
node2_managementif_addr=$node2_managementif_addr
node2_managementif_mask=$(ipcalc -m $(getIp4 $extconnif)|sed 's/.*=//')
node2_managementif_gateway=$gateWay

:; echo -e "\n\033[1;30m================================================================================\033[0m"
:; echo -e "\033[1;30m=> [$vmnode2] start ...\033[0m"
vm create -n $vmnode2 ONTAP-simulator -i $_dir/vsim-NetAppDOT-simulate-disk1.qcow2 \
	--diskbus=ide \
	--disk=$_dir/vsim-NetAppDOT-simulate-disk{2..4}.qcow2,bus=ide \
	--net=$netcluster,e1000 --net=$netcluster,e1000 \
	$extNetOpt,e1000 \
	--net=$netdata,e1000 --net=$netdata,e1000 \
	$extNetOpt,e1000 \
	--noauto --nocloud --video auto --osv $OSV \
	--msize $((6*1024)) --cpus 2,cores=2 \
	--vncput-after-install "x"  --force  $qemucpuOpt

read vncaddr <<<"$(vm vnc $vmnode2)"
vncaddr=${vncaddr/:/::}
[[ -z "$vncaddr" ]] && {
	echo "{WARN}: something is wrong, exit ..." >&2
	exit 1
}

vncwait ${vncaddr} "VLO.DER>" 0.5
vncputln ${vncaddr} "setenv SYS_SERIAL_NUM 4034389-06-2"
vncputln ${vncaddr} "setenv bootarg.nvram.sysid 4034389062"
vncputln ${vncaddr} "printenv SYS_SERIAL_NUM"
vncputln ${vncaddr} "printenv bootarg.nvram.sysid"
vncputln ${vncaddr} "boot"

vncwait ${vncaddr} "^login:" 5
[[ -z "$node2_managementif_addr" ]] &&
	node2_managementif_addr=$(vncget $vncaddr | sed -nr '/^.*https:..([0-9.]+).*$/{s//\1/; p}')
[[ -z "$node2_managementif_addr" ]] &&
	node2_managementif_addr=$(freeIpList $extconnif "${ExcludeIpList[@]}"|sort -R|tail -1)
if [[ -z "$node2_managementif_addr" ]]; then
	node2_managementif_addr=169.254.20.12
	node2_managementif_mask=16
	node2_managementif_gateway=169.254.20.1
fi
ExcludeIpList+=($node2_managementif_addr)
vncputln ${vncaddr} "admin" ""
vncputln ${vncaddr} "reboot"

vncwait ${vncaddr} ".re you sure you want to reboot node.*? .y.n.:" 5
vncputln ${vncaddr} "y"

: <<'COMM'
vncwait ${vncaddr} "Press Ctrl-C for Boot Menu." 5
vncput ${vncaddr} key:ctrl-c

vncwait ${vncaddr} "Selection (1-9)?" 5
vncputln ${vncaddr} "4"

vncwait ${vncaddr} "Zero disks, reset config and install a new file system?" 5
vncputln ${vncaddr} "yes"

vncwait ${vncaddr} "This will erase all the data on the disks, are you sure?" 5
vncputln ${vncaddr} "yes"
COMM

if vercmp "$ontapver" lt 9.13; then
	echo; expect -c "spawn virsh console $vmnode2
		set timeout 120
		expect {
			-exact {Hit [Enter] to boot immediately} { send \"\\r\"; send_user \" #exit#\\n\"; exit }
			{cryptomod_fips:} { send_user \" #exit#\\n\"; exit }
		}"

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
else
	read node1_private_ip <<<"$node1_private_ips"
	expect -c 'spawn virsh console '"$vmnode2"'
		expect {
			-exact {Hit [Enter] to boot immediately} { send "\r"; }
			{cryptomod_fips:} { send_user " #missing Hit ...#\n"; }
		}
		set timeout 300
		expect -exact {Type yes to confirm and continue {yes}:} { send "yes\r"; }
		expect -re "Enter the node management interface port" { send "'${node2_managementif_port}'\r"; }
		expect -re "Enter the node management interface .. address" { send "'$node2_managementif_addr'\r"; }
		expect -re "Enter the node management interface netmask" { send "'$node2_managementif_mask'\r"; }
		expect -re "Enter the node management interface default gateway" { send "'$node2_managementif_gateway'\r"; }
		expect -re "complete cluster setup using the command line" { send "\r"; }
		expect     "create a new cluster or join an existing cluster?" { send "join\r"; }
		expect     "Do you want to use this configuration?" { send "yes\r"; }
		expect     "cluster you want to join:" { send "'$node1_private_ip'\r"; }
		expect     "This node has been joined to cluster" { send_user "#exit#\r"; }
		exit
		'
fi

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
	port-available.sh $cluster_managementif_addr 22 --wait

	nodename=${cluster_name}-0$idx
	diagpasswd=d1234567
	expect -c "spawn ssh admin@$cluster_managementif_addr
		set timeout 120
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
		set timeout 10
		expect eof
	"

	if vercmp "$ontapver" lt 9.13; then
		echo; expect -c "spawn virsh console $vmnode
			set timeout 120
			expect {
				-exact {Hit [Enter] to boot immediately} { send \"\\r\"; send_user \" #exit#\\n\"; exit }
				{cryptomod_fips:} { send_user \" #exit#\\n\"; exit }
			}"
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
	else
		expect -c 'spawn virsh console '$vmnode'
			set timeout 120
			expect {
				-exact {Hit [Enter] to boot immediately} { send "\r"; }
				{cryptomod_fips:} { send_user " #missing Hit ...#\n"; }
			}
			set timeout 300
			expect {login:} { send "admin\r"; }
			expect {*:} { send "'${password}'\r"; }
			expect {'${cluster_name}'::>} { send "cluster show\r"; }
			expect {'$nodename'  *true} { sleep 1; }
			exit
		'
	fi

	let idx++
done

for ((I=1; I <= 2; I++)); do
	nodename=${cluster_name}-0$I
	aggr0name=aggr0_${nodename//-/_}
	expect -c "spawn ssh admin@$cluster_managementif_addr
		set timeout 120
		expect {Password:} { send \"${password}\\r\" }
		expect {${cluster_name}::>} { send \"disk assign -all true -node ${nodename}\\r\" }
		expect {${cluster_name}::>} {
			send \"aggr add-disks -aggregate $aggr0name -diskcount 5\\r\"
			send \"y\\r\"
			send \"y\\r\"
		}
		while 1 {
			expect {${cluster_name}::>} { send \"aggr show -aggregate $aggr0name -fields size\\r\" }
			expect {
				{*GB} break
				{*MB} { sleep 2; continue }
			}
		}
		expect {${cluster_name}::>} { send \"vol modify -vserver ${nodename} -volume vol0 -size 4G\\r\" }
		expect {${cluster_name}::>} { send \"exit\\r\" }
		expect eof
	"
done

#don't do any pre-configuration after system initialization
if [[ -n "$RAW" ]]; then
	expect -c "spawn ssh admin@$cluster_managementif_addr
		set timeout 120
		expect {Password:} { send \"${password}\\r\" }
		expect {${cluster_name}::>} { send \"aggr show\\r\" }
		expect {${cluster_name}::>} { send \"vol show\\r\" }
		expect {${cluster_name}::>} { send \"network port show\\r\" }
		expect {${cluster_name}::>} { send \"network interface show\\r\" }
		expect {${cluster_name}::>} { send \"exit\\r\" }
		expect eof
	"
	exit
fi

for ((I=1; I <= 2; I++)); do
	nodename=${cluster_name}-0$I
	expect -c "spawn ssh admin@$cluster_managementif_addr
		set timeout 120
		expect {Password:} { send \"${password}\\r\" }
		expect {${cluster_name}::>} {
			send \"aggr create -aggregate aggr${I}_1 -node ${nodename} -disksize 9 -diskcount 28\\r\"
			send \"y\\r\"
			expect {Job succeeded: DONE} {}
		}
		expect {${cluster_name}::>} {
			send \"aggr create -aggregate aggr${I}_2 -node ${nodename} -disksize 1 -diskcount 20\\r\"
			send \"y\\r\"
			expect {Job succeeded: DONE} {}
		}
		expect {${cluster_name}::>} { send \"aggr show\\r\" }
		expect {${cluster_name}::>} { send \"exit\\r\" }
		expect eof
	"
done

getBaseLicense() { local lf=$1; awk 'BEGIN{RS="[\x0d\x0a\x0d]"} /Cluster Base license/ {printf $NF}' $lf; }
getFirstNodeLicenses() { local lf=$1; awk '$2 ~ /^[A-Z]{28}$/ && $2 ~ /ABG/ {print $2}' $lf | paste -sd,; }
getSecondNodeLicenses() { local lf=$1; awk '$2 ~ /^[A-Z]{28}$/ && $2 ~ /EZF/ {print $2}' $lf | paste -sd,; }
BaseLicense=$(getBaseLicense $LicenseFile)
FirstNodeLicenses=$(getFirstNodeLicenses $LicenseFile)
SecondNodeLicenses=$(getSecondNodeLicenses $LicenseFile)
LicenseList=$BaseLicense,$FirstNodeLicenses,$SecondNodeLicenses
expect -c "spawn ssh admin@$cluster_managementif_addr
	set timeout 120
	expect {Password:} { send \"${password}\\r\" }
	expect {${cluster_name}::>} { send \"system license add -license-code $LicenseList\\r\" }
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
testIp=$(getIp4 $extconnif|sed 's;/.*$;;')

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
[[ -z "$LIF1_1_ADDR" ]] && LIF1_1_ADDR=$(freeIpList $extconnif "${ExcludeIpList[@]}"|sort -R|head -1)
ExcludeIpList+=($LIF1_1_ADDR)
LIF1_1_MASK=$(getIp4Mask $(getIp4 $extconnif))
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
[[ -z "$LIF2_1_ADDR" ]] && LIF2_1_ADDR=$(freeIpList $extconnif "${ExcludeIpList[@]}"|sort -R|head -1)
ExcludeIpList+=($LIF2_1_ADDR)
LIF2_1_MASK=$(getIp4Mask $(getIp4 $extconnif))
LIF2_1_NODE=${cluster_name}-02
LIF2_1_PORT=e0f

[[ -z "$NAS_SERVER_NAME" ]] && {
	read A B C D N < <(getIp4 $(getDefaultNic)|sed 's;[./]; ;g')
	NAS_SERVER_NAME=ontap2-$(printf %02x%02x $C $D)
}
NAS_SERVER_FQDN=$NAS_SERVER_NAME
CIFS_WORKGROUP=${CIFS_WORKGROUP:-FSQE}
LOCAL_USER=root
LOCAL_USER_PASSWD=Sesame~0pen
cifsOption="-workgroup $CIFS_WORKGROUP"
AD_DOMAIN=${AD_NAME#*.}
[[ -n "$AD_DOMAIN" ]] && {
	cifsOption="-domain $AD_DOMAIN"
	CIFS_WORKGROUP=
	NAS_SERVER_FQDN+=.$AD_DOMAIN
}
AD_REALM=$(echo ${AD_DOMAIN} | tr [:lower:] [:upper:])
AD_ADMIN=${AD_ADMIN:-administrator}
AD_PASSWD=${AD_PASSWD:-fsqe2015!}
CIFSVOL1=cifsvol1
CIFSVOL1_AGGR=aggr1_1
CIFSVOL1_SIZE=60G
CIFSVOL1_PATH=/cifs1
SHARENAME1=cifs1

CIFSVOL2=cifsvol2
CIFSVOL2_AGGR=aggr2_1
CIFSVOL2_SIZE=60G
CIFSVOL2_PATH=/cifs2
SHARENAME2=cifs2
#ref1: https://library.netapp.com/ecmdocs/ECMP1366832/html/vserver/export-policy/create.html
#ref2: https://library.netapp.com/ecmdocs/ECMP1366832/html/vserver/export-policy/rule/create.html
#ref3: https://tcler.github.io/2017/08/24/NetApp-pnfs-mds-ds-config

port-available.sh $cluster_managementif_addr 22 --wait

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
		send \"network port broadcast-domain show -ports ${LIF1_0_NODE}:${LIF1_0_PORT} -fields failover-groups\\r\"
		expect -re {.*\s+(\S+)\s+${cluster_name}::>} {
			set failoverGroup \$expect_out(1,string)
			send \"network interface create -vserver $VS -lif $LIF1_0_NAME -service-policy default-data-files -role data -data-protocol nfs,cifs,fcache -address $LIF1_0_ADDR -netmask $LIF1_0_MASK -home-node $LIF1_0_NODE -home-port $LIF1_0_PORT -status-admin up -failover-policy system-defined -firewall-policy data -auto-revert true -failover-group \$failoverGroup\\r\"
		}
	}
	expect {${cluster_name}::>} {
		send \"network port broadcast-domain show -ports ${LIF1_1_NODE}:${LIF1_1_PORT} -fields failover-groups\\r\"
		expect -re {.*\s+(\S+)\s+${cluster_name}::>} {
			set failoverGroup \$expect_out(1,string)
			send \"network interface create -vserver $VS -lif $LIF1_1_NAME -service-policy default-data-files -role data -data-protocol nfs,cifs,fcache -address $LIF1_1_ADDR -netmask $LIF1_1_MASK -home-node $LIF1_1_NODE -home-port $LIF1_1_PORT -status-admin up -failover-policy system-defined -firewall-policy data -auto-revert true -failover-group \$failoverGroup\\r\"
		}
	}
	expect {${cluster_name}::>} {
		send \"volume create -volume $VOL2 -aggregate $VOL2_AGGR -size $VOL2_SIZE -state online -unix-permissions ---rwxrwxrwx -type RW -snapshot-policy default -foreground true -tiering-policy none -vserver $VS -junction-path $VOL2_JUNCTION_PATH -policy $PolicyName -group 0 -user 0\\r\"
	}
	expect {${cluster_name}::>} {
		send \"network port broadcast-domain show -ports ${LIF2_0_NODE}:${LIF2_0_PORT} -fields failover-groups\\r\"
		expect -re {.*\s+(\S+)\s+${cluster_name}::>} {
			set failoverGroup \$expect_out(1,string)
			send \"network interface create -vserver $VS -lif $LIF2_0_NAME -service-policy default-data-files -role data -data-protocol nfs,cifs,fcache -address $LIF2_0_ADDR -netmask $LIF2_0_MASK -home-node $LIF2_0_NODE -home-port $LIF2_0_PORT -status-admin up -failover-policy system-defined -firewall-policy data -auto-revert true -failover-group \$failoverGroup\\r\"
		}
	}
	expect {${cluster_name}::>} {
		send \"network port broadcast-domain show -ports ${LIF2_1_NODE}:${LIF2_1_PORT} -fields failover-groups\\r\"
		expect -re {.*\s+(\S+)\s+${cluster_name}::>} {
			set failoverGroup \$expect_out(1,string)
			send \"network interface create -vserver $VS -lif $LIF2_1_NAME -service-policy default-data-files -role data -data-protocol nfs,cifs,fcache -address $LIF2_1_ADDR -netmask $LIF2_1_MASK -home-node $LIF2_1_NODE -home-port $LIF2_1_PORT -status-admin up -failover-policy system-defined -firewall-policy data -auto-revert true -failover-group \$failoverGroup\\r\"
		}
	}
	expect {${cluster_name}::>} {
		send \"network route create -vserver $VS  -destination 0.0.0.0/0 -gateway $gateWay\\r\"
	}
	expect {${cluster_name}::>} {
		send \"dns create -domains $dns_domains -name-servers $dns_addrs -timeout 5 -attempts 4 -skip-config-validation -vserver $VS\\r\"
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
		send \"ntp server create -server $TIME_SERVER\\r\"
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
		send \"vserver cifs share create -share-name $SHARENAME1 -vserver $VS -path $CIFSVOL1_PATH\\r\"
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

[[ -n "$AD_DOMAIN" ]] && {
	echo -e "\033[1;30m=> Add dns entry for nas server($NAS_SERVER_NAME) in Windows AD($AD_DOMAIN) ...\033[0m"
	vm exec -v $AD_VM -u "${AD_ADMIN}:${AD_PASSWD}" -- "Add-DnsServerResourceRecordA -Name $NAS_SERVER_NAME -ZoneName $AD_DOMAIN -AllowUpdateAny -IPv4Address $LIF1_1_ADDR"
	vm exec -v $AD_VM -u "${AD_ADMIN}:${AD_PASSWD}" -- "Add-DnsServerResourceRecordA -Name $NAS_SERVER_NAME -ZoneName $AD_DOMAIN -AllowUpdateAny -IPv4Address $LIF1_0_ADDR"
	host $NAS_SERVER_NAME $AD_IP
	host $NAS_SERVER_NAME $(vm if $AD_VM)

	LogOutPut=$(expect -c "spawn ssh admin@$cluster_managementif_addr
		set timeout 120
		expect {Password:} { send \"${password}\\r\" }
		expect {${cluster_name}::>} { send \"cifs show  -vserver $VS -fields domain-workgroup\\r\" }
		expect {${cluster_name}::>} { send \"exit\\r\" }
		expect eof
		")
	NETBIOS_WIN=`echo "$LogOutPut" |grep -A 2 domain-workgroup | awk 'END{print $2}'`

	#TimeZone=$(timedatectl | awk '/Time zone:/{print $3}')
	expect -c "spawn ssh admin@$cluster_managementif_addr
	set timeout 120
	expect {Password:} { send \"${password}\\r\" }
	#expect {${cluster_name}::>} { send \"cluster date modify -timezone ${TimeZone:-America/New_York}\\r\" }
	#expect {${cluster_name}::>} { send \"cluster date modify -date \\\"$(date '+%m/%d/%Y %H:%M:%S')\\\"\\r\" }
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
	expect {${cluster_name}::>} {
		send \"kerberos interface enable -lif $LIF2_1_NAME -admin-username ${AD_ADMIN} -spn nfs/${NAS_SERVER_NAME}.${AD_DOMAIN}@${AD_REALM}\\r\"
		expect {
			{Password:} { send \"${AD_PASSWD}\\r\" }
			{${cluster_name}::>} { send \"\\r\" }
		}
	}
	expect {${cluster_name}::>} { send \"cluster date show\\rcluster date show -utc\\r\" }
	expect {${cluster_name}::>} { send \"exit\\r\" }
	expect eof
	"
	vm exec -v $AD_VM -u "${AD_ADMIN}:${AD_PASSWD}" -- '$(Get-Date).ToUniversalTime().ToString(\"yyyy/MM/dd HH:mm:ss\")'
	vm exec -v $AD_VM -u "${AD_ADMIN}:${AD_PASSWD}" -- "Set-ADComputer NFS-${NAS_SERVER_NAME} -KerberosEncryptionType AES256,AES128,DES,RC4"
}

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
NETAPP_NAS_HOSTNAME=${NAS_SERVER_FQDN}
NETAPP_NAS_IP=$LIF1_1_ADDR
NETAPP_NAS_IP_LOC=$LIF1_0_ADDR
NETAPP_NFS_SHARE=$VOL1_JUNCTION_PATH
NETAPP_NFS_SHARE2=$VOL2_JUNCTION_PATH
NETAPP_CIFS_SHARE=$SHARENAME1
NETAPP_CIFS_SHARE2=$SHARENAME2
NETAPP_CIFS_USER=$LOCAL_USER
NETAPP_CIFS_PASSWD=$LOCAL_USER_PASSWD
NETAPP_DOMAIN_WG=$NETBIOS_WIN
NETAPP_CIFS_WG=$CIFS_WORKGROUP
EOF
