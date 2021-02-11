#!/bin/bash

export LANG=C
run() {
	[[ $# -eq 0 ]] && return 0

	echo "[run]" "$@"
	"$@"
}
getDefaultIp4() {
	local nic=$1
	[[ -z "$nic" ]] &&
		nics=$(ip route | awk '/default/{match($0,"dev ([^ ]+)",M); print M[1]}')
	for nic in $nics; do
		[[ -z "$(ip -d link show  dev $nic|sed -n 3p)" ]] && {
			break
		}
	done
	local ipaddr=`ip addr show $nic`;
	local ret=$(echo "$ipaddr" |
			awk '/inet .* global dynamic/{match($0,"inet ([0-9.]+)/[0-9]+",M); print M[1]}');
	echo "$ret"
}

#-------------------------------------------------------------------------------
KissVMUrl=https://github.com/tcler/kiss-vm-ns
echo -e "installing kiss-vm ..."
git config --global http.postBuffer 5242880000  #avoid git clone fail
git clone --depth=1 "$KissVMUrl" && make -C kiss-vm-ns
which vm || {
	wget http://download.devel.redhat.com/qa/rhts/lookaside/kiss-vm-ns/kiss-vm
	mv kiss-vm /usr/bin/vm && chmod +x /usr/bin/vm
}
which netns || {
	wget http://download.devel.redhat.com/qa/rhts/lookaside/kiss-vm-ns/kiss-netns
	mv kiss-netns /usr/bin/netns && chmod +x /usr/bin/netns
}
vm --prepare >/dev/null

echo -e "creating macvlan if mv-host ..."
netns host,mv-host,dhcp


read A B C D N < <(getDefaultIp4|sed 's;[./]; ;g')
HostIPSuffix=$(printf %02x%02x $C $D)
HostIPSuffixL=$(printf %02x%02x%02x%02x $A $B $C $D)
WinVmName=win2016-${HostIPSuffix}

if true; then
#-------------------------------------------------------------------------------
#WINVER=2019
#img_name=Win2019-Evaluation.iso
#os_variant=win2k19
WINVER=2016
img_name=Win2016-Evaluation.iso
os_variant=win2k16

download_path=/home/download

echo -e "installing dependency ..."
yum install -y libvirt libvirt-client virt-install virt-viewer qemu-kvm dosfstools \
    openldap-clients dos2unix unix2dos glibc-common expect wget

mkdir -p $download_path
img_path="$download_path/$img_name"

echo -e "downloading image $img_name ..."
if [[ "$HOSTNAME" = *pek2.redhat.com ]]; then
	img_url="ftp://fs-qe.usersys.redhat.com/pub/windows-images/$img_name"
	openssh_url=ftp://fs-qe.usersys.redhat.com/pub/windows-images/OpenSSH-Win64.zip
else
	img_url="http://download.devel.redhat.com/qa/rhts/lookaside/windows-images/$img_name"
	openssh_url="http://download.devel.redhat.com/qa/rhts/lookaside/windows-images/OpenSSH-Win64.zip"
fi
wget -cq $img_url -O $img_path

echo -e "downloading make-windows-vm tool ..."
git clone https://github.com/tcler/make-windows-vm.git
osvariants=$(virt-install --os-variant list 2>/dev/null) || {
	osvariants=$(osinfo-query os)
}
grep " $os_variant" <<<"$osvariants" || {
	os_variant=$(egrep -o 'win2k12r2|win2k12|win2k16|win2k19|win2k8' <<<"$osvariants"|head -n1)
}

echo -e "openssh_url=$openssh_url\nimage_url=$img_url"
ADDomain=fsqe${HostIPSuffix}.redhat.com
ADPasswd=Sesame~0pen
opts=(--vm-name ${WinVmName} --os-variant $os_variant --disk-size 50 \
	--image $img_path --openssh=$openssh_url \
	--enable-kdc --domain ${ADDomain} -p ${ADPasswd} --force --timeout 180)
pushd make-windows-vm
echo "./make-win-vm.sh answerfiles-cifs-nfs/* ${opts[@]}"
./make-win-vm.sh answerfiles-cifs-nfs/* "${opts[@]}"
popd

fi

#-------------------------------------------------------------------------------
protocol="http"
address="download.devel.red hat.com"
path="qa/rh ts/look aside/Netapp-Simulator"
BaseUrl=${protocol// /}://${address// /}/${path// /}

ImageUrl=${BaseUrl}/vsim-netapp-DOT9.7-cm_nodar.ova
LicenseFileUrl=${BaseUrl}/CMode_licenses_9.7.txt
script=ontap-simulator-two-node.sh
minram=$((15*1024))
singlenode=$1
[[ "$singlenode" = [sy]* ]] && {
	shift
	script=ontap-simulator-single-node.sh
	minram=$((8*1024 - 512))
}
ramsize=$(free -m|awk '/Mem:/{print $2}')
[[ "$ramsize" -le "$minram" ]] && {
	echo "{WARN} total ram size(${ramsize}m) on your system is not enough(>=$minram)"
	exit 1
}

wget -c --progress=dot:giga "$ImageUrl"
tar vxf vsim-netapp-DOT9.7-cm_nodar.ova
for i in {1..4}; do
	qemu-img convert -f vmdk -O qcow2 vsim-NetAppDOT-simulate-disk${i}.vmdk vsim-NetAppDOT-simulate-disk${i}.qcow2
done

wget -c --progress=dot:giga "$LicenseFileUrl"

echo -e "installing ontap-simulator-in-kvm tool ..."
git clone --depth=1 https://github.com/tcler/ontap-simulator-in-kvm

eval $(< /tmp/${WinVmName}.env)
NTP_SERVER=10.5.26.10
DNS_DOMAIN=${AD_DOMAIN}
DNS_ADDR=${VM_EXT_IP}
AD_HOSTNAME=${AD_FQDN}
AD_IP=${VM_EXT_IP}
AD_ADMIN=${ADMINUSER}
AD_PASS=${ADMINPASSWORD}
optx=(--ntp-server=$NTP_SERVER --dnsdomains=$DNS_DOMAIN --dnsaddrs=$DNS_ADDR \
	--ad-hostname=$AD_HOSTNAME --ad-ip=$AD_IP \
	--ad-admin=$AD_ADMIN --ad-passwd=$AD_PASS --ad-ip-hostonly "${VM_INT_IP}")
ONTAP_INSTALL_LOG=/tmp/ontap2-install.log
ONTAP_IF_INFO=/tmp/ontap2-if-info.txt
bash ontap-simulator-in-kvm/$script "${optx[@]}" &> >(tee $ONTAP_INSTALL_LOG)

tac $ONTAP_INSTALL_LOG | sed -nr '/^[ \t]+lif/ {:loop /\nfsqe-[s2]nc1/!{N; b loop}; p;q}' | tac >$ONTAP_IF_INFO

################################# Assert ################################
echo -e "Assert 1: ping windows ad server: $VM_EXT_IP ..." >/dev/tty
ping -c 4 $VM_EXT_IP || {
	[[ -n "$VM_INT_IP" ]] && {
		sshOpt="-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
		expect -c "spawn ssh $sshOpt $AD_ADMIN@${VM_INT_IP} ipconfig
		expect {password:} { send \"${AD_PASSWD}\\r\" }
		"  &>/dev/tty
	}
	exit 1
}
################################# Assert ################################

#join host to ad domain(krb5 realm)
echo -e "join host to $AD_DOMAIN($AD_HOSTNAME) ..."
shorthostname=host-${HostIPSuffix}
echo $shorthostname >/etc/hostname
hostname $shorthostname
export HOSTNAME=$shorthostname
./make-windows-vm/utils/config_ad_client.sh --addc_ip $VM_INT_IP --addc_ip_ext $VM_EXT_IP -p $AD_PASS --config_krb --enctypes AES

ONTAP_ENV_FILE=/tmp/ontap2info.env
nfsmp_krb5=/mnt/nfsmp-ontap-krb5
nfsmp_krb5i=/mnt/nfsmp-ontap-krb5i
nfsmp_krb5p=/mnt/nfsmp-ontap-krb5p
eval $(< $ONTAP_ENV_FILE)
clientip=$(getDefaultIp4 mv-host)

################################# Assert ################################
echo -e "Assert 2: ping windows ad server: $VM_EXT_IP ..." >/dev/tty
ping -c 4 $VM_EXT_IP || {
	[[ -n "$VM_INT_IP" ]] && {
		sshOpt="-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
		expect -c "spawn ssh $sshOpt $AD_ADMIN@${VM_INT_IP} ipconfig
		expect {password:} { send \"${AD_PASSWD}\\r\" }
		"  &>/dev/tty
	}
	exit 1
}
################################# Assert ################################

run mkdir -p $nfsmp_krb5 $nfsmp_krb5i $nfsmp_krb5p
run mount $NETAPP_NAS_HOSTNAME:$NETAPP_NFS_SHARE2 $nfsmp_krb5 -osec=krb5,clientaddr=$clientip
run mount $NETAPP_NAS_HOSTNAME:$NETAPP_NFS_SHARE2 $nfsmp_krb5i -osec=krb5i,clientaddr=$clientip
run mount $NETAPP_NAS_HOSTNAME:$NETAPP_NFS_SHARE2 $nfsmp_krb5p -osec=krb5p,clientaddr=$clientip
run mount -t nfs4
run umount -a -t nfs4,nfs
