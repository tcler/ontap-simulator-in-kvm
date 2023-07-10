# ontap-simulator-in-kvm
show how to install and configure ONTAP simulator in KVM automatically
```
Netapp officially only supports the installation of ONTAP simulator with VMware, 
but this requires a lot of manual operations and cannot be automated.
```

# platform requires
In order to run this script correctly, you need a **x86_64** PC or laptop with **>16G** RAM, and the OS shoud be CentOS-7/RHEL-7/Fedora-30 or higher  
(verified on Fedora-{32..36}, RHEL-8.{2..7}, RHEL-7.{8,9})

# software requires
You also need to install [kiss-vm-ns](https://github.com/tcler/kiss-vm-ns) in advance:
```
#1. kiss-vm
git clone --depth=1 https://github.com/tcler/kiss-vm-ns; sudo make -C kiss-vm-ns; sudo vm prepare

#*2. if you are non-root user, open new terminal and continue
```

# usage/steps
## download ONTAP simulator image and license file
```
# Download url: https://mysupport.netapp.com/site/tools/tool-eula/simulate-ontap
# Note: need log in to the NetApp Support Site at http://mysupport-beta.netapp.com/ before download
# `Update(2022-12-22): found some where could download the old simulator release:
#  |-> http://www.leraren.it/~gerard/download/NetApp/
#  |-> https://sysin.org/blog/netapp-ontap-9/
# ls -1 *.ova *.txt
CMode_licenses_9.9.1.txt
vsim-netapp-DOT9.9.1-cm_nodar.ova
```

## run the automation script
```
imageFile=vsim-netapp-DOT9.9.1-cm_nodar.ova
licenseFile=CMode_licenses_9.9.1.txt
git clone https://github.com/tcler/ontap-simulator-in-kvm

bash ontap-simulator-in-kvm/ontap-simulator-single-node.sh --image $imageFile --license-file $licenseFile #deploy a single node ontap cluster
#or
bash ontap-simulator-in-kvm/ontap-simulator-two-node.sh --image $imageFile --license-file $licenseFile    #deploy a two node ontap cluster
```

## more examples
```
#install windows ad VM by using kiss-vm
winVmName=win2019-ad
winIsoUrl=/path/to/windows-server-2019.iso
vm create Windows-server -n ${winVmName} -C $winIsoUrl --dsize 50 --msize 8092 \
	--win-auto=cifs-nfs \
	--win-enable-kdc \
	--win-domain ${ADDomain} --win-passwd ${ADPasswd} --force --wait

eval $(< /tmp/${winVmName}.env)
NTP_SERVER=10.5.26.10
DNS_DOMAIN=${AD_DOMAIN}
DNS_ADDR=${VM_EXT_IP}
AD_HOSTNAME=${AD_FQDN}
AD_IP=${VM_EXT_IP}
AD_ADMIN=${ADMINUSER}
AD_PASS=${ADMINPASSWORD}

licenseFile=CMode_licenses_9.9.1.txt
imageFile=vsim-netapp-DOT9.9.1-cm_nodar.ova

time ontap-simulator-in-kvm/ontap-simulator-single-node.sh \
  --image $imageFile \
  --license-file $licenseFile \
  --node-pubaddr 10.66.61.3 --lif-pubaddr 10.66.61.6 \
  --ntp-server=$NTP_SERVER --dnsdomains=$DNS_DOMAIN --dnsaddrs=$DNS_ADDR \
  --ad-hostname=$AD_HOSTNAME --ad-ip=$AD_IP \
  --ad-admin=$AD_ADMIN --ad-passwd=$AD_PASS --ad-ip-hostonly "${VM_INT_IP}"

time ontap-simulator-in-kvm/ontap-simulator-two-node.sh \
  --image $imageFile \
  --license-file $licenseFile \
  --node1-pubaddr 10.66.60.66 --node2-pubaddr 10.66.60.77 \
  --lif1-pubaddr 10.66.60.89 --lif2-pubaddr 10.66.60.174 \
  --ntp-server=$NTP_SERVER --dnsdomains=$DNS_DOMAIN --dnsaddrs=$DNS_ADDR \
  --ad-hostname=$AD_HOSTNAME --ad-ip=$AD_IP \
  --ad-admin=$AD_ADMIN --ad-passwd=$AD_PASS --ad-ip-hostonly "${VM_INT_IP}"
```
