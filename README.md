# ontap-simulator-in-kvm
show how to install and configure ONTAP simulator in KVM automatically

### verified host OS list
Fedora-32, Fedora-33, RHEL-8.2.0, RHEL-8.3.0, RHEL-7.8, RHEL-7.9

### dependent packages install
```
#1. kiss-vm
git config http.postBuffer 524288000   #avoid git clone fail
git clone --depth=1 https://github.com/tcler/kiss-vm-ns; sudo make -C kiss-vm-ns; sudo vm --prepare

#*2. if you are non-root user, open new terminal and continue
```

### download ONTAP simulator image and license file, and convert image file to qcow2
```
# download url: https://mysupport.netapp.com/site/tools/tool-eula/simulate-ontap
# note: need log in to the NetApp Support Site athttp://mysupport-beta.netapp.com/ before download
tar vxf vsim-netapp-DOT9.7-cm_nodar.ova
for i in {1..4}; do
    qemu-img convert -f vmdk -O qcow2 vsim-NetAppDOT-simulate-disk${i}.vmdk vsim-NetAppDOT-simulate-disk${i}.qcow2
done
```

### run the automation script
```
git clone https://github.com/tcler/ontap-simulator-in-kvm

bash ontap-simulator-in-kvm/ontap-simulator-9.7-single-node.sh  #deploy a single node ontap cluster
#or
bash ontap-simulator-in-kvm/ontap-simulator-9.7-two-node.sh     #deploy a two node ontap cluster
```

### more examples
```
NTP_SERVER=10.5.26.10
WIN_AD_HOSTNAME=win-2016
WIN_AD_IP=${VM_EXT_IP}
DNS_DOMAIN=fstest.redhat.com
DNS_ADDR=$WIN_AD_IP
AD_HOSTNAME=$WIN_AD_HOSTNAME.fstest.redhat.com
AD_ADMIN=administrator
AD_PASS=~Ocgxyz

time ontap-simulator-in-kvm/ontap-simulator-9.7-single-node.sh \
  --node-pubaddr 10.66.61.3 --lif-pubaddr 10.66.61.6 \
  --ntp-server=$NTP_SERVER --dnsdomains=$DNS_DOMAIN --dnsaddrs=$DNS_ADDR \
  --ad-hostname=$AD_HOSTNAME --ad-ip=$AD_IP \
  --ad-admin=$AD_ADMIN --ad-passwd=$AD_PASS --ad-ip-hostonly "${VM_INT_IP}"

time ontap-simulator-in-kvm/ontap-simulator-9.7-two-node.sh \
  --node1-pubaddr 10.66.60.66 --node2-pubaddr 10.66.60.77 \
  --lif1-pubaddr 10.66.60.89 --lif2-pubaddr 10.66.60.174 \
  --ntp-server=$NTP_SERVER --dnsdomains=$DNS_DOMAIN --dnsaddrs=$DNS_ADDR \
  --ad-hostname=$AD_HOSTNAME --ad-ip=$AD_IP \
  --ad-admin=$AD_ADMIN --ad-passwd=$AD_PASS --ad-ip-hostonly "${VM_INT_IP}"
```
