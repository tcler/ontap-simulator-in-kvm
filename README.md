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
for i in {1..4}; do qemu-img convert -f vmdk -O qcow2 vsim-NetAppDOT-simulate-disk${i}.vmdk vsim-NetAppDOT-simulate-disk${i}.qcow2; done
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
time ontap-simulator-in-kvm/ontap-simulator-9.7-single-node.sh --node-pubaddr 10.66.12.108 --lif-pubaddr 10.66.12.1 --ntp-server=10.5.26.10  --dnsaddrs=10.73.4.201 --dnsdomains=rhts.eng.pek2.redhat.com --ad-domain=rhts.eng.pek2.redhat.com --ad-admin=administrator --ad-passwd=Hello2020~

time ontap-simulator-in-kvm/ontap-simulator-9.7-two-node.sh --node1-pubaddr 10.66.12.176 --node2-pubaddr 10.66.12.160 --lif1-pubaddr 10.66.12.4 --lif2-pubaddr 10.66.12.5 --ntp-server=10.5.26.10  --dnsaddrs=10.73.4.201 --dnsdomains=rhts.eng.pek2.redhat.com --ad-domain=rhts.eng.pek2.redhat.com --ad-admin=administrator --ad-passwd=Hello2020~
```
