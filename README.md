# ontap-simulator-in-kvm
show how to install and configure ONTAP simulator in KVM automatically

### verified host OS
Fedora-32, Fedora-33

### dependent packages install
```
#1. kiss-vm
git clone https://github.com/tcler/kiss-vm-ns; sudo make -C kiss-vm-ns; sudo vm --prepare

#2. vncdotool
sudo yum install -y python-devel
pip install vncdotool

#3. gocr
sudo yum install -y gocr

#*4. if you are non-root user, open new terminal and continue
```

### download ONTAP simulator image and license file, and convert image file to qcow2
```
# download url: https://mysupport.netapp.com/site/tools/tool-eula/simulate-ontap
# note: need log in to the NetApp Support Site athttp://mysupport-beta.netapp.com/ before download
tar vxf vsim-netapp-DOT9.7-cm_nodar.ova
for i in {1..4}; do qemu-img convert -f vmdk -O qcow2 vsim-NetAppDOT-simulate-disk${i}.vmdk vsim-NetAppDOT-simulate-disk${i}.qcow2; done
```

### change/customize your own configuration in automation script. e.g:
```
#!/bin/bash
#configure ontap simulator 9.7 as single cluster

##please change/cusotmize bellow default configration at first
vmname=ontap-single
password=fsqe2020
cluster_name=fsqe-sn-01
managementif_port=e0c
managementif_addr=10.66.12.229
managementif_mask=255.255.254.0
managementif_gateway=10.66.13.254
cluster_managementif_port=e0a
cluster_managementif_addr=192.168.100.11
cluster_managementif_mask=255.255.255.0
cluster_managementif_gateway=192.168.100.1
dns_domain=192.168.100.1
dns_addr=192.168.100.1
controller_located=raycom
```

### run the automation script. e.g: ontap-simulator-9.7-auto.sh
```
bash ontap-simulator-9.7-auto.sh
```
