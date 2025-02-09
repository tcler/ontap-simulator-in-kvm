# ontap-simulator-in-kvm
show how to install and configure ONTAP simulator in KVM automatically
```
Netapp officially only supports the installation of ONTAP simulator with VMware, 
but this requires a lot of manual operations and cannot be automated.
```

# platform requires
In order to run this script correctly, you need a **x86_64** PC or laptop with **>16G** RAM, and the OS shoud be CentOS-7/RHEL-7/Fedora-30 or **higher**. (verified on Fedora-{32..41}, RHEL-9.{1..4}, RHEL-8.{2..10}, RHEL-7.{8,9}, Debian-12.5, openSUSE-15.5)  

**\#Note**: We can not bring up ONTAP-9.9 and higher Version on RHEL-7, So it is recommended to use the latest version of **Fedora, RHEL-9/Rocky-9/Alma-9, RHEL-8/Rocky-8/Alma-8**  
**\#[Update: 2024-03-29]** with latest [kiss-vm](https://github.com/tcler/kiss-vm-ns), we can also bring up ONTAP-13.1 on latest **Debian-12.5**, **openSUSE-15.5**  and **latest archlinux**

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
# Note: need log in to the NetApp Support Site at http://mysupport.netapp.com/ before download
# `Update(2022-12-22): found some where could download the old simulator release:
#  |-> http://www.leraren.it/~gerard/download/NetApp/
#  |-> https://sysin.org/blog/netapp-ontap-9/
# ls -1 *.ova *.txt
CMode_licenses_9.9.1.txt
vsim-netapp-DOT9.9.1-cm_nodar.ova
```

## supported ontap simulator versions:
```
9.7, 9.8, 9.9.1, 9.10.1, 9.11.1, 9.12.1, 9.13.1, 9.13.1P7, 9.14.1 9.15.1
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
- https://github.com/tcler/kiss-vm-ns/blob/master/utils/make-ontap-simulator.sh
- https://github.com/tcler/kiss-vm-ns/blob/master/utils/make-ontap-with-windows-ad.sh

## ssh login ontap cluster's managment port
ssh admin@192.168.20.11  #default passwd: fsqe2020  

## web login ontap cluster
https://192.168.20.11

