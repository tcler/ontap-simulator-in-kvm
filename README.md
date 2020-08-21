# ontap-simulator-in-kvm
show how to install and configure ONTAP simulator in KVM automatically

### verified host OS
Fedora-32, Fedora-33

### dependent packages install
```
#1. kiss-vm
git clone https://github.com/tcler/kiss-vm-ns; sudo make -C kiss-vm-ns; sudo vm --prepare

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
