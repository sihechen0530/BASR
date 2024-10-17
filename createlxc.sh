#!/bin/bash
rm -r configfiles
mkdir configfiles
for (( c=1; c<=$1; c++ ))
do  
    echo "lxc.uts.name = org$c" >> configfiles/org$c.conf
    echo "lxc.net.0.type = veth" >> configfiles/org$c.conf
    echo "lxc.net.0.flags = up" >> configfiles/org$c.conf
    echo "lxc.net.0.link = lxcbr0" >> configfiles/org$c.conf
    echo "lxc.net.1.type = veth" >> configfiles/org$c.conf
    echo "lxc.net.1.flags = up" >> configfiles/org$c.conf
    echo "lxc.net.1.link = br-org$c" >> configfiles/org$c.conf
    echo "lxc.apparmor.profile = unconfined" >> configfiles/org$c.conf
    echo "lxc.cgroup.devices.allow=a" >> configfiles/org$c.conf
    echo "lxc.mount.auto=proc:rw sys:rw" >> configfiles/org$c.conf
    brctl addbr "br-org$c"
    tunctl -t tap-org$c
    ifconfig tap-org$c 0.0.0.0 promisc up
    brctl addif br-org$c tap-org$c
    ifconfig br-org$c up
    brctl show
    lxc-create -f configfiles/org$c.conf -t download -n org$c -- --server mirrors.tuna.tsinghua.edu.cn/lxc-images -d ubuntu -r focal -a amd64
    lxc-start org$c
    cp environment.sh /var/lib/lxc/org$c/rootfs/home/
    /bin/bash -c "lxc-attach org$c -- chmod 777 /home/environment.sh"
    gnome-terminal -- /bin/bash -c "lxc-attach org$c -- ./home/environment.sh"
done
