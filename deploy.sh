#!/bin/bash
for (( c=1; c<=$1; c++ ))
do  
    rm -r /var/lib/lxc/org$c/rootfs/home/iroha_config
    cp -r iroha_config /var/lib/lxc/org$c/rootfs/home
    rm -r /var/lib/lxc/org$c/rootfs/home/basr
    cp -r basr /var/lib/lxc/org$c/rootfs/home
    /bin/bash -c "lxc-attach org$c -- chmod 777 /home/iroha_config/runirohad.sh"
    gnome-terminal -- /bin/bash -c "lxc-attach org$c -- ./home/iroha_config/runirohad.sh $c"
done

# sleep 60
for (( c=1; c<=$1; c++ ))
do  
    gnome-terminal -- /bin/bash -c "lxc-attach org$c -- python3 /home/basr/run.py 10.0.56.$c"
done

# ip route add 10.0.56.0/24 dev lxcbr0
lxc-ls -f

