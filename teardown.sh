#!/bin/bash
for (( c=1; c<=$1; c++ )) # remove 5 nodes
do  
    lxc-stop -n org$c
    lxc-destroy -n org$c
    ifconfig br-org$c down
    brctl delif br-org$c tap-org$c
    brctl delbr br-org$c
    ifconfig tap-org$c down
    tunctl -d tap-org$c
done
rm -r configfiles