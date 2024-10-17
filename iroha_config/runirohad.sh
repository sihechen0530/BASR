#!/bin/bash

ip addr add 10.0.56.$1 dev eth1
ip route add 10.0.56.0/24 dev eth1
cd home/iroha_config
acc=$(echo -n "10.0.56.$1"|md5sum |cut -d" " -f1)
./irohad --config config.sample --genesis_block genesis.block --keypair_name $acc@test --overwrite_ledger --drop_state