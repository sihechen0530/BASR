# basr
## An Implementation of Blockchain-based AODV with Signature Routing
implementation of aodv and basr with python, lxc and ns3
for lxc usage in ns3, please look at [](https://www.nsnam.org/wiki/HOWTO_Use_Linux_Containers_to_set_up_virtual_networks)

### iroha_config
irohad: daemon for iroha
irohac-cli: client for iroha
.pub & .priv: generated public key and private key using command
	`bash iroha-cli --new_account --account_name <account name>`
	for details please look at genkey.py
runirohad.sh: script for starting iroha daemon in container

### aodv-py
python implementation of AODV

### basr
python implementation of BASR

### createlxc.sh
create linux container of ubuntu:focal

### deploy.sh
start iroha daemon and run basr

### environment.sh
initialize environment for experiment inside lxc

### teardown.sh
stop all lxc's
