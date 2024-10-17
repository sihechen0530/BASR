#!/bin/bash

unset http_proxy
systemctl restart systemd-networkd
systemctl restart systemd-resolved
dhclient
apt update && apt upgrade -y
apt install python3-pip -y
pip3 install scapy iroha
apt install postgresql -y
echo "listen_addresses = '*'" >> /etc/postgresql/12/main/postgresql.conf
echo "host  all  all 0.0.0.0/0 md5" >> /etc/postgresql/12/main/pg_hba.conf
systemctl restart postgresql
su postgres -c "psql -c \"\password\""