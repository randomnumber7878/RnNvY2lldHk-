#!/bin/bash
RANDOM_PORT=$(( ( RANDOM % 1000 ) + 9000 ))
echo "Generated random port: $RANDOM_PORT"
sudo echo "HiddenServiceDir /var/lib/tor/hidden_service/" >> /etc/tor/torrc
sudo echo "HiddenServicePort $RANDOM_PORT 127.0.0.1:$RANDOM_PORT" >> /etc/tor/torrc
sudo systemctl restart tor
sleep 5
echo "Onion service created on port: $RANDOM_PORT"
echo "Onion address:"
sudo cat /var/lib/tor/hidden_service/hostname
