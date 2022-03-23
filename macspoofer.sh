#!/bin/bash

sudo apt install macchanger

sudo apt install net-tools

sudo service NetworkManager stop; sleep 5;

# Get list of network interfaces. Excludes loopback and virtual machine interfaces.
interfaces=$(ls /sys/class/net | grep -v 'lo' | grep -v 'tun0' | grep -v "virbr")

#turn the interfaces off
for i in ${interfaces}
do

  sudo ifconfig $i down

done
# Spoof the MAC address of each.
for i in ${interfaces}
do

 sudo macchanger -e $i >/dev/null # Hide the output so it can't be discovered with systemd logs.
done

for i in ${interfaces}
do

  sudo ifconfig $i up

done

sudo service NetworkManager start;

echo "done"

sleep 5;


