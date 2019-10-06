#!/bin/bash

#
# Prints the veth used by running docker containers
#

if [ "$EUID" -ne 0 ]
then echo "Please run as root"
     exit
fi

echo "veth        containerId"
echo "-----------------------"

for container in $(docker ps --format '{{.Names}}'); do    
    iflink=$(docker exec -it $container bash -c 'cat /sys/class/net/eth*/iflink')
    for net in $iflink; do
	net=$(echo $net|tr -d '\r')
	veth=$(grep -l $net /sys/class/net/veth*/ifindex)
	veth=$(echo $veth|sed -e 's;^.*net/\(.*\)/ifindex$;\1;')
	echo $veth   $container
    done
done
