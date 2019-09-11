#!/bin/bash

if [ "$EUID" -ne 0 ]
then echo "Please run as root"
     exit
fi

if [ -x "/snap/bin/microk8s.kubectl" ]; then
    kubectl="/snap/bin/microk8s.kubectl"
else
    kubectl=$(which kubectl)
fi

for listNamespace in $($kubectl get namespace -o jsonpath='{.items[*].metadata.name}'); do
      for listPod in $($kubectl get pod --namespace=$listNamespace -o jsonpath='{.items[*].metadata.name}'); do

	id=`$kubectl exec $listPod --  cat /sys/class/net/eth0/iflink 2>1 /dev/null`
	if test "$id" != ""; then
	    ifname=`ip -o link|grep ^$id:|cut -d ':' -f 2|cut -d '@' -f 1|tr -d '[:blank:]'`
	    echo "$ifname   $listPod"
	fi
    done
done
