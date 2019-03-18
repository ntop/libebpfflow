# libebpfflow
Traffic visibility library based on eBPF

### Introduction
libebpfflow is a traffic visibility library based on eBPF able to compute network flows. It can be used to:
* enable network visibility
* create a packet-less network probe
* inspect host and container communications

### Main features
* Ability to inspect TCP and UDP traffic
* Container visibility
* TCP latency computation
* Process and user visibility

### Requirements
You need a modern eBPF-enabled Linux distribution.

On Ubuntu 18.04 LTS you can install the prerequisites (we assume that the compiler is already installed) as follows:
```sh
$ sudo apt-get install libbpfcc-dev
```

### Usage
In order demonstrate how to use the library you can refer to the [ntopng](https://github.com/ntop/ntopng) code or inspect the code of the ebptest application.

```sh
$ sudo ./ebpftest
Welcome to libebpfflow v.1.0.190213
(C) 2018-19 ntop.org
Initializing eBPF [Legacy API]...
eBPF initializated successfully
1550096766.241662 [lo][Sent][IPv4/TCP][/][pid/tid: 23933/21802 [/usr/lib/chromium-browser/chromium-browser], uid/gid: 1000/1000][father pid/tid: 19407/0 [/usr/bin/gnome-shell], uid/gid: 1000/1000][addr: 127.0.0.1:55496 <-> 127.0.0.1:9229][latency: 0.16 msec]
1550096766.241792 [lo][Sent][IPv4/TCP][/][pid/tid: 23933/21802 [/usr/lib/chromium-browser/chromium-browser], uid/gid: 1000/1000][father pid/tid: 19407/0 [/usr/bin/gnome-shell], uid/gid: 1000/1000][addr: 127.0.0.1:34788 <-> 127.0.0.1:9229][latency: 0.12 msec]
1550096766.242167 [lo][Sent][IPv4/TCP][/][pid/tid: 23933/21802 [/usr/lib/chromium-browser/chromium-browser], uid/gid: 1000/1000][father pid/tid: 19407/0 [/usr/bin/gnome-shell], uid/gid: 1000/1000][addr: 127.0.0.1:55500 <-> 127.0.0.1:9229][latency: 0.12 msec]
1550096766.242308 [lo][Sent][IPv4/TCP][/][pid/tid: 23933/21802 [/usr/lib/chromium-browser/chromium-browser], uid/gid: 1000/1000][father pid/tid: 19407/0 [/usr/bin/gnome-shell], uid/gid: 1000/1000][addr: 127.0.0.1:34792 <-> 127.0.0.1:9229][latency: 0.09 msec]
1550096766.598306 [eth0][Sent][IPv4/UDP][/][pid/tid: 19981/19664 [/home/deri/.dropbox-dist/dropbox-lnx.x86_64-66.4.84/dropbox], uid/gid: 1000/1000][father pid/tid: 1/0 [/lib/systemd/systemd], uid/gid: 0/0][addr: 192.168.1.11:17500 <-> 255.255.255.255:17500]
1550096766.598846 [eth0][Sent][IPv4/UDP][/][pid/tid: 19981/19664 [/home/deri/.dropbox-dist/dropbox-lnx.x86_64-66.4.84/dropbox], uid/gid: 1000/1000][father pid/tid: 1/0 [/lib/systemd/systemd], uid/gid: 0/0][addr: 192.168.1.11:17500 <-> 192.168.1.127:17500]
1550096766.599092 [virbr0][Sent][IPv4/UDP][/][pid/tid: 19981/19664 [/home/deri/.dropbox-dist/dropbox-lnx.x86_64-66.4.84/dropbox], uid/gid: 1000/1000][father pid/tid: 1/0 [/lib/systemd/systemd], uid/gid: 0/0][addr: 192.168.123.1:17500 <-> 192.168.123.255:17500]
1550096766.599287 [docker0][Sent][IPv4/UDP][/][pid/tid: 19981/19664 [/home/deri/.dropbox-dist/dropbox-lnx.x86_64-66.4.84/dropbox], uid/gid: 1000/1000][father pid/tid: 1/0 [/lib/systemd/systemd], uid/gid: 0/0][addr: 172.17.0.1:17500 <-> 172.17.255.255:17500]
1550096767.244176 [lo][Sent][IPv4/TCP][/][pid/tid: 23933/21802 [/usr/lib/chromium-browser/chromium-browser], uid/gid: 1000/1000][father pid/tid: 19407/0 [/usr/bin/gnome-shell], uid/gid: 1000/1000][addr: 127.0.0.1:55504 <-> 127.0.0.1:9229][latency: 0.18 msec]
1550096767.244356 [lo][Sent][IPv4/TCP][/][pid/tid: 23933/21802 [/usr/lib/chromium-browser/chromium-browser], uid/gid: 1000/1000][father pid/tid: 19407/0 [/usr/bin/gnome-shell], uid/gid: 1000/1000][addr: 127.0.0.1:34796 <-> 127.0.0.1:9229][latency: 0.12 msec]
1550096767.244602 [lo][Sent][IPv4/TCP][/][pid/tid: 23933/21802 [/usr/lib/chromium-browser/chromium-browser], uid/gid: 1000/1000][father pid/tid: 19407/0 [/usr/bin/gnome-shell], uid/gid: 1000/1000][addr: 127.0.0.1:55508 <-> 127.0.0.1:9229][latency: 0.09 msec]
[1550096767.244773 [lo][Sent][IPv4/TCP][/][pid/tid: 23933/21802 [/usr/lib/chromium-browser/chromium-browser], uid/gid: 1000/1000][father pid/tid: 19407/0 [/usr/bin/gnome-shell], uid/gid: 1000/1000][addr: 127.0.0.1:34800 <-> 127.0.0.1:9229][latency: 0.10 msec]
1550096767.769190 [enp5s0][Rcvd][IPv4/UDP][][pid/tid: 0/0 [], uid/gid: 0/0][father pid/tid: 0/0 [], uid/gid: 0/0][addr: 192.168.99.84:138 <-> 192.168.99.255:138]
1550096767.807201 [enp5s0][Rcvd][IPv4/UDP][][pid/tid: 0/0 [], uid/gid: 0/0][father pid/tid: 0/0 [], uid/gid: 0/0][addr: 192.168.99.79:5353 <-> 224.0.0.251:5353]
1550096767.847075 [enp5s0][Rcvd][IPv4/UDP][][pid/tid: 0/0 [], uid/gid: 0/0][father pid/tid: 0/0 [], uid/gid: 0/0][addr: 192.168.96.158:5353 <-> 224.0.0.251:5353]
1550097252.240631 [eth0][S][IPv6/TCP][/][pid/tid: 23488/23455 (MTP::internal:: [/home/deri/Telegram/Telegram]), uid/gid: 1000/1000][father pid/tid: 1/0 (MTP::internal:: [/lib/systemd/systemd]), uid/gid: 0/0][addr: 2a00:d40:1:3:192:168:13:11:40430 <-> 2001:67c:4e8:f004::a:443][latency: 0.12 msec]
1550097252.241718 [eth0][S][IPv6/TCP][/][pid/tid: 29591/23455 (Qt HTTP thread [/home/deri/Telegram/Telegram]), uid/gid: 1000/1000][father pid/tid: 1/0 (Qt HTTP thread [/lib/systemd/systemd]), uid/gid: 0/0][addr: 2a00:d40:1:3:192:168:13:11:57108 <-> 2001:67c:4e8:f004::a:80][latency: 0.06 msec]
1550097255.526824 [eth0][Sent][IPv4/UDP][7109bf5e5e043fb620f91dc6fad30a1b0b8fb4eb9ed83f80b8dbf333f410f9][pid/tid: 29590/29589 [/usr/bin/curl], uid/gid: 0/0][father pid/tid: 26673/0 [/bin/bash], uid/gid: 0/0][addr: 172.17.0.2:36064 <-> 192.168.13.6:53]
1550097255.526879 [veth78452bf][Rcvd][IPv4/UDP][][pid/tid: 0/0 [], uid/gid: 0/0][father pid/tid: 0/0 [], uid/gid: 0/0][addr: 172.17.0.2:36064 <-> 192.168.13.6:53]
1550097255.526930 [eth0][Sent][IPv4/UDP][7109bf5e5e043fb620f91dc6fad30a1b0b8fb4eb9ed83f80b8dbf333f410f9][pid/tid: 29590/29589 [/usr/bin/curl], uid/gid: 0/0][father pid/tid: 26673/0 [/bin/bash], uid/gid: 0/0][addr: 192.12.193.11:36064 <-> 192.168.13.6:53]
1550097255.527515 [eth0][Rcvd][IPv4/UDP][][pid/tid: 0/0 [], uid/gid: 0/0][father pid/tid: 0/0 [], uid/gid: 0/0][addr: 192.168.13.6:53 <-> 192.12.193.11:36064]
1550097255.527531 [docker0][Sent][IPv4/UDP][/][pid/tid: 0/0 [], uid/gid: 0/0][father pid/tid: 0/0 [], uid/gid: 0/0][addr: 192.168.13.6:53 <-> 172.17.0.2:36064]
1550097255.665312 [enp5s0][Rcvd][IPv4/UDP][][pid/tid: 0/0 [], uid/gid: 0/0][father pid/tid: 0/0 [], uid/gid: 0/0][addr: 192.168.96.195:17500 <-> 255.255.255.255:17500]
1550097255.665878 [enp5s0][Rcvd][IPv4/UDP][][pid/tid: 0/0 [], uid/gid: 0/0][father pid/tid: 0/0 [], uid/gid: 0/0][addr: 192.168.96.195:17500 <-> 192.168.99.255:17500]
1550097256.034440 [eth0][Sent][IPv4/TCP][7109bf5e5e043fb620f91dc6fad30a1b0b8fb4eb9ed83f80b8dbf333f410f9][pid/tid: 29589/29589 [/usr/bin/curl], uid/gid: 0/0][father pid/tid: 26673/0 [/bin/bash], uid/gid: 0/0][addr: 172.17.0.2:54120 <-> 178.62.197.130:80][latency: 0.18 msec]
```

###go_libebpfflow
The project also offers a way to access eBPF network events through the Go programming language. A basic example is found in the file *goebpf_flow.go*, which can be compiled using the makefile from the project root.


```sh
$ make go_toolebpflow
$ sudo ./go_toolebpflow
```  

### Open Issues
While the library is already usable in production, we plan to add some additional features including:
* Add POD/K8 visibility
* Implement periodic flow stats exports including bytes/packets/retransmissions
* Add flow termination export
