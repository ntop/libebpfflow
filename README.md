# libebpfflow
Traffic visibility library based on eBPF

### Introduction
libebpfflow is a traffic visibility library based on eBPF able to compute network flows. It can be used to:
* enable network visibility
* create a packet-less network probe
* inspect host and container communications for different container runtimes

### Main features
* Ability to inspect TCP and UDP traffic
* Container visibility
* TCP latency computation
* Process and user visibility

### Supported Languages
* Golang
* C/C++
 
### Requirements
You need a modern eBPF-enabled Linux distribution.

On Ubuntu 16.04/18.04 LTS you can install the prerequisites (we assume that the compiler is already installed) as follows:
```sh
$ sudo apt-get install build-essential autoconf automake autogen libjson-c-dev pkg-config libzmq3-dev libcurl4-openssl-dev libbpfcc-dev
```

### Build
Library only
```sh
$ make libebpfflow.a
```
Library and ebpflowexport
```sh
$ make
```
Go testing tool
```sh
make go_ebpflowexport
```

### Testing
The library comes with two different tools: *ebpflowexport* and *go\_ebpflowexport*. In the _Build_ section is reported how to build the tools. Although both tools were developed to show potential library usage and to provide guidance on how to use the library, *ebpflowexport* displays all the information provided by *libebpfflow* and provides some options for filtering flow events while *go\_ebpflowexport* displays only basic information concerning events.
```sh
$ sudo ./ebpflowexport -h
ebpflowexport: Traffic visibility tool based on libebpfflow. By default all events will be shown 
Usage: ebpflow [ OPTIONS ] 
   -h, --help      display this message 
   -t, --tcp       TCP events 
   -u, --udp       UDP events 
   -i, --in        incoming events (i.e. TCP accept and UDP receive) 
   -o, --on        outgoing events (i.e. TCP connect and UDP send) 
   -r, --retr      retransmissions events 
   -c, --tcpclose  TCP close events 
   -d, --docker    gather additional information concerning containers (default: enabled)
   -v, --verbose   vebose formatting (default: every event is shown) 
Note: please run as root 
```
What follows is a demostration of the execution of *ebpflowexport* in a system where both minikube with containerd as runtime and docker containers are running at the same time.
```sh
$ sudo ./ebpflowexport -tio
Welcome to ebpflowexport v.1.0.190407
(C) 2018-19 ntop.org
Initializing eBPF [Legacy API]...
eBPF initializated successfully
1554803923.684786 [lo][Sent][IPv4/TCP][pid/tid: 1446/496 [/usr/bin/kubelet], uid/gid: 0/0][father pid/tid: 1/0 [/lib/systemd/systemd], uid/gid: 0/0][addr: 127.0.0.1:53790 <-> 127.0.0.1:10252][latency: 0.10 msec]
1554803923.685139 [lo][Rcvd][IPv4/TCP][pid/tid: 2554/2329 [/usr/local/bin/kube-controller-manager], uid/gid: 0/0][father pid/tid: 2295/0 [/usr/local/bin/containerd-shim], uid/gid: 0/0][addr: 127.0.0.1:53790 <-> 127.0.0.1:10252][containerID: 275d71585e03][runtime: containerd][kube_pod: kube-controller-manager-minikube][kube_ns: kube-system][latency: 0.00 msec]
1554803924.781354 [eth0][Sent][IPv4/TCP][pid/tid: 30197/30197 [/usr/bin/curl], uid/gid: 0/0][father pid/tid: 26219/0 [/bin/bash], uid/gid: 0/0][addr: 172.17.0.2:54348 <-> 216.58.205.46:80][containerID: cbd2540ec5be][runtime: docker][docker_name: sleepy_haibt][latency: 0.22 msec]
1554803929.257494 [enp0s3][Sent][IPv4/TCP][pid/tid: 30221/30221 [/usr/lib/apt/methods/http], uid/gid: 104/65534][father pid/tid: 30216/0 [/usr/bin/apt], uid/gid: 0/0][addr: 10.0.2.15:37140 <-> 91.189.88.162:80][latency: 0.17 msec]
```
A basic example of usage in c++ can be found in the directory */examples* whereas for the Go language the example provided is the one in */go/ebpf_flow.go*. More details on how to use the library you can be found in the [ntopng](https://github.com/ntop/ntopng) code or by inspecting the code of the tool ebpflowexport application.

### Export eBPF Information to ntopng
Supposing to start both ebpflowexport and ntopng on the same host do

- ntopng -i tcp://127.0.0.1:1234
- ebpflowexport -z tcp://127.0.0.1:1234


### Start as a Docker container
To use ebpflowexport as a Docker container first you have to build the tool. Once the tool has been built, build the docker image from the project root:
```sh
$ docker build -t ebpflowexport .
```
The container can then be run
```sh
$ docker run -it --rm --privileged \
  -v /lib/modules:/lib/modules:ro \
  -v /usr/src:/usr/src:ro \
  -v /etc/localtime:/etc/localtime:ro \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /snap/bin/microk8s.ctr:/snap/bin/microk8s.ctr \
  ebpflowexport
```

### Open Issues
While the library is already usable in production, we plan to add some additional features including:
* Implement periodic flow stats exports including bytes/packets/retransmissions

