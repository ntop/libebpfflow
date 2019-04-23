# pid2veth
print the name of the virtual Ethernet associated with a container given the pid of a task in it.
### Build
```sh
$ make
```
### Testing
Start a container and get the pid of a process in it.
```sh
$ sudo docker run --name=pid2veth_test -id ubuntu
2c93a6cf1e9719ef1c842981ae4efaae37b684fe67f4f3eace4e09cba2c6c2d3
$ docker ps -q | xargs docker inspect --format '[Name:{{.Name}}][Pid:{{.State.Pid}}][ID:{{.ID}}]'
[Name:/pid2veth_test][Pid:13033][ID:2c93a6cf1e97]
```
Build and execute pid2veth.
```sh
$ sudo ./pid2veth 13033
veth0eb3759
```


