###Build
Before building the example libebpfflow.a must be build from the project root.
Once libebpfflow.a has been built, the example can be build with g++.
```sh
$ g++ usage_libebpfflow.cpp -o example ../../libebpfflow.a -lbcc -ljson-c -lcurl
```

###Usage
```
$ sudo ./example
```
