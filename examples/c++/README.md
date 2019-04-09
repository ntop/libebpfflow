### Build
Before building the example libebpfflow.a must be built from the project root.
The example can be built with g++.
```sh
$ g++ usage_libebpfflow.cpp -o example ../../libebpfflow.a -lbcc -ljson-c -lcurl
```

### Usage
```
$ sudo ./example
```
