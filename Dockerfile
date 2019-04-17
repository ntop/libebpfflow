FROM ubuntu:18.04

RUN echo "deb [trusted=yes] http://repo.iovisor.org/apt/bionic bionic-nightly main" | \
  tee /etc/apt/sources.list.d/iovisor.list && \
  apt-get update -y && \
  DEBIAN_FRONTEND=noninteractive apt-get install -y bcc-tools

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libcurl4-openssl-dev libjson-c-dev libzmq3-dev

COPY toolebpflow /usr/share/

ENTRYPOINT ["/usr/share/toolebpflow"]

