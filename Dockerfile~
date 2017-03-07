FROM ubuntu:14.04
COPY apt.conf /etc/apt/apt.conf
RUN apt-get update
RUN apt-get -y install python-dev python ipython python-crypto
WORKDIR /tmp/src
