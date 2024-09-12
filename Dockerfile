FROM ubuntu:22.04

RUN apt-get update
RUN apt-get install --no-install-recommends --no-install-suggests -y \
      mingw-w64 zip build-essential perl python3 xml2 pkg-config automake \
      libtool autotools-dev make g++ git ruby wget libssl-dev

WORKDIR /opt
RUN git clone https://github.com/TheWover/donut.git
WORKDIR /opt/donut
RUN make -f Makefile

WORKDIR /workdir
RUN chmod ugo+wrx /workdir
RUN ls /opt/donut
ENTRYPOINT ["/opt/donut/donut"]
