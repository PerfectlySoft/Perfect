FROM ubuntu:20.04
RUN apt-get update -y
RUN apt-get install -y wget
WORKDIR /tmp
ARG arch
COPY ./${arch}.url.txt /tmp/url.txt
RUN rm -rf /tmp/sw*
RUN wget -O /tmp/swift.tgz $(cat /tmp/url.txt)
RUN cd /tmp && tar xf /tmp/swift.tgz && rm -rf /tmp/swift.tgz && mv $(ls|grep swift) /tmp/swift/
RUN cd /tmp/swift/usr/ && tar cf /tmp/sw.tar *
RUN cd /usr && tar xf /tmp/sw.tar
RUN rm -rf /tmp/sw*
RUN apt-get update -y
RUN apt-get install -y build-essential clang wget
RUN apt-get install -y libcurl4-openssl-dev uuid-dev
RUN apt-get install -y libsqlite3-dev libncurses-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libxml2-dev
