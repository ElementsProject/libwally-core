FROM ubuntu:20.04 as build-stage
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y
# Install build dependencies
RUN apt-get install -y git
RUN apt-get install -y build-essential
RUN apt-get install -y python python3
RUN apt-get install -y autoconf automake libtool
RUN apt-get install -y libc++-10-dev libc++abi-10-dev
RUN apt-get install -y lsb-release wget software-properties-common
RUN wget https://apt.llvm.org/llvm.sh
RUN chmod +x llvm.sh
RUN ./llvm.sh 10  # version 10
# Build libwally-core
COPY . /libwally-core
WORKDIR /libwally-core
RUN git submodule update --init --recursive
ENV CC="clang-10" CXX="clang++-10"
RUN ./tools/autogen.sh
RUN ./configure --disable-clear-tests
RUN make
RUN make check
