FROM ubuntu:19.04@sha256:d7f038fcfc5acdc73b7ec864537827085a17970fde9e8d2a7049b4f9d9c1d57a
COPY ubuntu_deps.sh /deps.sh
RUN /deps.sh && rm /deps.sh
VOLUME /wallycore
