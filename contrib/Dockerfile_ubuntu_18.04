FROM ubuntu:18.04@sha256:017eef0b616011647b269b5c65826e2e2ebddbe5d1f8c1e56b3599fb14fabec8
COPY ubuntu_deps.sh /deps.sh
RUN /deps.sh && rm /deps.sh
VOLUME /wallycore
