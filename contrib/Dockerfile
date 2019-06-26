FROM debian:stretch@sha256:2b20d1b80dbcdef98ff4e747109c39d2b91539f7f12d7873fdd452306eddb04d
COPY stretch_deps.sh /deps.sh
RUN /deps.sh && rm /deps.sh
VOLUME /wallycore
ENV JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk-amd64
ENV ANDROID_NDK=/opt/android-ndk-r20
