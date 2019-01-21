FROM debian:stretch@sha256:21ac5961a3038a839f6fa92ec4583c90f9eb6ca8f580598cde19d35d0f4d8fa6
COPY stretch_deps.sh /deps.sh
RUN /deps.sh && rm /deps.sh
VOLUME /wallycore
ENV JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk-amd64
ENV ANDROID_NDK=/opt/android-ndk-r19
