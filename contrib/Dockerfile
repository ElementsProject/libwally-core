FROM debian:stretch@sha256:802706fa62e75c96fff96ada0e8ca11f570895ae2e9ba4a9d409981750ca544c
COPY stretch_deps.sh /deps.sh
RUN /deps.sh && rm /deps.sh
VOLUME /wallycore
ENV JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk-amd64
ENV ANDROID_NDK=/opt/android-ndk-r18b
