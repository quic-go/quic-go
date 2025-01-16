FROM gcr.io/oss-fuzz-base/base-builder-go:v1

ARG TARGETPLATFORM
RUN echo "TARGETPLATFORM: ${TARGETPLATFORM}"

ENV GOVERSION=1.24.0

RUN platform=$(echo ${TARGETPLATFORM} | tr '/' '-') && \
  filename="go${GOVERSION}.${platform}.tar.gz" && \
  wget https://dl.google.com/go/${filename} && \
  mkdir temp-go && \
  rm -rf /root/.go/* && \
  tar -C temp-go/ -xzf ${filename} && \
  mv temp-go/go/* /root/.go/ && \
  rm -r ${filename} temp-go

RUN apt-get update && apt-get install -y make autoconf automake libtool

COPY . $SRC/quic-go
WORKDIR quic-go
COPY .clusterfuzzlite/build.sh $SRC/
