FROM gcr.io/oss-fuzz-base/base-builder-go:v1

COPY . $SRC/quic-go
WORKDIR $SRC/quic-go
COPY .clusterfuzzlite/build.sh $SRC/
