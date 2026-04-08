FROM gcr.io/oss-fuzz-base/base-builder-go:v1

RUN go install github.com/AdamKorcz/go-118-fuzz-build@latest

RUN apt-get update && apt-get install -y make autoconf automake libtool

COPY . $SRC/quic-go
WORKDIR $SRC/quic-go
COPY .clusterfuzzlite/build.sh $SRC/
