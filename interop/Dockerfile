# build on the native platform and cross-compile
FROM --platform=$BUILDPLATFORM martenseemann/quic-network-simulator-endpoint:latest AS builder

ARG BUILDPLATFORM
ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH
RUN echo "BUILDPLATFORM: ${BUILDPLATFORM}, TARGETPLATFORM: ${TARGETPLATFORM}"

RUN apt-get update && apt-get install -y wget tar git && rm -rf /var/lib/apt/lists/*

ENV GOVERSION=1.27.0

RUN platform=$(echo ${BUILDPLATFORM} | tr '/' '-') && \
  filename="go${GOVERSION}.${platform}.tar.gz" && \
  wget https://dl.google.com/go/${filename} && \
  tar xfz ${filename} && \
  rm ${filename}

ENV PATH="/go/bin:${PATH}"
ENV GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0

# build with --build-arg CACHEBUST=$(date +%s)
ARG CACHEBUST=1

COPY . /quic-go
WORKDIR /quic-go

RUN git rev-parse HEAD | tee commit.txt
RUN go build -o server -ldflags="-X github.com/quic-go/quic-go/qlog.quicGoVersion=$(git describe --always --long --dirty)" interop/server/main.go
RUN go build -o client -ldflags="-X github.com/quic-go/quic-go/qlog.quicGoVersion=$(git describe --always --long --dirty)" interop/client/main.go


FROM martenseemann/quic-network-simulator-endpoint:latest

WORKDIR /quic-go

COPY --from=builder /quic-go/commit.txt /quic-go/server /quic-go/client ./
COPY --from=builder --chmod=755 /quic-go/interop/run_endpoint.sh ./

ENTRYPOINT [ "./run_endpoint.sh" ]
