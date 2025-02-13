FROM martenseemann/quic-network-simulator-endpoint:latest AS builder

ARG TARGETPLATFORM
RUN echo "TARGETPLATFORM: ${TARGETPLATFORM}"

RUN apt-get update && apt-get install -y wget tar git

ENV GOVERSION=1.24.0

RUN platform=$(echo ${TARGETPLATFORM} | tr '/' '-') && \
  filename="go${GOVERSION}.${platform}.tar.gz" && \
  wget https://dl.google.com/go/${filename} && \
  tar xfz ${filename} && \
  rm ${filename}

ENV PATH="/go/bin:${PATH}"

# build with --build-arg CACHEBUST=$(date +%s)
ARG CACHEBUST=1

# build other branches / commits / tags using --build-arg GITREF="<git reference>"
ARG GITREF="master"

RUN git clone https://github.com/quic-go/quic-go
WORKDIR /quic-go
RUN git checkout ${GITREF}
RUN go get ./...

RUN git rev-parse HEAD | tee commit.txt
RUN go build -o server -ldflags="-X github.com/quic-go/quic-go/qlog.quicGoVersion=$(git describe --always --long --dirty)" interop/server/main.go
RUN go build -o client -ldflags="-X github.com/quic-go/quic-go/qlog.quicGoVersion=$(git describe --always --long --dirty)" interop/client/main.go


FROM martenseemann/quic-network-simulator-endpoint:latest

WORKDIR /quic-go

COPY --from=builder /quic-go/commit.txt /quic-go/server /quic-go/client ./

COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh

ENTRYPOINT [ "./run_endpoint.sh" ]
