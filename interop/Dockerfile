FROM martenseemann/quic-network-simulator-endpoint:latest AS builder

RUN apt-get update && apt-get install -y wget tar git

RUN wget https://dl.google.com/go/go1.20.linux-amd64.tar.gz && \
  tar xfz go1.20.linux-amd64.tar.gz && \
  rm go1.20.linux-amd64.tar.gz

ENV PATH="/go/bin:${PATH}"

# build with --build-arg CACHEBUST=$(date +%s)
ARG CACHEBUST=1

RUN git clone https://github.com/quic-go/quic-go && \
  cd quic-go && \
  git fetch origin interop && git checkout -t origin/interop && \
  go get ./...

WORKDIR /quic-go

RUN git rev-parse HEAD > commit.txt
RUN go build -o server -ldflags="-X github.com/quic-go/quic-go/qlog.quicGoVersion=$(git describe --always --long --dirty)" interop/server/main.go
RUN go build -o client -ldflags="-X github.com/quic-go/quic-go/qlog.quicGoVersion=$(git describe --always --long --dirty)" interop/client/main.go


FROM martenseemann/quic-network-simulator-endpoint:latest

WORKDIR /quic-go

COPY --from=builder /quic-go/commit.txt /quic-go/server /quic-go/client ./

COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh

ENTRYPOINT [ "./run_endpoint.sh" ]
