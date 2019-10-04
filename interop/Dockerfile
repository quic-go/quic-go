FROM martenseemann/quic-network-simulator-endpoint:latest

RUN apt-get update && apt-get install -y wget tar git vim python

RUN wget https://dl.google.com/go/go1.13.3.linux-amd64.tar.gz && \
  tar xfz go1.13.3.linux-amd64.tar.gz && \
  rm go1.13.3.linux-amd64.tar.gz

ENV PATH="/go/bin:${PATH}"

# build with --build-arg CACHEBUST=$(date +%s)
ARG CACHEBUST=1

RUN git clone https://github.com/lucas-clemente/quic-go && \
  cd quic-go && \
  git checkout interop && \
  go get ./...

WORKDIR /quic-go

COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh

ENTRYPOINT [ "./run_endpoint.sh" ]
