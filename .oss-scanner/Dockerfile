FROM golang:1.27-bookworm

ENV GOTOOLCHAIN=local

# The scanner expects the checkout at /src.
COPY . /src
WORKDIR /src

# Fetch all modules and warm the build cache while the network is available.
RUN go mod download && go build ./...

# The scan runs offline.
ENV GOPROXY=off
