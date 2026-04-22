FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

WORKDIR /build/benchmark
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/benchmark_server ./server
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/benchmark_client ./client
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/benchmark_runner ./runner
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/benchmark_comprehensive ./comprehensive_runner

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates

# Binaries that the runner expects in its CWD
WORKDIR /app
COPY --from=builder /out/benchmark_server /app/benchmark_server
COPY --from=builder /out/benchmark_client /app/benchmark_client
COPY --from=builder /out/benchmark_runner /app/benchmark_runner
COPY --from=builder /out/benchmark_comprehensive /app/benchmark_comprehensive

RUN mkdir /results

ENTRYPOINT ["/app/benchmark_runner", "-skip-build"]
CMD ["-output=/results/benchmark_results.csv"]
