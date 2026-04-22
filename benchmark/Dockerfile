FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /build

# Copy go.mod and go.sum from parent
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binaries
WORKDIR /build/benchmark
RUN CGO_ENABLED=0 GOOS=linux go build -o /benchmark_server ./server
RUN CGO_ENABLED=0 GOOS=linux go build -o /benchmark_client ./client
RUN CGO_ENABLED=0 GOOS=linux go build -o /benchmark_runner ./runner

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

# Copy binaries
COPY --from=builder /benchmark_server /usr/local/bin/
COPY --from=builder /benchmark_client /usr/local/bin/
COPY --from=builder /benchmark_runner /usr/local/bin/

# Create results directory
RUN mkdir /results

WORKDIR /

# Default command
ENTRYPOINT ["/usr/local/bin/benchmark_runner"]
CMD ["-output=/results/benchmark_results.csv"]
