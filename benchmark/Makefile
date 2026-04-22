.PHONY: build clean run-local test run-custom run-classic run-pqc \
        run-comprehensive test-comprehensive \
        test-1kb test-5kb test-10kb test-100kb test-500kb test-1mb test-all-sizes \
        docker-build docker-run analyze help

# Default target
.DEFAULT_GOAL := help

# Build all binaries
build:
	@echo "Building benchmark binaries..."
	@cd server && go build -o ../benchmark_server .
	@cd client && go build -o ../benchmark_client .
	@cd runner && go build -o ../benchmark_runner .
	@cd comprehensive_runner && go build -o ../benchmark_comprehensive .
	@echo "Build complete!"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -f benchmark_server benchmark_client benchmark_runner benchmark_comprehensive
	@rm -f benchmark_results.csv comprehensive_results.csv
	@rm -rf qemu-images
	@echo "Clean complete!"

# Run benchmarks locally (native)
run-local: build
	@echo "Running benchmarks locally..."
	@./benchmark_runner \
		-iterations=10 \
		-size=1048576 \
		-security=768 \
		-output=benchmark_results.csv

# Run quick test (fewer iterations)
test: build
	@echo "Running quick benchmark test..."
	@./benchmark_runner \
		-iterations=3 \
		-size=1048576 \
		-security=768 \
		-output=benchmark_results_test.csv

# Run with specific parameters
run-custom: build
	@echo "Running custom benchmark..."
	@./benchmark_runner \
		-iterations=$(ITERATIONS) \
		-size=$(SIZE) \
		-security=$(SECURITY) \
		-output=$(OUTPUT)

# Run only classic benchmarks
run-classic: build
	@./benchmark_runner -classic=true -pqc=false -output=benchmark_classic.csv

# Run only PQC benchmarks
run-pqc: build
	@./benchmark_runner -classic=false -pqc=true -output=benchmark_pqc.csv

# Run comprehensive benchmark (all security levels)
run-comprehensive: build
	@echo "Running comprehensive benchmark (all security levels)..."
	@./benchmark_comprehensive \
		-iterations=10 \
		-size=1048576 \
		-output=comprehensive_results.csv

# Run comprehensive quick test
test-comprehensive: build
	@echo "Running comprehensive quick test..."
	@./benchmark_comprehensive \
		-iterations=3 \
		-size=1048576 \
		-output=comprehensive_results_test.csv

# Size-segmented comprehensive benchmarks (default: 50 iterations)
ITERATIONS ?= 50

# 1KB test
test-1kb: build
	@echo "Running comprehensive test with 1KB data size ($(ITERATIONS) iterations)..."
	@./benchmark_comprehensive \
		-iterations=$(ITERATIONS) \
		-size=1024 \
		-output=comprehensive_results_1kb.csv

# 5KB test
test-5kb: build
	@echo "Running comprehensive test with 5KB data size ($(ITERATIONS) iterations)..."
	@./benchmark_comprehensive \
		-iterations=$(ITERATIONS) \
		-size=5120 \
		-output=comprehensive_results_5kb.csv

# 10KB test
test-10kb: build
	@echo "Running comprehensive test with 10KB data size ($(ITERATIONS) iterations)..."
	@./benchmark_comprehensive \
		-iterations=$(ITERATIONS) \
		-size=10240 \
		-output=comprehensive_results_10kb.csv

# 100KB test
test-100kb: build
	@echo "Running comprehensive test with 100KB data size ($(ITERATIONS) iterations)..."
	@./benchmark_comprehensive \
		-iterations=$(ITERATIONS) \
		-size=102400 \
		-output=comprehensive_results_100kb.csv

# 500KB test
test-500kb: build
	@echo "Running comprehensive test with 500KB data size ($(ITERATIONS) iterations)..."
	@./benchmark_comprehensive \
		-iterations=$(ITERATIONS) \
		-size=512000 \
		-output=comprehensive_results_500kb.csv

# 1MB test
test-1mb: build
	@echo "Running comprehensive test with 1MB data size ($(ITERATIONS) iterations)..."
	@./benchmark_comprehensive \
		-iterations=$(ITERATIONS) \
		-size=1048576 \
		-output=comprehensive_results_1mb.csv

# Run all size tests sequentially
test-all-sizes: build
	@echo "Running comprehensive tests across all data sizes ($(ITERATIONS) iterations each)..."
	@echo ""
	@echo "=== Test 1/6: 1KB ==="
	@$(MAKE) test-1kb ITERATIONS=$(ITERATIONS)
	@echo ""
	@echo "=== Test 2/6: 5KB ==="
	@$(MAKE) test-5kb ITERATIONS=$(ITERATIONS)
	@echo ""
	@echo "=== Test 3/6: 10KB ==="
	@$(MAKE) test-10kb ITERATIONS=$(ITERATIONS)
	@echo ""
	@echo "=== Test 4/6: 100KB ==="
	@$(MAKE) test-100kb ITERATIONS=$(ITERATIONS)
	@echo ""
	@echo "=== Test 5/6: 500KB ==="
	@$(MAKE) test-500kb ITERATIONS=$(ITERATIONS)
	@echo ""
	@echo "=== Test 6/6: 1MB ==="
	@$(MAKE) test-1mb ITERATIONS=$(ITERATIONS)
	@echo ""
	@echo "✅ All size tests complete!"
	@echo "Results: comprehensive_results_{1kb,5kb,10kb,100kb,500kb,1mb}.csv"

# Build Docker image with Alpine Linux
docker-build:
	@echo "Building Docker image..."
	@docker build -t quic-pqc-benchmark:latest -f Dockerfile ..
	@echo "Docker image built!"

# Run in Docker container
docker-run: docker-build
	@echo "Running benchmarks in Docker..."
	@docker run --rm \
		-v $(PWD)/results:/results \
		quic-pqc-benchmark:latest \
		-iterations=10 \
		-output=/results/benchmark_results.csv

# Analyze results
analyze:
	@echo "=== Benchmark Results Analysis ==="
	@if [ -f benchmark_results.csv ]; then \
		echo ""; \
		echo "Total tests:"; \
		tail -n +2 benchmark_results.csv | wc -l; \
		echo ""; \
		echo "Classic mode results:"; \
		grep "^classic," benchmark_results.csv | wc -l; \
		echo ""; \
		echo "PQC mode results:"; \
		grep "^pqc," benchmark_results.csv | wc -l; \
		echo ""; \
		echo "Average throughput (Classic):"; \
		awk -F, '$$1=="classic" && NF>6 {sum+=$$7; count++} END {if(count>0) print sum/count " Mbps"; else print "No data"}' benchmark_results.csv; \
		echo ""; \
		echo "Average throughput (PQC):"; \
		awk -F, '$$1=="pqc" && NF>6 {sum+=$$7; count++} END {if(count>0) print sum/count " Mbps"; else print "No data"}' benchmark_results.csv; \
	else \
		echo "No results file found. Run 'make run-local' first."; \
	fi

# Help target
help:
	@echo "QUIC PQC Benchmark Makefile"
	@echo ""
	@echo "Basic Targets:"
	@echo "  make build                - Build all binaries"
	@echo "  make clean                - Clean build artifacts"
	@echo "  make run-local            - Run benchmarks locally"
	@echo "  make test                 - Run quick test (3 iterations)"
	@echo "  make run-classic          - Run only classic benchmarks"
	@echo "  make run-pqc              - Run only PQC benchmarks"
	@echo ""
	@echo "Comprehensive Tests (all security levels):"
	@echo "  make run-comprehensive    - Full test (10 iterations, 1MB)"
	@echo "  make test-comprehensive   - Quick test (3 iterations, 1MB)"
	@echo ""
	@echo "Size-Segmented Tests (all security levels, default: 50 iterations):"
	@echo "  make test-1kb             - Test with 1KB data size"
	@echo "  make test-5kb             - Test with 5KB data size"
	@echo "  make test-10kb            - Test with 10KB data size"
	@echo "  make test-100kb           - Test with 100KB data size"
	@echo "  make test-500kb           - Test with 500KB data size"
	@echo "  make test-1mb             - Test with 1MB data size"
	@echo "  make test-all-sizes       - Run all sizes sequentially"
	@echo ""
	@echo "Other Targets:"
	@echo "  make docker-build         - Build Docker image (multi-stage: Go builder + Alpine runtime)"
	@echo "  make docker-run           - Build image and run benchmarks inside container"
	@echo "  make analyze              - Analyze benchmark_results.csv"
	@echo "  make help                 - Show this help"
	@echo ""
	@echo "Configurable Parameters:"
	@echo "  ITERATIONS=N              - Number of iterations per test (default: 10)"
	@echo ""
	@echo "Examples:"
	@echo "  make test                                    # Quick test"
	@echo "  make test-comprehensive                      # Test all security levels (quick)"
	@echo "  make test-all-sizes ITERATIONS=3             # Test all sizes with 3 iterations"
	@echo "  make test-100mb ITERATIONS=20                # Test 100MB with 20 iterations"
	@echo "  make run-custom ITERATIONS=50 SIZE=52428800  # Custom benchmark"
