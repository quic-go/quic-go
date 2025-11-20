# Testing Guide

## Running Tests

### Go 1.24

When using Go 1.24, tests require the `synctest` experiment to be enabled:

```bash
GOEXPERIMENT=synctest go test ./...
```

Or use the provided helper script:

```bash
./run-tests.sh
```

### Go 1.25+

For Go 1.25 and later, the `synctest` package is stable and no special flags are needed:

```bash
go test ./...
```

## Why GOEXPERIMENT=synctest?

The test suite uses the `testing/synctest` package for time simulation in tests. This allows tests that use `time.Sleep()` to run instantly by simulating time rather than waiting in real-time.

- **Go 1.24**: `testing/synctest` is experimental and requires `GOEXPERIMENT=synctest`
- **Go 1.25+**: `testing/synctest` is stable and works by default

## Build vs Test Requirements

- **Building**: The project includes a fallback implementation that allows building without the synctest experiment
- **Testing**: Full test suite requires the synctest experiment on Go 1.24 for time simulation features

## CI Configuration

The CI configuration (`.github/workflows/unit.yml`) automatically sets `GOEXPERIMENT=synctest` for Go 1.24 builds.
