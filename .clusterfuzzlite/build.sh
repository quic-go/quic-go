#!/bin/bash

set -euo pipefail

# Go toolchain setup adapted from Tailscale:
# https://github.com/tailscale/tailscale/pull/21057
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# Pin the adapter to the commit used in that PR.
fuzzbuild_ref=fc5dc53b9db8a38c394c53d6e439a1410cf8fc19

# Copy downloaded toolchains out of the module cache so OSS-Fuzz can overlay
# the standard library when building fuzzers.
goroot=$(go env GOROOT)
gomodcache=$(go env GOMODCACHE)
if [[ "$goroot" == "$gomodcache"* ]]; then
	cp -r "$goroot/." "$tmpdir/goroot"
	# Toolchain files are read-only; make them writable so cleanup works for any user.
	chmod -R u+rwX "$tmpdir/goroot"
	export GOROOT="$tmpdir/goroot"
	export PATH="$GOROOT/bin:$PATH"
	export GOTOOLCHAIN=local
fi

# Rebuild the adapter with the selected Go version so it can process our source.
git clone --depth 1 https://github.com/AdamKorcz/go-118-fuzz-build "$tmpdir/v2"
(
	cd "$tmpdir/v2"
	git fetch --depth 1 origin "$fuzzbuild_ref"
	git checkout -q FETCH_HEAD
	GOFLAGS=-mod=mod go build -o "$tmpdir/bin/go-118-fuzz-build_v2" .
)
export PATH="$tmpdir/bin:$PATH"

go version
go env

build_native_go_fuzzer() {
	local pkg=$1
	local fuzz=$2
	local name=$3
	local corpus_dir="${WORK:-/tmp}/quic-go-seed-corpus/$name"
	local corpus_zip="$OUT/${name}_seed_corpus.zip"

	# FUZZ_CORPUS_DIR makes go-ossfuzz-seeds write each f.Add seed as a raw
	# libFuzzer corpus file. OSS-Fuzz picks up <fuzzer>_seed_corpus.zip from
	# $OUT and unpacks it next to the fuzzer binary.
	rm -rf "$corpus_dir"
	mkdir -p "$corpus_dir"
	FUZZ_CORPUS_DIR="$corpus_dir" go test "$pkg" -run "^${fuzz}$" -count=1 -v

	rm -f "$corpus_zip"
	corpus_files=$(find "$corpus_dir" -type f | wc -l)
	echo "$name: generated $corpus_files corpus files"
	if [[ "$corpus_files" -gt 0 ]]; then
		(cd "$corpus_dir" && zip -q -r "$corpus_zip" .)
	fi

	compile_native_go_fuzzer_v2 "$pkg" "$fuzz" "$name"
}

build_native_go_fuzzer github.com/quic-go/quic-go/internal/wire FuzzFrames frame_fuzzer_v2
build_native_go_fuzzer github.com/quic-go/quic-go/internal/wire FuzzTransportParameters transportparameter_fuzzer_v2
build_native_go_fuzzer github.com/quic-go/quic-go/http3 FuzzFrameParser http3_frame_fuzzer
build_native_go_fuzzer github.com/quic-go/quic-go/internal/wire FuzzHeaderParser header_fuzzer_v2
build_native_go_fuzzer github.com/quic-go/quic-go/internal/handshake FuzzHandshake handshake_fuzzer_v2
build_native_go_fuzzer github.com/quic-go/quic-go FuzzFrameSorter frame_sorter_fuzzer
build_native_go_fuzzer github.com/quic-go/quic-go/http3 FuzzHeaderParsing http3_header_parsing_fuzzer
