#!/bin/bash -eu

go version
go env

compile_native_go_fuzzer_v2 github.com/quic-go/quic-go/internal/wire FuzzFrames frame_fuzzer
compile_native_go_fuzzer_v2 github.com/quic-go/quic-go/internal/wire FuzzTransportParameters transportparameter_fuzzer
compile_native_go_fuzzer_v2 github.com/quic-go/quic-go/http3 FuzzFrameParser http3_frame_fuzzer
compile_native_go_fuzzer_v2 github.com/quic-go/quic-go/internal/wire FuzzHeaderParser header_fuzzer
compile_native_go_fuzzer_v2 github.com/quic-go/quic-go/internal/handshake FuzzHandshake handshake_fuzzer
compile_native_go_fuzzer_v2 github.com/quic-go/quic-go/http3 FuzzHeaderParsing http3_header_parsing_fuzzer
