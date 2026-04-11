#!/bin/bash -eu

go version
go env

compile_native_go_fuzzer_v2 github.com/quic-go/quic-go/internal/wire FuzzFrameParser frame_fuzzer
compile_native_go_fuzzer_v2 github.com/quic-go/quic-go/internal/wire FuzzTransportParameters transportparameter_fuzzer
compile_native_go_fuzzer_v2 github.com/quic-go/quic-go/http3 FuzzFrameParser http3_frame_fuzzer
compile_native_go_fuzzer_v2 github.com/quic-go/quic-go/internal/wire FuzzHeaderParser header_fuzzer
compile_go_fuzzer github.com/quic-go/quic-go/fuzzing/tokens Fuzz token_fuzzer
compile_go_fuzzer github.com/quic-go/quic-go/fuzzing/handshake Fuzz handshake_fuzzer
compile_native_go_fuzzer_v2 github.com/quic-go/quic-go/http3 FuzzRequestHeaders http3_request_headers_fuzzer
