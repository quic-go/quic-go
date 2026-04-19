#!/bin/bash

go version
go env

(
# fuzz qpack
cd $GOPATH/src/github.com/quic-go/qpack

compile_native_go_fuzzer_v2 github.com/quic-go/qpack FuzzDecode qpack_decode_fuzzer
)

(
# fuzz quic-go
cd $GOPATH/src/github.com/quic-go/quic-go/

compile_native_go_fuzzer_v2 github.com/quic-go/quic-go/internal/wire FuzzFrameParser frame_fuzzer
compile_native_go_fuzzer_v2 github.com/quic-go/quic-go/internal/wire FuzzTransportParameters transportparameter_fuzzer
compile_native_go_fuzzer_v2 github.com/quic-go/quic-go/http3 FuzzFrameParser http3_frame_fuzzer
compile_native_go_fuzzer_v2 github.com/quic-go/quic-go/internal/wire FuzzHeaderParser header_fuzzer
compile_go_fuzzer github.com/quic-go/quic-go/fuzzing/handshake Fuzz handshake_fuzzer
compile_native_go_fuzzer_v2 github.com/quic-go/quic-go/http3 FuzzHeaderParsing http3_header_parsing_fuzzer

if [ $SANITIZER == "coverage" ]; then
    # no need for corpora if coverage
    exit 0
fi

# generate seed corpora
go generate -x ./fuzzing/...

zip --quiet -r $OUT/handshake_fuzzer_seed_corpus.zip fuzzing/handshake/corpus
)

# for debugging
ls -al $OUT
