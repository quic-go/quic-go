#!/bin/bash

go version
go env

(
# fuzz qpack
compile_go_fuzzer github.com/quic-go/qpack/fuzzing Fuzz qpack_fuzzer
)

(
# fuzz quic-go
compile_native_go_fuzzer_v2 github.com/quic-go/quic-go/internal/wire FuzzFrameParser frame_fuzzer
compile_go_fuzzer github.com/quic-go/quic-go/fuzzing/header Fuzz header_fuzzer
compile_go_fuzzer github.com/quic-go/quic-go/fuzzing/transportparameters Fuzz transportparameter_fuzzer
compile_go_fuzzer github.com/quic-go/quic-go/fuzzing/tokens Fuzz token_fuzzer
compile_go_fuzzer github.com/quic-go/quic-go/fuzzing/handshake Fuzz handshake_fuzzer

if [ $SANITIZER == "coverage" ]; then
    # no need for corpora if coverage
    exit 0
fi

# generate seed corpora
cd $GOPATH/src/github.com/quic-go/quic-go/
go generate -x ./fuzzing/...

zip --quiet -r $OUT/header_fuzzer_seed_corpus.zip fuzzing/header/corpus
zip --quiet -r $OUT/transportparameter_fuzzer_seed_corpus.zip fuzzing/transportparameters/corpus
zip --quiet -r $OUT/handshake_fuzzer_seed_corpus.zip fuzzing/handshake/corpus
)

# for debugging
ls -al $OUT
