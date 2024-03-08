#!/bin/bash -eu

export CXX="${CXX} -lresolv" # required by Go 1.20

compile_go_fuzzer github.com/danielpfeifer02/quic-go-prio-packs/fuzzing/frames Fuzz frame_fuzzer
compile_go_fuzzer github.com/danielpfeifer02/quic-go-prio-packs/fuzzing/header Fuzz header_fuzzer
compile_go_fuzzer github.com/danielpfeifer02/quic-go-prio-packs/fuzzing/transportparameters Fuzz transportparameter_fuzzer
compile_go_fuzzer github.com/danielpfeifer02/quic-go-prio-packs/fuzzing/tokens Fuzz token_fuzzer
compile_go_fuzzer github.com/danielpfeifer02/quic-go-prio-packs/fuzzing/handshake Fuzz handshake_fuzzer
