#!/bin/bash -eu

export CXX="${CXX} -lresolv" # required by Go 1.20

compile_go_fuzzer github.com/Noooste/uquic-go/fuzzing/frames Fuzz frame_fuzzer
compile_go_fuzzer github.com/Noooste/uquic-go/fuzzing/header Fuzz header_fuzzer
compile_go_fuzzer github.com/Noooste/uquic-go/fuzzing/transportparameters Fuzz transportparameter_fuzzer
compile_go_fuzzer github.com/Noooste/uquic-go/fuzzing/tokens Fuzz token_fuzzer
compile_go_fuzzer github.com/Noooste/uquic-go/fuzzing/handshake Fuzz handshake_fuzzer
