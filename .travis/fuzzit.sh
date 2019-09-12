if [ "$TRAVIS_PULL_REQUEST" = "false" ]; then
    export FUZZING_TYPE="fuzzing"
    export BRANCH=${TRAVIS_BRANCH}
else
    export FUZZING_TYPE="local-regression"
    export BRANCH="PR-${TRAVIS_PULL_REQUEST}"
fi

## Build fuzzing targets
## go-fuzz doesn't support modules for now, so ensure we do everything
## in the old style GOPATH way
export GO111MODULE="off"

## Install fuzzit
wget -q -O fuzzit https://github.com/fuzzitdev/fuzzit/releases/download/v2.4.46/fuzzit_Linux_x86_64
chmod a+x fuzzit

## Install go-fuzz
go get -u github.com/dvyukov/go-fuzz/go-fuzz github.com/dvyukov/go-fuzz/go-fuzz-build

# install quic-go
go get -d -v -u ./...

cd fuzzing/header
go-fuzz-build -libfuzzer -o fuzz-header.a .
clang -fsanitize=fuzzer fuzz-header.a -o fuzz-header

cd ../frames
go-fuzz-build -libfuzzer -o fuzz-frames.a .
clang -fsanitize=fuzzer fuzz-frames.a -o fuzz-frames

cd ../..

# Create the jobs
./fuzzit create job --type ${FUZZING_TYPE} --branch ${BRANCH} --revision=${TRAVIS_COMMIT} quic-go/fuzz-header fuzzing/header/fuzz-header
./fuzzit create job --type ${FUZZING_TYPE} --branch ${BRANCH} --revision=${TRAVIS_COMMIT} quic-go/fuzz-frames fuzzing/frames/fuzz-frames
