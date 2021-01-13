#!/bin/bash

go get honnef.co/go/tools/cmd/staticcheck

output=$(staticcheck ./...)
code=$?

echo "$output"
exit $code
