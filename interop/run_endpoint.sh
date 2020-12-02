#!/bin/bash
set -e

# Set up the routing needed for the simulation.
/setup.sh

echo "Using commit:" `cat commit.txt`

if [ "$ROLE" == "client" ]; then
    # Wait for the simulator to start up.
    /wait-for-it.sh sim:57832 -s -t 10
    echo "Starting QUIC client..."
    echo "Client params: $CLIENT_PARAMS"
    echo "Test case: $TESTCASE"
    QUIC_GO_LOG_LEVEL=debug ./client $CLIENT_PARAMS $REQUESTS
else
    echo "Running QUIC server."
    QUIC_GO_LOG_LEVEL=debug ./server "$@"
fi
