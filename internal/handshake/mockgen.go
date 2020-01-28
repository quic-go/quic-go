package handshake

//go:generate sh -c "../../mockgen_private.sh handshake mock_handshake_runner_test.go github.com/lucas-clemente/quic-go/internal/handshake handshakeRunner"

// The following command produces a warning message on OSX, however, it still generates the correct mock file.
// See https://github.com/golang/mock/issues/339 for details.
//go:generate sh -c "mockgen -package handshake -destination mock_client_session_cache_test.go crypto/tls ClientSessionCache && goimports -w mock_client_session_cache_test.go"
