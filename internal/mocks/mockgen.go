package mocks

//go:generate sh -c "go run github.com/golang/mock/mockgen -package mockquic -destination quic/stream.go github.com/quic-go/quic-go Stream"
//go:generate sh -c "go run github.com/golang/mock/mockgen -package mockquic -destination quic/early_conn_tmp.go github.com/quic-go/quic-go EarlyConnection && sed 's/qtls.ConnectionState/quic.ConnectionState/g' quic/early_conn_tmp.go > quic/early_conn.go && rm quic/early_conn_tmp.go && go run golang.org/x/tools/cmd/goimports -w quic/early_conn.go"
//go:generate sh -c "go run github.com/golang/mock/mockgen -package mockquic -destination quic/early_listener.go github.com/quic-go/quic-go EarlyListener"
//go:generate sh -c "go run github.com/golang/mock/mockgen -package mocklogging -destination logging/tracer.go github.com/quic-go/quic-go/logging Tracer"
//go:generate sh -c "go run github.com/golang/mock/mockgen -package mocklogging -destination logging/connection_tracer.go github.com/quic-go/quic-go/logging ConnectionTracer"
//go:generate sh -c "go run github.com/golang/mock/mockgen -package mocks -destination short_header_sealer.go github.com/quic-go/quic-go/internal/handshake ShortHeaderSealer"
//go:generate sh -c "go run github.com/golang/mock/mockgen -package mocks -destination short_header_opener.go github.com/quic-go/quic-go/internal/handshake ShortHeaderOpener"
//go:generate sh -c "go run github.com/golang/mock/mockgen -package mocks -destination long_header_opener.go github.com/quic-go/quic-go/internal/handshake LongHeaderOpener"
//go:generate sh -c "go run github.com/golang/mock/mockgen -package mocks -destination crypto_setup_tmp.go github.com/quic-go/quic-go/internal/handshake CryptoSetup && sed -E 's~github.com/quic-go/qtls[[:alnum:]_-]*~github.com/quic-go/quic-go/internal/qtls~g; s~qtls.ConnectionStateWith0RTT~qtls.ConnectionState~g' crypto_setup_tmp.go > crypto_setup.go && rm crypto_setup_tmp.go && go run golang.org/x/tools/cmd/goimports -w crypto_setup.go"
//go:generate sh -c "go run github.com/golang/mock/mockgen -package mocks -destination stream_flow_controller.go github.com/quic-go/quic-go/internal/flowcontrol StreamFlowController"
//go:generate sh -c "go run github.com/golang/mock/mockgen -package mocks -destination congestion.go github.com/quic-go/quic-go/internal/congestion SendAlgorithmWithDebugInfos"
//go:generate sh -c "go run github.com/golang/mock/mockgen -package mocks -destination connection_flow_controller.go github.com/quic-go/quic-go/internal/flowcontrol ConnectionFlowController"
//go:generate sh -c "go run github.com/golang/mock/mockgen -package mockackhandler -destination ackhandler/sent_packet_handler.go github.com/quic-go/quic-go/internal/ackhandler SentPacketHandler"
//go:generate sh -c "go run github.com/golang/mock/mockgen -package mockackhandler -destination ackhandler/received_packet_handler.go github.com/quic-go/quic-go/internal/ackhandler ReceivedPacketHandler"

// The following command produces a warning message on OSX, however, it still generates the correct mock file.
// See https://github.com/golang/mock/issues/339 for details.
//go:generate sh -c "go run github.com/golang/mock/mockgen -package mocktls -destination tls/client_session_cache.go crypto/tls ClientSessionCache"
