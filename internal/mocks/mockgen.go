//go:build gomock || generate

package mocks

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package mockquic -destination quic/stream.go github.com/Noooste/uquic-go Stream"
//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package mockquic -destination quic/early_conn_tmp.go github.com/Noooste/uquic-go EarlyConnection && sed 's/qtls.ConnectionState/quic.ConnectionState/g' quic/early_conn_tmp.go > quic/early_conn.go && rm quic/early_conn_tmp.go && go run golang.org/x/tools/cmd/goimports -w quic/early_conn.go"
//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package mocks -destination short_header_sealer.go github.com/Noooste/uquic-go/internal/handshake ShortHeaderSealer"
//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package mocks -destination short_header_opener.go github.com/Noooste/uquic-go/internal/handshake ShortHeaderOpener"
//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package mocks -destination long_header_opener.go github.com/Noooste/uquic-go/internal/handshake LongHeaderOpener"
//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package mocks -destination crypto_setup_tmp.go github.com/Noooste/uquic-go/internal/handshake CryptoSetup && sed -E 's~github.com/quic-go/qtls[[:alnum:]_-]*~github.com/Noooste/uquic-go/internal/qtls~g; s~qtls.ConnectionStateWith0RTT~qtls.ConnectionState~g' crypto_setup_tmp.go > crypto_setup.go && rm crypto_setup_tmp.go && go run golang.org/x/tools/cmd/goimports -w crypto_setup.go"
//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package mocks -destination stream_flow_controller.go github.com/Noooste/uquic-go/internal/flowcontrol StreamFlowController"
//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package mocks -destination congestion.go github.com/Noooste/uquic-go/internal/congestion SendAlgorithmWithDebugInfos"
//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package mocks -destination connection_flow_controller.go github.com/Noooste/uquic-go/internal/flowcontrol ConnectionFlowController"
//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package mockackhandler -destination ackhandler/sent_packet_handler.go github.com/Noooste/uquic-go/internal/ackhandler SentPacketHandler"
//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package mockackhandler -destination ackhandler/received_packet_handler.go github.com/Noooste/uquic-go/internal/ackhandler ReceivedPacketHandler"
