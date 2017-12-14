package mocks

//go:generate sh -c "./mockgen_internal.sh mockhandshake handshake/mint_tls.go github.com/lucas-clemente/quic-go/internal/handshake MintTLS"
//go:generate sh -c "./mockgen_internal.sh mocks tls_extension_handler.go github.com/lucas-clemente/quic-go/internal/handshake TLSExtensionHandler"
//go:generate sh -c "./mockgen_internal.sh mocks stream_flow_controller.go github.com/lucas-clemente/quic-go/internal/flowcontrol StreamFlowController"
//go:generate sh -c "./mockgen_internal.sh mocks sent_packet_handler.go github.com/lucas-clemente/quic-go/ackhandler SentPacketHandler"
//go:generate sh -c "./mockgen_internal.sh mocks received_packet_handler.go github.com/lucas-clemente/quic-go/ackhandler ReceivedPacketHandler"
//go:generate sh -c "./mockgen_internal.sh mocks connection_flow_controller.go github.com/lucas-clemente/quic-go/internal/flowcontrol ConnectionFlowController"
//go:generate sh -c "./mockgen_internal.sh mockcrypto crypto/aead.go github.com/lucas-clemente/quic-go/internal/crypto AEAD"
//go:generate sh -c "./mockgen_stream.sh mocks stream.go github.com/lucas-clemente/quic-go StreamI"
//go:generate sh -c "goimports -w ."
