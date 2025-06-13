package quic

import tls "github.com/Noooste/utls"

const (
	DefaultUDPDatagramMinSize = 1200
)

type QUICSpec struct {
	// InitialPacketSpec specifies the QUIC Initial Packet, which includes Initial
	// Packet Headers and Frames.
	InitialPacketSpec InitialPacketSpec

	// ClientHelloSpec specifies the TLS ClientHello to be sent in the first Initial
	// Packet. It is implemented by the uTLS library and a valid ClientHelloSpec
	// for QUIC MUST include (utls).QUICTransportParametersExtension.
	ClientHelloSpec *tls.ClientHelloSpec

	// UDPDatagramMinSize specifies the minimum size of the UDP Datagram (UDP payload).
	// If the UDP Datagram is smaller than this size, zeros will be padded to the end
	// of the UDP Datagram until this size is reached.
	UDPDatagramMinSize int
}

func (s *QUICSpec) UpdateConfig(config *Config) {
	s.InitialPacketSpec.UpdateConfig(config)
}
