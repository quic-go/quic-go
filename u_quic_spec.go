package quic

import tls "github.com/refraction-networking/utls"

const (
	DefaultUDPDatagramMinSize = 1200
)

type QUICSpec struct {
	InitialPacketSpec InitialPacketSpec
	ClientHelloSpec   *tls.ClientHelloSpec

	UDPDatagramMinSize int
}

func (s *QUICSpec) UpdateConfig(config *Config) {
	s.InitialPacketSpec.UpdateConfig(config)
}
