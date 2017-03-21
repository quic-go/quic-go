package handshake

import "github.com/lucas-clemente/quic-go/protocol"

// Sealer seals a packet
type Sealer func(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte

// CryptoSetup is a crypto setup
type CryptoSetup interface {
	Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel, error)
	HandleCryptoStream() error
	HandshakeComplete() bool
	// TODO: clean up this interface
	DiversificationNonce() []byte         // only needed for cryptoSetupServer
	SetDiversificationNonce([]byte) error // only needed for cryptoSetupClient

	GetSealer() (protocol.EncryptionLevel, Sealer)
	GetSealerWithEncryptionLevel(protocol.EncryptionLevel) (Sealer, error)
}
