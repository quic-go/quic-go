package handshake

import "github.com/lucas-clemente/quic-go/protocol"

// CryptoSetup is a crypto setup
type CryptoSetup interface {
	HandleCryptoStream() error
	Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel, error)
	Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel)
	SealWith(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte, forceEncryptionLevel protocol.EncryptionLevel) ([]byte, protocol.EncryptionLevel, error)
	LockForSealing()
	UnlockForSealing()
	HandshakeComplete() bool
	// TODO: clean up this interface
	DiversificationNonce(force bool) []byte // only needed for cryptoSetupServer
	SetDiversificationNonce([]byte) error   // only needed for cryptoSetupClient
}
