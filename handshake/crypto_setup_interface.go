package handshake

import "github.com/lucas-clemente/quic-go/protocol"

// CryptoSetup is a crypto setup
type CryptoSetup interface {
	HandleCryptoStream() error
	Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error)
	Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte
	DiversificationNonce() []byte
	LockForSealing()
	UnlockForSealing()
	HandshakeComplete() bool
}
