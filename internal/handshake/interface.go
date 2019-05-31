package handshake

import (
	"crypto/tls"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/marten-seemann/qtls"
)

// Opener opens a packet
type Opener interface {
	Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error)
	DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte)
}

// Sealer seals a packet
type Sealer interface {
	Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte
	EncryptHeader(sample []byte, firstByte *byte, pnBytes []byte)
	Overhead() int
}

// A tlsExtensionHandler sends and received the QUIC TLS extension.
type tlsExtensionHandler interface {
	GetExtensions(msgType uint8) []qtls.Extension
	ReceivedExtensions(msgType uint8, exts []qtls.Extension)
	TransportParameters() <-chan []byte
}

type handshakeRunner interface {
	OnReceivedParams([]byte)
	OnError(error)
	DropKeys(protocol.EncryptionLevel)
}

// CryptoSetup handles the handshake and protecting / unprotecting packets
type CryptoSetup interface {
	RunHandshake()
	io.Closer
	ChangeConnectionID(protocol.ConnectionID) error

	HandleMessage([]byte, protocol.EncryptionLevel) bool
	Received1RTTAck()
	ConnectionState() tls.ConnectionState

	GetSealer() (protocol.EncryptionLevel, Sealer)
	GetSealerWithEncryptionLevel(protocol.EncryptionLevel) (Sealer, error)
	GetOpener(protocol.EncryptionLevel) (Opener, error)
}
