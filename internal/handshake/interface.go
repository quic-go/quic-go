package handshake

import (
	"crypto/tls"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/marten-seemann/qtls"
)

type headerDecryptor interface {
	DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte)
}

// LongHeaderOpener opens a long header packet
type LongHeaderOpener interface {
	headerDecryptor
	Open(dst, src []byte, pn protocol.PacketNumber, associatedData []byte) ([]byte, error)
}

// ShortHeaderOpener opens a short header packet
type ShortHeaderOpener interface {
	headerDecryptor
	Open(dst, src []byte, pn protocol.PacketNumber, kp protocol.KeyPhase, associatedData []byte) ([]byte, error)
}

// LongHeaderSealer seals a long header packet
type LongHeaderSealer interface {
	Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte
	EncryptHeader(sample []byte, firstByte *byte, pnBytes []byte)
	Overhead() int
}

// ShortHeaderSealer seals a short header packet
type ShortHeaderSealer interface {
	LongHeaderSealer
	KeyPhase() protocol.KeyPhase
}

// A tlsExtensionHandler sends and received the QUIC TLS extension.
type tlsExtensionHandler interface {
	GetExtensions(msgType uint8) []qtls.Extension
	ReceivedExtensions(msgType uint8, exts []qtls.Extension)
	TransportParameters() <-chan []byte
}

type handshakeRunner interface {
	OnReceivedParams([]byte)
	OnHandshakeComplete()
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

	GetInitialOpener() (LongHeaderOpener, error)
	GetHandshakeOpener() (LongHeaderOpener, error)
	Get1RTTOpener() (ShortHeaderOpener, error)

	GetInitialSealer() (LongHeaderSealer, error)
	GetHandshakeSealer() (LongHeaderSealer, error)
	Get1RTTSealer() (ShortHeaderSealer, error)
}
