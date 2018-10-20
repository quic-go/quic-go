package handshake

import (
	"crypto/x509"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/marten-seemann/qtls"
)

// Opener opens a packet
type Opener interface {
	Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error)
}

// Sealer seals a packet
type Sealer interface {
	Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte
	Overhead() int
}

// A tlsExtensionHandler sends and received the QUIC TLS extension.
type tlsExtensionHandler interface {
	GetExtensions(msgType uint8) []qtls.Extension
	ReceivedExtensions(msgType uint8, exts []qtls.Extension) error
}

type baseCryptoSetup interface {
	RunHandshake() error
	ConnectionState() ConnectionState

	GetSealer() (protocol.EncryptionLevel, Sealer)
	GetSealerWithEncryptionLevel(protocol.EncryptionLevel) (Sealer, error)
}

// CryptoSetup is the crypto setup used by gQUIC
type CryptoSetup interface {
	baseCryptoSetup

	GetSealerForCryptoStream() (protocol.EncryptionLevel, Sealer)
	Open(dst, src []byte, pn protocol.PacketNumber, ad []byte) ([]byte, protocol.EncryptionLevel, error)
}

// CryptoSetupTLS is the crypto setup used by IETF QUIC
type CryptoSetupTLS interface {
	baseCryptoSetup

	HandleMessage([]byte, protocol.EncryptionLevel)
	OpenInitial(dst, src []byte, pn protocol.PacketNumber, ad []byte) ([]byte, error)
	OpenHandshake(dst, src []byte, pn protocol.PacketNumber, ad []byte) ([]byte, error)
	Open1RTT(dst, src []byte, pn protocol.PacketNumber, ad []byte) ([]byte, error)
}

// ConnectionState records basic details about the QUIC connection.
// Warning: This API should not be considered stable and might change soon.
type ConnectionState struct {
	HandshakeComplete bool                // handshake is complete
	ServerName        string              // server name requested by client, if any (server side only)
	PeerCertificates  []*x509.Certificate // certificate chain presented by remote peer
}
