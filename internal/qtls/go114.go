// +build !go1.15

package qtls

import (
	"crypto"
	"crypto/cipher"
	"crypto/tls"
	"net"
	"unsafe"

	"github.com/marten-seemann/qtls"
)

type (
	// Alert is a TLS alert
	Alert = qtls.Alert
	// A Certificate is qtls.Certificate.
	Certificate = qtls.Certificate
	// CertificateRequestInfo contains inforamtion about a certificate request.
	CertificateRequestInfo = qtls.CertificateRequestInfo
	// A CipherSuiteTLS13 is a cipher suite for TLS 1.3
	CipherSuiteTLS13 = qtls.CipherSuiteTLS13
	// ClientHelloInfo contains information about a ClientHello.
	ClientHelloInfo = qtls.ClientHelloInfo
	// ClientSessionCache is a cache used for session resumption.
	ClientSessionCache = qtls.ClientSessionCache
	// ClientSessionState is a state needed for session resumption.
	ClientSessionState = qtls.ClientSessionState
	// A Config is a qtls.Config.
	Config = qtls.Config
	// A Conn is a qtls.Conn.
	Conn = qtls.Conn
	// ConnectionState contains information about the state of the connection.
	ConnectionState = qtls.ConnectionState
	// EncryptionLevel is the encryption level of a message.
	EncryptionLevel = qtls.EncryptionLevel
	// Extension is a TLS extension
	Extension = qtls.Extension
	// RecordLayer is a qtls RecordLayer.
	RecordLayer = qtls.RecordLayer
)

type ExtraConfig struct {
	// GetExtensions, if not nil, is called before a message that allows
	// sending of extensions is sent.
	// Currently only implemented for the ClientHello message (for the client)
	// and for the EncryptedExtensions message (for the server).
	// Only valid for TLS 1.3.
	GetExtensions func(handshakeMessageType uint8) []Extension

	// ReceivedExtensions, if not nil, is called when a message that allows the
	// inclusion of extensions is received.
	// It is called with an empty slice of extensions, if the message didn't
	// contain any extensions.
	// Currently only implemented for the ClientHello message (sent by the
	// client) and for the EncryptedExtensions message (sent by the server).
	// Only valid for TLS 1.3.
	ReceivedExtensions func(handshakeMessageType uint8, exts []Extension)

	// AlternativeRecordLayer is used by QUIC
	AlternativeRecordLayer RecordLayer

	// Enforce the selection of a supported application protocol.
	// Only works for TLS 1.3.
	// If enabled, client and server have to agree on an application protocol.
	// Otherwise, connection establishment fails.
	EnforceNextProtoSelection bool

	// If MaxEarlyData is greater than 0, the client will be allowed to send early
	// data when resuming a session.
	// Requires the AlternativeRecordLayer to be set.
	//
	// It has no meaning on the client.
	MaxEarlyData uint32

	// The Accept0RTT callback is called when the client offers 0-RTT.
	// The server then has to decide if it wants to accept or reject 0-RTT.
	// It is only used for servers.
	Accept0RTT func(appData []byte) bool

	// 0RTTRejected is called when the server rejectes 0-RTT.
	// It is only used for clients.
	Rejected0RTT func()

	// If set, the client will export the 0-RTT key when resuming a session that
	// allows sending of early data.
	// Requires the AlternativeRecordLayer to be set.
	//
	// It has no meaning to the server.
	Enable0RTT bool

	// Is called when the client saves a session ticket to the session ticket.
	// This gives the application the opportunity to save some data along with the ticket,
	// which can be restored when the session ticket is used.
	GetAppDataForSessionState func() []byte

	// Is called when the client uses a session ticket.
	// Restores the application data that was saved earlier on GetAppDataForSessionTicket.
	SetAppDataFromSessionState func([]byte)
}

const (
	// EncryptionHandshake is the Handshake encryption level
	EncryptionHandshake = qtls.EncryptionHandshake
	// Encryption0RTT is the 0-RTT encryption level
	Encryption0RTT = qtls.Encryption0RTT
	// EncryptionApplication is the application data encryption level
	EncryptionApplication = qtls.EncryptionApplication
)

// CipherSuiteName gets the name of a cipher suite.
func CipherSuiteName(id uint16) string {
	return qtls.CipherSuiteName(id)
}

// HkdfExtract generates a pseudorandom key for use with Expand from an input secret and an optional independent salt.
func HkdfExtract(hash crypto.Hash, newSecret, currentSecret []byte) []byte {
	return qtls.HkdfExtract(hash, newSecret, currentSecret)
}

// HkdfExpandLabel HKDF expands a label
func HkdfExpandLabel(hash crypto.Hash, secret, hashValue []byte, label string, L int) []byte {
	return qtls.HkdfExpandLabel(hash, secret, hashValue, label, L)
}

// AEADAESGCMTLS13 creates a new AES-GCM AEAD for TLS 1.3
func AEADAESGCMTLS13(key, fixedNonce []byte) cipher.AEAD {
	return qtls.AEADAESGCMTLS13(key, fixedNonce)
}

// Client returns a new TLS client side connection.
func Client(conn net.Conn, config *tls.Config, extraConfig *ExtraConfig) *Conn {
	return qtls.Client(conn, tlsConfigToQtlsConfig(config, extraConfig))
}

// Server returns a new TLS server side connection.
func Server(conn net.Conn, config *tls.Config, extraConfig *ExtraConfig) *Conn {
	return qtls.Server(conn, tlsConfigToQtlsConfig(config, extraConfig))
}

func GetConnectionState(conn *Conn) ConnectionState {
	return conn.ConnectionState()
}

type cipherSuiteTLS13 struct {
	ID     uint16
	KeyLen int
	AEAD   func(key, fixedNonce []byte) cipher.AEAD
	Hash   crypto.Hash
}

//go:linkname cipherSuiteTLS13ByID github.com/marten-seemann/qtls.cipherSuiteTLS13ByID
func cipherSuiteTLS13ByID(id uint16) *cipherSuiteTLS13

// CipherSuiteTLS13ByID gets a TLS 1.3 cipher suite.
func CipherSuiteTLS13ByID(id uint16) *CipherSuiteTLS13 {
	val := cipherSuiteTLS13ByID(id)
	cs := (*cipherSuiteTLS13)(unsafe.Pointer(val))
	return &qtls.CipherSuiteTLS13{
		ID:     cs.ID,
		KeyLen: cs.KeyLen,
		AEAD:   cs.AEAD,
		Hash:   cs.Hash,
	}
}
