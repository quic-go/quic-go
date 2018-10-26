package protocol

// EncryptionLevel is the encryption level
// Default value is Unencrypted
type EncryptionLevel int

const (
	// EncryptionUnspecified is a not specified encryption level
	EncryptionUnspecified EncryptionLevel = iota
	// EncryptionUnencrypted is not encrypted, for gQUIC
	EncryptionUnencrypted
	// EncryptionInitial is the Initial encryption level
	EncryptionInitial
	// EncryptionSecure is encrypted, but not forward secure
	EncryptionSecure
	// EncryptionHandshake is the Handshake encryption level
	EncryptionHandshake
	// EncryptionForwardSecure is forward secure
	EncryptionForwardSecure
	// Encryption1RTT is the 1-RTT encryption level
	Encryption1RTT
)

func (e EncryptionLevel) String() string {
	switch e {
	// gQUIC
	case EncryptionUnencrypted:
		return "unencrypted"
	case EncryptionSecure:
		return "encrypted (not forward-secure)"
	case EncryptionForwardSecure:
		return "forward-secure"
	// IETF QUIC
	case EncryptionInitial:
		return "Initial"
	case EncryptionHandshake:
		return "Handshake"
	case Encryption1RTT:
		return "1-RTT"
	}
	return "unknown"
}
