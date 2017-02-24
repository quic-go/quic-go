package protocol

// EncryptionLevel is the encryption level
// Default value is Unencrypted
type EncryptionLevel int

const (
	// EncryptionUnspecified is a not specified encryption level
	EncryptionUnspecified EncryptionLevel = iota
	// EncryptionUnencrypted is not encrypted
	EncryptionUnencrypted
	// EncryptionSecure is encrypted, but not forward secure
	EncryptionSecure
	// EncryptionForwardSecure is forward secure
	EncryptionForwardSecure
)
