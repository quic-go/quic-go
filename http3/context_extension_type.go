package http3

import "fmt"

const (
	ContextExtensionTypeCloseCode ContextExtensionType = 0x00
	ContextExtensionTypeDetails   ContextExtensionType = 0x01
)

// A ContextExtensionType represents an HTTP datagram context extension type code.
// https://www.ietf.org/archive/id/draft-ietf-masque-h3-datagram-03.html#name-context-extension-types
type ContextExtensionType uint64

// String returns the IETF registered name for t if available.
func (t ContextExtensionType) String() string {
	switch t {
	case ContextExtensionTypeCloseCode:
		return "CLOSE_CODE"
	case ContextExtensionTypeDetails:
		return "DETAILS"
	default:
		return fmt.Sprintf("%#x", uint64(t))
	}
}
