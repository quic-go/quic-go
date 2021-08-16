package http3

import "fmt"

const (
	CapsuleTypeRegisterDatagramContext   CapsuleType = 0x00
	CapsuleTypeCloseDatagramContext      CapsuleType = 0x01
	CapsuleTypeDatagram                  CapsuleType = 0x02
	CapsuleTypeRegisterDatagramNoContext CapsuleType = 0x03
)

// A CapsuleType represents an HTTP capsule type.
// https://www.ietf.org/archive/id/draft-ietf-masque-h3-datagram-03.html#name-capsule-types
type CapsuleType uint64

// String returns the IETF registered name for t if available.
func (t CapsuleType) String() string {
	switch t {
	case CapsuleTypeRegisterDatagramContext:
		return "REGISTER_DATAGRAM_CONTEXT"
	case CapsuleTypeCloseDatagramContext:
		return "CLOSE_DATAGRAM_CONTEXT"
	case CapsuleTypeDatagram:
		return "DATAGRAM"
	case CapsuleTypeRegisterDatagramNoContext:
		return "REGISTER_DATAGRAM_NO_CONTEXT"
	default:
		return fmt.Sprintf("%#x", uint64(t))
	}
}
