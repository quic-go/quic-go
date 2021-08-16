package http3

import "fmt"

const (
	FrameTypeData          FrameType = 0x00
	FrameTypeHeaders       FrameType = 0x01
	FrameTypeCancelPush    FrameType = 0x03
	FrameTypeSettings      FrameType = 0x04
	FrameTypePushPromise   FrameType = 0x05
	FrameTypeGoAway        FrameType = 0x07
	FrameTypeMaxPushID     FrameType = 0x0d
	FrameTypeDuplicatePush FrameType = 0x0e

	// https://www.ietf.org/archive/id/draft-ietf-masque-h3-datagram-03.html#name-http-3-capsule-frame
	FrameTypeCapsule FrameType = 0xffcab5
)

// A FrameType represents an HTTP/3 frame type.
// https://www.ietf.org/archive/id/draft-ietf-quic-http-34.html#name-frame-definitions
type FrameType uint64

// String returns the IETF registered name for t if available.
func (t FrameType) String() string {
	switch t {
	case FrameTypeData:
		return "DATA"
	case FrameTypeHeaders:
		return "HEADERS"
	case FrameTypeCancelPush:
		return "CANCEL_PUSH"
	case FrameTypeSettings:
		return "SETTINGS"
	case FrameTypePushPromise:
		return "PUSH_PROMISE"
	case FrameTypeGoAway:
		return "GO_AWAY"
	case FrameTypeMaxPushID:
		return "MAX_PUSH_ID"
	case FrameTypeDuplicatePush:
		return "DUPLICATE_PUSH"
	case FrameTypeCapsule:
		return "CAPSULE"
	default:
		return fmt.Sprintf("%#x", uint64(t))
	}
}
