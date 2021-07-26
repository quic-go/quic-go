package http3

import "fmt"

const (
	FrameTypeData          FrameType = 0x0
	FrameTypeHeaders       FrameType = 0x1
	FrameTypeCancelPush    FrameType = 0x3
	FrameTypeSettings      FrameType = 0x4
	FrameTypePushPromise   FrameType = 0x5
	FrameTypeGoAway        FrameType = 0x7
	FrameTypeMaxPushID     FrameType = 0xd
	FrameTypeDuplicatePush FrameType = 0xe
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
	default:
		return fmt.Sprintf("H3 frame type 0x%x", uint64(t))
	}
}
