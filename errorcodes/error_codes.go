package errorcodes

import "github.com/lucas-clemente/quic-go/protocol"

// The error codes defined by QUIC
const (
	InternalError      protocol.ErrorCode = 1
	InvalidFrameData   protocol.ErrorCode = 4
	DecryptionFailure  protocol.ErrorCode = 12
	PeerGoingAway      protocol.ErrorCode = 16
	NetworkIdleTimeout protocol.ErrorCode = 25
)
