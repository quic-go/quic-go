// Package errorcodes defines the error codes in QUIC.
//
package errorcodes

// An ErrorCode in QUIC
type ErrorCode uint32

// The error codes defined by QUIC
const (
	InternalError      ErrorCode = 1
	InvalidFrameData   ErrorCode = 4
	DecryptionFailure  ErrorCode = 12
	PeerGoingAway      ErrorCode = 16
	NetworkIdleTimeout ErrorCode = 25
)
