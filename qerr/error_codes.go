package qerr

// The error codes defined by QUIC
// Remeber to run `go generate ./...` whenever the error codes change.
//go:generate stringer -type=ErrorCode
const (
	InternalError      ErrorCode = 1
	InvalidFrameData   ErrorCode = 4
	DecryptionFailure  ErrorCode = 12
	PeerGoingAway      ErrorCode = 16
	NetworkIdleTimeout ErrorCode = 25
)
