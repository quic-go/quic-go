package qerr

// The error codes defined by QUIC
// Remember to run `go generate ./...` whenever the error codes change.
// This uses the Go stringer tool, which can be installed by running
// go get -u golang.org/x/tools/cmd/stringer

//go:generate stringer -type=ErrorCode
const (
	NoError                 ErrorCode = 0x0
	InternalError           ErrorCode = 0x1
	ServerBusy              ErrorCode = 0x2
	FlowControlError        ErrorCode = 0x3
	StreamLimitError        ErrorCode = 0x4
	StreamStateError        ErrorCode = 0x5
	FinalSizeError          ErrorCode = 0x6
	FrameEncodingError      ErrorCode = 0x7
	TransportParameterError ErrorCode = 0x8
	VersionNegotiationError ErrorCode = 0x9
	ProtocolViolation       ErrorCode = 0xa
	InvalidMigration        ErrorCode = 0xc
	CryptoError             ErrorCode = 0x100
)
