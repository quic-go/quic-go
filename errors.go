package quic

import (
	"github.com/lucas-clemente/quic-go/internal/qerr"
)

type (
	TransportError          = qerr.TransportError
	ApplicationError        = qerr.ApplicationError
	VersionNegotiationError = qerr.VersionNegotiationError
)

type (
	TransportErrorCode   = qerr.TransportErrorCode
	ApplicationErrorCode = qerr.ApplicationErrorCode
)

const (
	NoError                   = qerr.NoError
	InternalError             = qerr.InternalError
	ConnectionRefused         = qerr.ConnectionRefused
	FlowControlError          = qerr.FlowControlError
	StreamLimitError          = qerr.StreamLimitError
	StreamStateError          = qerr.StreamStateError
	FinalSizeError            = qerr.FinalSizeError
	FrameEncodingError        = qerr.FrameEncodingError
	TransportParameterError   = qerr.TransportParameterError
	ConnectionIDLimitError    = qerr.ConnectionIDLimitError
	ProtocolViolation         = qerr.ProtocolViolation
	InvalidToken              = qerr.InvalidToken
	ApplicationErrorErrorCode = qerr.ApplicationErrorErrorCode
	CryptoBufferExceeded      = qerr.CryptoBufferExceeded
	KeyUpdateError            = qerr.KeyUpdateError
	AEADLimitReached          = qerr.AEADLimitReached
	NoViablePathError         = qerr.NoViablePathError
)
