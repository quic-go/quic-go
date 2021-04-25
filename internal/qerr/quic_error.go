package qerr

import (
	"fmt"
)

var (
	ErrHandshakeTimeout = &HandshakeTimeoutError{}
	ErrIdleTimeout      = &IdleTimeoutError{}
)

type TransportError struct {
	Remote       bool
	FrameType    uint64
	ErrorCode    TransportErrorCode
	ErrorMessage string
}

var _ error = &TransportError{}

// NewCryptoError create a new TransportError instance for a crypto error
func NewCryptoError(tlsAlert uint8, errorMessage string) *TransportError {
	return &TransportError{
		ErrorCode:    0x100 + TransportErrorCode(tlsAlert),
		ErrorMessage: errorMessage,
	}
}

func (e *TransportError) Is(target error) bool {
	_, ok := target.(*TransportError)
	return ok
}

func (e *TransportError) Error() string {
	str := e.ErrorCode.String()
	if e.FrameType != 0 {
		str += fmt.Sprintf(" (frame type: %#x)", e.FrameType)
	}
	msg := e.ErrorMessage
	if len(msg) == 0 {
		msg = e.ErrorCode.Message()
	}
	if len(msg) == 0 {
		return str
	}
	return str + ": " + msg
}

// An ApplicationErrorCode is an application-defined error code.
type ApplicationErrorCode uint64

type ApplicationError struct {
	Remote       bool
	ErrorCode    ApplicationErrorCode
	ErrorMessage string
}

var _ error = &ApplicationError{}

func (e *ApplicationError) Is(target error) bool {
	_, ok := target.(*ApplicationError)
	return ok
}

func (e *ApplicationError) Error() string {
	if len(e.ErrorMessage) == 0 {
		return fmt.Sprintf("Application error %#x", e.ErrorCode)
	}
	return fmt.Sprintf("Application error %#x: %s", e.ErrorCode, e.ErrorMessage)
}

type IdleTimeoutError struct{}

var _ error = &IdleTimeoutError{}

func (e *IdleTimeoutError) Timeout() bool   { return true }
func (e *IdleTimeoutError) Temporary() bool { return false }
func (e *IdleTimeoutError) Error() string   { return "timeout: no recent network activity" }
func (e *IdleTimeoutError) Is(target error) bool {
	_, ok := target.(*IdleTimeoutError)
	return ok
}

type HandshakeTimeoutError struct{}

var _ error = &HandshakeTimeoutError{}

func (e *HandshakeTimeoutError) Timeout() bool   { return true }
func (e *HandshakeTimeoutError) Temporary() bool { return false }
func (e *HandshakeTimeoutError) Error() string   { return "timeout: handshake did not complete in time" }
func (e *HandshakeTimeoutError) Is(target error) bool {
	_, ok := target.(*HandshakeTimeoutError)
	return ok
}
