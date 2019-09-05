package http3

import (
	"fmt"

	quic "github.com/lucas-clemente/quic-go"
)

type errorCode quic.ErrorCode

const (
	errorNoError              errorCode = 0x100
	errorGeneralProtocolError errorCode = 0x101
	errorInternalError        errorCode = 0x102
	errorStreamCreationError  errorCode = 0x103
	errorClosedCriticalStream errorCode = 0x104
	errorUnexpectedFrame      errorCode = 0x105
	errorFrameError           errorCode = 0x106
	errorExcessiveLoad        errorCode = 0x107
	errorWrongStream          errorCode = 0x108
	errorIDError              errorCode = 0x109
	errorSettingsError        errorCode = 0x10a
	errorMissingSettings      errorCode = 0x10b
	errorRequestRejected      errorCode = 0x10c
	errorRequestCanceled      errorCode = 0x10d
	errorRequestIncomplete    errorCode = 0x10e
	errorEarlyResponse        errorCode = 0x10f
	errorConnectError         errorCode = 0x110
	errorVersionFallback      errorCode = 0x111
)

func (e errorCode) String() string {
	switch e {
	case errorNoError:
		return "HTTP_NO_ERROR"
	case errorGeneralProtocolError:
		return "HTTP_GENERAL_PROTOCOL_ERROR"
	case errorInternalError:
		return "HTTP_INTERNAL_ERROR"
	case errorStreamCreationError:
		return "HTTP_STREAM_CREATION_ERROR"
	case errorClosedCriticalStream:
		return "HTTP_CLOSED_CRITICAL_STREAM"
	case errorUnexpectedFrame:
		return "HTTP_UNEXPECTED_FRAME"
	case errorFrameError:
		return "HTTP_FRAME_ERROR"
	case errorExcessiveLoad:
		return "HTTP_EXCESSIVE_LOAD"
	case errorWrongStream:
		return "HTTP_WRONG_STREAM"
	case errorIDError:
		return "HTTP_ID_ERROR"
	case errorSettingsError:
		return "HTTP_SETTINGS_ERROR"
	case errorMissingSettings:
		return "HTTP_MISSING_SETTINGS"
	case errorRequestRejected:
		return "HTTP_REQUEST_REJECTED"
	case errorRequestCanceled:
		return "HTTP_REQUEST_CANCELLED"
	case errorRequestIncomplete:
		return "HTTP_INCOMPLETE_REQUEST"
	case errorEarlyResponse:
		return "HTTP_EARLY_RESPONSE"
	case errorConnectError:
		return "HTTP_CONNECT_ERROR"
	case errorVersionFallback:
		return "HTTP_VERSION_FALLBACK"
	default:
		return fmt.Sprintf("unknown error code: %#x", uint16(e))
	}
}
