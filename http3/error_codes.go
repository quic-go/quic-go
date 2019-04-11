package http3

import (
	"fmt"

	quic "github.com/lucas-clemente/quic-go"
)

type errorCode quic.ErrorCode

const (
	errorNoError                errorCode = 0x0
	errorWrongSettingsDirection errorCode = 0x1
	errorPushRefused            errorCode = 0x2
	errorInternalError          errorCode = 0x3
	errorPushAlreadyInCache     errorCode = 0x4
	errorRequestCanceled        errorCode = 0x5
	errorIncompleteRequest      errorCode = 0x6
	errorConnectError           errorCode = 0x7
	errorExcessiveLoad          errorCode = 0x8
	errorVersionFallback        errorCode = 0x9
	errorWrongStream            errorCode = 0xa
	errorLimitExceeded          errorCode = 0xb
	errorDuplicatePush          errorCode = 0xc
	errorUnknownStreamType      errorCode = 0xd
	errorWrongStreamCount       errorCode = 0xe
	errorClosedCriticalStream   errorCode = 0xf
	errorWrongStreamDirection   errorCode = 0x10
	errorEarlyResponse          errorCode = 0x11
	errorMissingSettings        errorCode = 0x12
	errorUnexpectedFrame        errorCode = 0x13
	errorRequestRejected        errorCode = 0x14
	errorGeneralProtocolError   errorCode = 0xff
)

func (e errorCode) String() string {
	switch e {
	case errorNoError:
		return "HTTP_NO_ERROR"
	case errorWrongSettingsDirection:
		return "HTTP_WRONG_SETTING_DIRECTION"
	case errorPushRefused:
		return "HTTP_PUSH_REFUSED"
	case errorInternalError:
		return "HTTP_INTERNAL_ERROR"
	case errorPushAlreadyInCache:
		return "HTTP_PUSH_ALREADY_IN_CACHE"
	case errorRequestCanceled:
		return "HTTP_REQUEST_CANCELLED"
	case errorIncompleteRequest:
		return "HTTP_INCOMPLETE_REQUEST"
	case errorConnectError:
		return "HTTP_CONNECT_ERROR"
	case errorExcessiveLoad:
		return "HTTP_EXCESSIVE_LOAD"
	case errorVersionFallback:
		return "HTTP_VERSION_FALLBACK"
	case errorWrongStream:
		return "HTTP_WRONG_STREAM"
	case errorLimitExceeded:
		return "HTTP_LIMIT_EXCEEDED"
	case errorDuplicatePush:
		return "HTTP_DUPLICATE_PUSH"
	case errorUnknownStreamType:
		return "HTTP_UNKNOWN_STREAM_TYPE"
	case errorWrongStreamCount:
		return "HTTP_WRONG_STREAM_COUNT"
	case errorClosedCriticalStream:
		return "HTTP_CLOSED_CRITICAL_STREAM"
	case errorWrongStreamDirection:
		return "HTTP_WRONG_STREAM_DIRECTION"
	case errorEarlyResponse:
		return "HTTP_EARLY_RESPONSE"
	case errorMissingSettings:
		return "HTTP_MISSING_SETTINGS"
	case errorUnexpectedFrame:
		return "HTTP_UNEXPECTED_FRAME"
	case errorRequestRejected:
		return "HTTP_REQUEST_REJECTED"
	case errorGeneralProtocolError:
		return "HTTP_GENERAL_PROTOCOL_ERROR"
	default:
		if e >= 0x100 && e < 0x200 {
			return fmt.Sprintf("HTTP_MALFORMED_FRAME: %#x", uint16(e-0x100))
		}
		return fmt.Sprintf("unknown error code: %#x", uint16(e))
	}
}
