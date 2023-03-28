package http3

import (
	"fmt"

	"github.com/quic-go/quic-go"
)

type ErrCode quic.ApplicationErrorCode

const (
	ErrNoError              ErrCode = 0x100
	ErrGeneralProtocolError ErrCode = 0x101
	ErrInternalError        ErrCode = 0x102
	ErrStreamCreationError  ErrCode = 0x103
	ErrClosedCriticalStream ErrCode = 0x104
	ErrFrameUnexpected      ErrCode = 0x105
	ErrFrameError           ErrCode = 0x106
	ErrExcessiveLoad        ErrCode = 0x107
	ErrIDError              ErrCode = 0x108
	ErrSettingsError        ErrCode = 0x109
	ErrMissingSettings      ErrCode = 0x10a
	ErrRequestRejected      ErrCode = 0x10b
	ErrRequestCanceled      ErrCode = 0x10c
	ErrRequestIncomplete    ErrCode = 0x10d
	ErrMessageError         ErrCode = 0x10e
	ErrConnectError         ErrCode = 0x10f
	ErrVersionFallback      ErrCode = 0x110
	ErrDatagramError        ErrCode = 0x4a1268
)

func (e ErrCode) String() string {
	switch e {
	case ErrNoError:
		return "H3_NO_ERROR"
	case ErrGeneralProtocolError:
		return "H3_GENERAL_PROTOCOL_ERROR"
	case ErrInternalError:
		return "H3_INTERNAL_ERROR"
	case ErrStreamCreationError:
		return "H3_STREAM_CREATION_ERROR"
	case ErrClosedCriticalStream:
		return "H3_CLOSED_CRITICAL_STREAM"
	case ErrFrameUnexpected:
		return "H3_FRAME_UNEXPECTED"
	case ErrFrameError:
		return "H3_FRAME_ERROR"
	case ErrExcessiveLoad:
		return "H3_EXCESSIVE_LOAD"
	case ErrIDError:
		return "H3_ID_ERROR"
	case ErrSettingsError:
		return "H3_SETTINGS_ERROR"
	case ErrMissingSettings:
		return "H3_MISSING_SETTINGS"
	case ErrRequestRejected:
		return "H3_REQUEST_REJECTED"
	case ErrRequestCanceled:
		return "H3_REQUEST_CANCELLED"
	case ErrRequestIncomplete:
		return "H3_INCOMPLETE_REQUEST"
	case ErrMessageError:
		return "H3_MESSAGE_ERROR"
	case ErrConnectError:
		return "H3_CONNECT_ERROR"
	case ErrVersionFallback:
		return "H3_VERSION_FALLBACK"
	case ErrDatagramError:
		return "H3_DATAGRAM_ERROR"
	default:
		return fmt.Sprintf("unknown error code: %#x", uint16(e))
	}
}
