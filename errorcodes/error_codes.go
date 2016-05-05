package errorcodes

import "github.com/lucas-clemente/quic-go/protocol"

const (
	QUIC_NO_ERROR                      = protocol.ErrorCode(0)
	QUIC_INTERNAL_ERROR                = protocol.ErrorCode(1)
	QUIC_STREAM_DATA_AFTER_TERMINATION = protocol.ErrorCode(2)
	// QUIC_SERVER_ERROR_PROCESSING_STREAM= There was some server error which halted stream processing.
	// QUIC_MULTIPLE_TERMINATION_OFFSETS= The sender received two mismatching fin or reset offsets for a single stream.
	// QUIC_BAD_APPLICATION_PAYLOAD= The sender received bad application data.
	QUIC_INVALID_PACKET_HEADER         = protocol.ErrorCode(3)
	QUIC_INVALID_FRAME_DATA            = protocol.ErrorCode(4)
	QUIC_INVALID_FEC_DATA              = protocol.ErrorCode(5)
	QUIC_INVALID_RST_STREAM_DATA       = protocol.ErrorCode(6)
	QUIC_INVALID_CONNECTION_CLOSE_DATA = protocol.ErrorCode(7)
	QUIC_INVALID_ACK_DATA              = protocol.ErrorCode(9)
	QUIC_DECRYPTION_FAILURE            = protocol.ErrorCode(12)
	QUIC_ENCRYPTION_FAILURE            = protocol.ErrorCode(13)
	QUIC_PACKET_TOO_LARGE              = protocol.ErrorCode(14)
	// QUIC_PACKET_FOR_NONEXISTENT_STREAM= Data was sent for a stream which did not exist.
	QUIC_PEER_GOING_AWAY                         = protocol.ErrorCode(16)
	QUIC_INVALID_STREAM_ID                       = protocol.ErrorCode(17)
	QUIC_TOO_MANY_OPEN_STREAMS                   = protocol.ErrorCode(18)
	QUIC_NETWORK_IDLE_TIMEOUT                    = protocol.ErrorCode(25)
	QUIC_CRYPTO_TAGS_OUT_OF_ORDER                = protocol.ErrorCode(29)
	QUIC_CRYPTO_TOO_MANY_ENTRIES                 = protocol.ErrorCode(30)
	QUIC_CRYPTO_INVALID_VALUE_LENGTH             = protocol.ErrorCode(31)
	QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE = protocol.ErrorCode(32)
	QUIC_INVALID_CRYPTO_MESSAGE_TYPE             = protocol.ErrorCode(33)
	// QUIC_SEQUENCE_NUMBER_LIMIT_REACHED= Transmitting an additional packet would cause a packet number to be reused.
)
