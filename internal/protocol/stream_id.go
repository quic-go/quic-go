package protocol

// A StreamID in QUIC
type StreamID uint64

// InitiatedBy says if the stream was initiated by the client or by the server
func (s StreamID) InitiatedBy() Perspective {
	if s%2 == 0 {
		return PerspectiveClient
	}
	return PerspectiveServer
}

// IsUniDirectional says if this is a unidirectional stream (true) or not (false)
func (s StreamID) IsUniDirectional() bool {
	return s%4 >= 2
}

// MaxBidiStreamID is the highest stream ID that the peer is allowed to open,
// when it is allowed to open numStreams bidirectional streams.
func MaxBidiStreamID(numStreams int, pers Perspective) StreamID {
	if numStreams == 0 {
		return 0
	}
	var first StreamID
	if pers == PerspectiveClient {
		first = 1
	} else {
		first = 0
	}
	return first + 4*StreamID(numStreams-1)
}

// MaxUniStreamID is the highest stream ID that the peer is allowed to open,
// when it is allowed to open numStreams unidirectional streams.
func MaxUniStreamID(numStreams int, pers Perspective) StreamID {
	if numStreams == 0 {
		return 0
	}
	var first StreamID
	if pers == PerspectiveClient {
		first = 3
	} else {
		first = 2
	}
	return first + 4*StreamID(numStreams-1)
}
