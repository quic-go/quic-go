package protocol

// A StreamID in QUIC
type StreamID uint64

// StreamType encodes if this is a unidirectional or bidirectional stream
type StreamType uint8

const (
	// StreamTypeUni is a unidirectional stream
	StreamTypeUni StreamType = iota
	// StreamTypeBidi is a bidirectional stream
	StreamTypeBidi
)

// InitiatedBy says if the stream was initiated by the client or by the server
func (s StreamID) InitiatedBy() Perspective {
	if s%2 == 0 {
		return PerspectiveClient
	}
	return PerspectiveServer
}

//Type says if this is a unidirectional or bidirectional stream
func (s StreamID) Type() StreamType {
	if s%4 >= 2 {
		return StreamTypeUni
	}
	return StreamTypeBidi
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
