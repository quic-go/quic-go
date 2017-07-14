package qtrace

// The Tracer can be attached to a connection within the usual quic
// configuration of a client/server. The corresponding functions
// are called if provided. In example/trace/trace.go an exemplary use
// of the Tracer can be found.
type Tracer struct {
	GotPacket func([]byte, int)
	SentPacket func([]byte, int, uint64)

	ClientSentCHLO func(TracerHandshakeMessage)
	ClientGotHandshakeMsg func(TracerHandshakeMessage)

	ServerSentCHLO func(TracerHandshakeMessage)
	ServerSentInchoateCHLO func(TracerHandshakeMessage)
	ServerGotHandshakeMsg func(TracerHandshakeMessage)
}


type TracerHandshakeMessage struct {
	Tag  uint32
	Data map[uint32][]byte
}
