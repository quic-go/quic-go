package protocol

// A PacketNumber in QUIC
type PacketNumber uint64

// A ConnectionID in QUIC
type ConnectionID uint64

// A StreamID in QUIC
type StreamID uint32

// An ErrorCode in QUIC
type ErrorCode uint32

// MaxPacketSize is the maximum packet size, including the public header
const MaxPacketSize = 1452

// MaxFrameSize is the maximum size of a QUIC frame
const MaxFrameSize = MaxPacketSize - (1 + 8 + 6) /*public header*/ - 1 /*private header*/ - 12 /*crypto signature*/
