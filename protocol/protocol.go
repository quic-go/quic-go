package protocol

// A PacketNumber in QUIC
type PacketNumber uint64

// A ConnectionID in QUIC
type ConnectionID uint64

// A StreamID in QUIC
type StreamID uint32

// A ByteCount in QUIC
type ByteCount uint64

// An ErrorCode in QUIC
type ErrorCode uint32

// MaxPacketSize is the maximum packet size, including the public header
const MaxPacketSize = 1452

// MaxFrameSize is the maximum size of a QUIC frame
const MaxFrameSize = MaxPacketSize - (1 + 8 + 6) /*public header*/ - 1 /*private header*/ - 12 /*crypto signature*/

// DefaultTCPMSS is the default maximum packet size used in the Linux TCP implementation.
// Used in QUIC for congestion window computations in bytes.
const DefaultTCPMSS ByteCount = 1460

// InitialCongestionWindow is the initial congestion window in QUIC packets
const InitialCongestionWindow PacketNumber = 32

// MaxCongestionWindow is the maximum size of the CWND, in packets.
// TODO: Unused?
const MaxCongestionWindow PacketNumber = 200

// DefaultMaxCongestionWindow is the default for the max congestion window
// Taken from Chrome
const DefaultMaxCongestionWindow PacketNumber = 107
