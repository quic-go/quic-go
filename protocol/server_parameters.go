package protocol

import "time"

// MaxCongestionWindow is the maximum size of the CWND, in packets.
// TODO: Unused?
const MaxCongestionWindow PacketNumber = 200

// DefaultMaxCongestionWindow is the default for the max congestion window
// Taken from Chrome
const DefaultMaxCongestionWindow PacketNumber = 107

// InitialCongestionWindow is the initial congestion window in QUIC packets
const InitialCongestionWindow PacketNumber = 32

// MaxUndecryptablePackets limits the number of undecryptable packets that a
// session queues for later until it sends a public reset.
const MaxUndecryptablePackets = 10

// SmallPacketPayloadSizeThreshold defines a threshold for small packets
// if the packet payload size (i.e. the packet without public header and private header) is below SmallPacketSizeThreshold, sending will be delayed by SmallPacketSendDelay
const SmallPacketPayloadSizeThreshold = MaxPacketSize / 2

// SmallPacketSendDelay is the time delay applied to small packets
const SmallPacketSendDelay = 500 * time.Microsecond

// ReceiveStreamFlowControlWindow is the stream-level flow control window for receiving data
// This is the value that Google servers are using
const ReceiveStreamFlowControlWindow ByteCount = (1 << 20) // 1 MB

// ReceiveConnectionFlowControlWindow is the stream-level flow control window for receiving data
// This is the value that Google servers are using
const ReceiveConnectionFlowControlWindow ByteCount = (1 << 20) * 1.5 // 1.5 MB

// MaxStreamsPerConnection is the maximum value accepted for the number of streams per connection
// TODO: set a reasonable value here
const MaxStreamsPerConnection uint32 = 100

// MaxIdleConnectionStateLifetime is the maximum value accepted for the idle connection state lifetime
// TODO: set a reasonable value here
const MaxIdleConnectionStateLifetime = 60 * time.Second

// WindowUpdateNumRepitions is the number of times the same WindowUpdate frame will be sent to the client
const WindowUpdateNumRepitions uint8 = 2

// MaxSessionUnprocessedPackets is the max number of packets stored in each session that are not yet processed.
const MaxSessionUnprocessedPackets = 128

// RetransmissionThreshold + 1 is the number of times a packet has to be NACKed so that it gets retransmitted
const RetransmissionThreshold uint8 = 3
