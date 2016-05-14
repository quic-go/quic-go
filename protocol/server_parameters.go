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
// TODO: set a reasonable value here
const ReceiveStreamFlowControlWindow ByteCount = (1 << 20) // 1 MB

// ReceiveConnectionFlowControlWindow is the stream-level flow control window for receiving data
// TODO: set a reasonable value here
const ReceiveConnectionFlowControlWindow ByteCount = (1 << 20) // 1 MB

// MaxIdleConnectionStateLifetime is the maximum value we accept for the idle connection state lifetime
// TODO: set a reasonable value here
const MaxIdleConnectionStateLifetime = 60 * time.Second
