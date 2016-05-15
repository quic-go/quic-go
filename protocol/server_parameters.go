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

// ReceiveStreamFlowControlWindowIncrement is the amount that the stream-level flow control window is increased when sending a WindowUpdate
const ReceiveStreamFlowControlWindowIncrement = ReceiveStreamFlowControlWindow

// ReceiveConnectionFlowControlWindow is the stream-level flow control window for receiving data
// temporarily set this to a very high value, until proper connection-level flow control is implemented
// TODO: set a reasonable value here
const ReceiveConnectionFlowControlWindow ByteCount = (1 << 20) * 1024 * 2 // 2 GB

// MaxStreamsPerConnection is the maximum value accepted for the number of streams per connection
// TODO: set a reasonable value here
const MaxStreamsPerConnection uint32 = 100

// MaxIdleConnectionStateLifetime is the maximum value accepted for the idle connection state lifetime
// TODO: set a reasonable value here
const MaxIdleConnectionStateLifetime = 60 * time.Second

// WindowUpdateThreshold is the size of the receive flow control window for which we send out a WindowUpdate frame
const WindowUpdateThreshold = ReceiveStreamFlowControlWindow / 2
