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

// AckSendDelay is the maximal time delay applied to packets containing only ACKs
const AckSendDelay = 5 * time.Millisecond

// ReceiveStreamFlowControlWindow is the stream-level flow control window for receiving data
// This is the value that Google servers are using
const ReceiveStreamFlowControlWindow ByteCount = (1 << 20) // 1 MB

// ReceiveConnectionFlowControlWindow is the stream-level flow control window for receiving data
// This is the value that Google servers are using
const ReceiveConnectionFlowControlWindow ByteCount = (1 << 20) * 1.5 // 1.5 MB

// MaxStreamsPerConnection is the maximum value accepted for the number of streams per connection
const MaxStreamsPerConnection uint32 = 100

// MaxIncomingDynamicStreams is the maximum value accepted for the incoming number of dynamic streams per connection
const MaxIncomingDynamicStreams uint32 = 100

// MaxStreamsMultiplier is the slack the client is allowed for the maximum number of streams per connection, needed e.g. when packets are out of order or dropped. The minimum of this procentual increase and the absolute increment specified by MaxStreamsMinimumIncrement is used.
const MaxStreamsMultiplier = 1.1

// MaxStreamsMinimumIncrement is the slack the client is allowed for the maximum number of streams per connection, needed e.g. when packets are out of order or dropped. The minimum of this absolute increment and the procentual increase specified by MaxStreamsMultiplier is used.
const MaxStreamsMinimumIncrement = 10

// MaxIdleConnectionStateLifetime is the maximum value accepted for the idle connection state lifetime
// TODO: set a reasonable value here
const MaxIdleConnectionStateLifetime = 60 * time.Second

// MaxSessionUnprocessedPackets is the max number of packets stored in each session that are not yet processed.
const MaxSessionUnprocessedPackets = 128

// RetransmissionThreshold + 1 is the number of times a packet has to be NACKed so that it gets retransmitted
const RetransmissionThreshold uint8 = 3

// SkipPacketAveragePeriodLength is the average period length in which one packet number is skipped to prevent an Optimistic ACK attack
const SkipPacketAveragePeriodLength PacketNumber = 500

// MaxTrackedSkippedPackets is the maximum number of skipped packet numbers the SentPacketHandler keep track of for Optimistic ACK attack mitigation
const MaxTrackedSkippedPackets int = 10

// STKExpiryTimeSec is the valid time of a source address token in seconds
const STKExpiryTimeSec = 24 * 60 * 60

// MaxTrackedSentPackets is maximum number of sent packets saved for either later retransmission or entropy calculation
// TODO: find a reasonable value here
// TODO: decrease this value after dropping support for QUIC 33 and earlier
const MaxTrackedSentPackets uint32 = 2000

// MaxTrackedReceivedPackets is the maximum number of received packets saved for doing the entropy calculations
// TODO: think about what to do with this when adding support for QUIC 34
const MaxTrackedReceivedPackets uint32 = 2000

// MaxStreamFrameSorterGaps is the maximum number of gaps between received StreamFrames
// prevents DOS attacks against the streamFrameSorter
const MaxStreamFrameSorterGaps = 1000

// CryptoMaxParams is the upper limit for the number of parameters in a crypto message.
// Value taken from Chrome.
const CryptoMaxParams = 128

// CryptoParameterMaxLength is the upper limit for the length of a parameter in a crypto message.
const CryptoParameterMaxLength = 2000

// EphermalKeyLifetime is the lifetime of the ephermal key during the handshake, see handshake.getEphermalKEX.
const EphermalKeyLifetime = time.Minute
