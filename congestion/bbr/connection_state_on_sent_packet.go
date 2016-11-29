package bbr

import (
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
)

// connectionStateOnSentPacket represents the information about a sent packet
// and the state of the connection at the moment the packet was sent,
// specifically the information about the most recently acknowledged packet at
// that moment.
type connectionStateOnSentPacket struct {
	// Time at which the packet is sent.
	sentTime time.Time
	// Size of the packet
	size protocol.ByteCount
	// The value of |total_bytes_sent_| at the time the packet was sent.
	// Includes the packet itself.
	totalBytesSent protocol.ByteCount
	// The value of |total_bytes_sent_at_last_acked_packet_| at the time the
	// packet was sent.
	totalBytesSentAtLastAckedPacket protocol.ByteCount
	// The value of |last_acked_packet_sent_time_| at the time the packet was sent
	lastAckedPacketSentTime time.Time
	// The value of |last_acked_packet_ack_time_| at the time the packet was sent
	lastAckedPacketAckTime time.Time
	// The value of |total_bytes_acked_| at the time the packet was sent.
	totalBytesAckedAtTheLastAckedPacket protocol.ByteCount
	// The value of |is_app_limited_| at the time the packet was sent.
	isAppLimited bool
}

// Snapshot constructor. Records the current state of the bandwidth sampler.
func newConnectionStateOnSentPacket(sentTime time.Time, size protocol.ByteCount, sampler *bandwidthSampler) connectionStateOnSentPacket {
	return connectionStateOnSentPacket{
		sentTime:                            sentTime,
		size:                                size,
		totalBytesSent:                      sampler.totalBytesSent,
		totalBytesSentAtLastAckedPacket:     sampler.totalBytesSentAtLastAckedPacket,
		lastAckedPacketSentTime:             sampler.lastAckedPacketSentTime,
		lastAckedPacketAckTime:              sampler.lastAckedPacketAckTime,
		totalBytesAckedAtTheLastAckedPacket: sampler.totalBytesAcked,
		isAppLimited:                        sampler.isAppLimited,
	}
}
