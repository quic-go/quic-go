package bbr

import (
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

// BandwidthSampler keeps track of sent and acknowledged packets and outputs a
// bandwidth sample for every packet acknowledged. The samples are taken for
// individual packets, and are not filtered; the consumer has to filter the
// bandwidth samples itself. In certain cases, the sampler will locally severely
// underestimate the bandwidth, hence a maximum filter with a size of at least
// one RTT is recommended.
//
// This class bases its samples on the slope of two curves: the number of bytes
// sent over time, and the number of bytes acknowledged as received over time.
// It produces a sample of both slopes for every packet that gets acknowledged,
// based on a slope between two points on each of the corresponding curves. Note
// that due to the packet loss, the number of bytes on each curve might get
// further and further away from each other, meaning that it is not feasible to
// compare byte values coming from different curves with each other.
//
// The obvious points for measuring slope sample are the ones corresponding to
// the packet that was just acknowledged. Let us denote them as S_1 (point at
// which the current packet was sent) and A_1 (point at which the current packet
// was acknowledged). However, taking a slope requires two points on each line,
// so estimating bandwidth requires picking a packet in the past with respect to
// which the slope is measured.
//
// For that purpose, BandwidthSampler always keeps track of the most recently
// acknowledged packet, and records it together with every outgoing packet.
// When a packet gets acknowledged (A_1), it has not only information about when
// it itself was sent (S_1), but also the information about the latest
// acknowledged packet right before it was sent (S_0 and A_0).
//
// Based on that data, send and ack rate are estimated as:
//   send_rate = (bytes(S_1) - bytes(S_0)) / (time(S_1) - time(S_0))
//   ack_rate = (bytes(A_1) - bytes(A_0)) / (time(A_1) - time(A_0))
//
// Here, the ack rate is intuitively the rate we want to treat as bandwidth.
// However, in certain cases (e.g. ack compression) the ack rate at a point may
// end up higher than the rate at which the data was originally sent, which is
// not indicative of the real bandwidth. Hence, we use the send rate as an upper
// bound, and the sample value is
//   rate_sample = min(send_rate, ack_rate)
//
// An important edge case handled by the sampler is tracking the app-limited
// samples. There are multiple meaning of "app-limited" used interchangeably,
// hence it is important to understand and to be able to distinguish between
// them.
//
// Meaning 1: connection state. The connection is said to be app-limited when
// there is no outstanding data to send. This means that certain bandwidth
// samples in the future would not be an accurate indication of the link
// capacity, and it is important to inform consumer about that. Whenever
// connection becomes app-limited, the sampler is notified via OnAppLimited()
// method.
//
// Meaning 2: a phase in the bandwidth sampler. As soon as the bandwidth
// sampler becomes notified about the connection being app-limited, it enters
// app-limited phase. In that phase, all *sent* packets are marked as
// app-limited. Note that the connection itself does not have to be
// app-limited during the app-limited phase, and in fact it will not be
// (otherwise how would it send packets?). The boolean flag below indicates
// whether the sampler is in that phase.
//
// Meaning 3: a flag on the sent packet and on the sample. If a sent packet is
// sent during the app-limited phase, the resulting sample related to the
// packet will be marked as app-limited.
//
// With the terminology issue out of the way, let us consider the question of
// what kind of situation it addresses.
//
// Consider a scenario where we first send packets 1 to 20 at a regular
// bandwidth, and then immediately run out of data. After a few seconds, we send
// packets 21 to 60, and only receive ack for 21 between sending packets 40 and
// 41. In this case, when we sample bandwidth for packets 21 to 40, the S_0/A_0
// we use to compute the slope is going to be packet 20, a few seconds apart
// from the current packet, hence the resulting estimate would be extremely low
// and not indicative of anything. Only at packet 41 the S_0/A_0 will become 21,
// meaning that the bandwidth sample would exclude the quiescence.
//
// Based on the analysis of that scenario, we implement the following rule: once
// OnAppLimited() is called, all sent packets will produce app-limited samples
// up until an ack for a packet that was sent after OnAppLimited() was called.
// Note that while the scenario above is not the only scenario when the
// connection is app-limited, the approach works in other cases too.

type bandwidthSampler struct {
	// The total number of congestion controlled bytes sent during the connection.
	totalBytesSent protocol.ByteCount
	// The total number of congestion controlled bytes which were acknowledged.
	totalBytesAcked protocol.ByteCount
	// The value of |total_bytes_sent_| at the time the last acknowledged packet
	// was sent. Valid only when |last_acked_packet_sent_time_| is valid.
	totalBytesSentAtLastAckedPacket protocol.ByteCount
	// The time at which the last acknowledged packet was sent. Set to
	// QuicTime::Zero() if no valid timestamp is available.
	lastAckedPacketSentTime time.Time
	// The time at which the most recent packet was acknowledged.
	lastAckedPacketAckTime time.Time
	// The most recently sent packet.
	lastSentPacket protocol.PacketNumber
	// Indicates whether the bandwidth sampler is currently in an app-limited phase.
	isAppLimited bool
	// The packet that will be acknowledged after this one will cause the sampler
	// to exit the app-limited phase.
	endOfAppLimitedPhase protocol.PacketNumber
	// Record of the connection state at the point where each packet in flight was
	// sent, indexed by the packet number.
	connectionStateMap map[protocol.PacketNumber]connectionStateOnSentPacket
}

func newBandwidthSampler() bandwidthSampler {
	return bandwidthSampler{connectionStateMap: make(map[protocol.PacketNumber]connectionStateOnSentPacket)}
}

// OnPacketSent inputs the sent packet information into the sampler. Assumes that all
// packets are sent in order. The information about the packet will not be
// released from the sampler until it the packet is either acknowledged or
// declared lost.
func (s *bandwidthSampler) OnPacketSent(sentTime time.Time, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, bytesInFlight protocol.ByteCount, hasRetransmittableData bool) {
	s.lastSentPacket = packetNumber

	if !hasRetransmittableData {
		return
	}

	s.totalBytesSent += bytes

	// If there are no packets in flight, the time at which the new transmission
	// opens can be treated as the A_0 point for the purpose of bandwidth
	// sampling. This underestimates bandwidth to some extent, and produces some
	// artificially low samples for most packets in flight, but it provides with
	// samples at important points where we would not have them otherwise, most
	// importantly at the beginning of the connection.
	if bytesInFlight == 0 {
		s.lastAckedPacketAckTime = sentTime
		s.totalBytesSentAtLastAckedPacket = s.totalBytesSent

		// In this situation ack compression is not a concern, set send rate to effectively infinite.
		s.lastAckedPacketSentTime = sentTime
	}

	// TODO: DCHECK
	s.connectionStateMap[packetNumber] = newConnectionStateOnSentPacket(sentTime, bytes, s)
	// TODO: QUIC_BUG_IF
}

// OnPacketAcknowledged notifies the sampler that the |packet_number| is acknowledged. Returns a
// bandwidth sample. If no bandwidth sample is available,
// QuicBandwidth::Zero() is returned.
func (s *bandwidthSampler) OnPacketAcknowledged(ackTime time.Time, packetNumber protocol.PacketNumber) bandwidthSample {
	sentPacket, ok := s.connectionStateMap[packetNumber]
	if !ok {
		// TODO(vasilvv): currently, this can happen because the congestion
		// controller can be created while some of the handshake packets are still
		// in flight.  Once the sampler is fully integrated with unacked packet map,
		// this should be a QUIC_BUG equivalent.
		return bandwidthSample{}
	}

	s.totalBytesAcked += sentPacket.size
	s.totalBytesSentAtLastAckedPacket = sentPacket.totalBytesSent
	s.lastAckedPacketSentTime = sentPacket.sentTime
	s.lastAckedPacketAckTime = ackTime

	delete(s.connectionStateMap, packetNumber)

	// Exit app-limited phase once a packet that was sent while the connection is
	// not app-limited is acknowledged.
	if s.isAppLimited && packetNumber > s.endOfAppLimitedPhase {
		s.isAppLimited = false
	}

	// There might have been no packets acknowledged at the moment when the
	// current packet was sent. In that case, there is no bandwidth sample to
	// make.
	if sentPacket.lastAckedPacketSentTime.IsZero() {
		return bandwidthSample{}
	}

	// Infinite rate indicates that the sampler is supposed to discard the
	// current send rate sample and use only the ack rate.
	sendRate := protocol.BandwidthInfinite
	if sentPacket.sentTime.After(sentPacket.lastAckedPacketSentTime) {
		sendRate = protocol.BandwidthFromDelta(sentPacket.totalBytesSent-sentPacket.totalBytesSentAtLastAckedPacket, sentPacket.sentTime.Sub(sentPacket.lastAckedPacketSentTime))
	}

	// During the slope calculation, ensure that ack time of the current packet is
	// always larger than the time of the previous packet, otherwise division by
	// zero or integer underflow can occur.
	if !ackTime.After(sentPacket.lastAckedPacketAckTime) {
		// TODO: QUIC_BUG
		return bandwidthSample{}
	}

	ackRate := protocol.BandwidthFromDelta(s.totalBytesAcked-sentPacket.totalBytesAckedAtTheLastAckedPacket, ackTime.Sub(sentPacket.lastAckedPacketAckTime))

	return bandwidthSample{
		bandwidth: utils.MinBandwidth(sendRate, ackRate),
		// Note: this sample does not account for delayed acknowledgement time.  This
		// means that the RTT measurements here can be artificially high, especially
		// on low bandwidth connections.
		rtt: ackTime.Sub(sentPacket.sentTime),
		// A sample is app-limited if the packet was sent during the app-limited
		// phase.
		isAppLimited: sentPacket.isAppLimited,
	}
}

// Informs the sampler that a packet is considered lost and it should no
// longer keep track of it.
func (s *bandwidthSampler) OnPacketLost(packetNumber protocol.PacketNumber) {
	_, ok := s.connectionStateMap[packetNumber]
	if !ok {
		// TODO(vasilvv): see the comment for the same case in
		// BandwidthSampler::OnPacketAcknowledged.
		return
	}

	delete(s.connectionStateMap, packetNumber)
}

// OnAppLimited nforms the sampler that the connection is currently app-limited, causing
// the sampler to enter the app-limited phase. The phase will expire by itself
// (see |is_app_limited_| documentation for details).
func (s *bandwidthSampler) OnAppLimited() {
	s.isAppLimited = true
	s.endOfAppLimitedPhase = s.lastSentPacket
}

// RemoveObsoletePackets removes all the packets lower than the specified packet number.
func (s *bandwidthSampler) RemoveObsoletePackets(leastUnacked protocol.PacketNumber) {
	for p := range s.connectionStateMap {
		if p < leastUnacked {
			delete(s.connectionStateMap, p)
		}
	}
}
