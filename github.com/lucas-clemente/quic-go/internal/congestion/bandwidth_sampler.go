package congestion

import (
	"fmt"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type BandwidthSample struct {
	// The bandwidth at that particular sample. Zero if no valid bandwidth sample
	// is available.
	bandwidth Bandwidth

	// The RTT measurement at this particular sample.  Zero if no RTT sample is
	// available.  Does not correct for delayed ack time.
	rtt time.Duration

	// Indicates whether the sample might be artificially low because the sender
	// did not have enough data to send in order to saturate the link.
	isAppLimited bool
}

func NewBandwidthSample() *BandwidthSample {
	return &BandwidthSample{
		bandwidth:    0,
		rtt:          time.Duration(0),
		isAppLimited: false,
	}
}

// ConnectionStateOnSentPacket represents the information about a sent packet
// and the state of the connection at the moment the packet was sent,
// specifically the information about the most recently acknowledged packet at
// that moment.
type ConnectionStateOnSentPacket struct {
	// Time at which the packet is sent.
	sentTime time.Time

	// Size of the packet.
	size protocol.ByteCount

	// The value of |totalBytesSent| at the time the packet was sent.
	// Includes the packet itself.
	totalBytesSent protocol.ByteCount

	// The value of |totalBytesSentAtLastAckedPacket| at the time the
	// packet was sent.
	totalBytesSentAtLastAckedPacket protocol.ByteCount

	// The value of |lastAckedPacketSentTime| at the time the packet was
	// sent.
	lastAckedPacketSentTime time.Time

	// The value of |lastAckedPacketAckTime| at the time the packet was
	// sent.
	lastAckedPacketAckTime time.Time

	// The value of |totalBytesAcked| at the time the packet was
	// sent.
	totalBytesAckedAtTheLastAckedPacket protocol.ByteCount

	// The value of |isAppLimited| at the time the packet was
	// sent.
	isAppLimited bool
}

type BandwidthSampler struct {

	// The total number of congestion controlled bytes sent during the connection.
	totalBytesSent protocol.ByteCount

	// The total number of congestion controlled bytes which were acknowledged.
	totalBytesAcked protocol.ByteCount

	// The value of |totalBytesSent| at the time the last acknowledged packet
	// was sent. Valid only when |lastAckedPacketSentTime| is valid.
	totalBytesSentAtLastAckedPacket protocol.ByteCount

	// The time at which the last acknowledged packet was sent. Set to
	// QuicTime::Zero() if no valid timestamp is available.
	lastAckedPacketSentTime time.Time

	// The time at which the most recent packet was acknowledged.
	lastAckedPacketAckTime time.Time

	// The most recently sent packet.
	lastSentPacket protocol.PacketNumber

	// Indicates whether the bandwidth sampler is currently in an app-limited
	// phase.
	isAppLimited bool

	// The packet that will be acknowledged after this one will cause the sampler
	// to exit the app-limited phase.
	endOfAppLimitedPhase protocol.PacketNumber

	// Record of the connection state at the point where each packet in flight was
	// sent, indexed by the packet number.
	connectionStateMap utils.PacketNumberIndexedQueue
}

// Snapshot constructor. Records the current state of the bandwidth
// sampler.
func NewConnectionStateOnSentPacket(
	sentTime time.Time,
	size protocol.ByteCount,
	sampler *BandwidthSampler) *ConnectionStateOnSentPacket {
	return &ConnectionStateOnSentPacket{
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

// Default constructor.  Required to put this structure into
// PacketNumberIndexedQueue.
func DefaultNewConnectionStateOnSentPacket() *ConnectionStateOnSentPacket {
	return &ConnectionStateOnSentPacket{
		// sentTime:QuicTime::Zero(),
		size:                                0,
		totalBytesSent:                      0,
		totalBytesSentAtLastAckedPacket:     0,
		totalBytesAckedAtTheLastAckedPacket: 0,
		isAppLimited:                        false,
	}
}

func (b *BandwidthSampler) OnPacketSent(
	sentTime time.Time,
	packetNumber protocol.PacketNumber,
	bytes protocol.ByteCount,
	bytesInFlight protocol.ByteCount,
	hasRetransmittableData bool) {
	b.lastSentPacket = packetNumber

	if hasRetransmittableData != true {
		return
	}

	b.totalBytesSent += bytes

	// If there are no packets in flight, the time at which the new transmission
	// opens can be treated as the A_0 point for the purpose of bandwidth
	// sampling. This underestimates bandwidth to some extent, and produces some
	// artificially low samples for most packets in flight, but it provides with
	// samples at important points where we would not have them otherwise, most
	// importantly at the beginning of the connection.
	if bytesInFlight == 0 {
		b.lastAckedPacketAckTime = sentTime
		b.totalBytesSentAtLastAckedPacket = b.totalBytesSent

		// In this situation ack compression is not a concern, set send rate to
		// effectively infinite.
		b.lastAckedPacketSentTime = sentTime
	}

	if !b.connectionStateMap.IsEmpty() &&
		packetNumber >
			b.connectionStateMap.LastPacket()+protocol.PacketNumber(protocol.MaxTrackedPackets) {
		fmt.Println("BandwidthSampler in-flight packet map has exceeded maximum number of tracked packets.")
	}

	if !b.connectionStateMap.Emplace(packetNumber, interface{}(*NewConnectionStateOnSentPacket(sentTime, bytes, b))) {
		fmt.Println("BandwidthSampler failed to insert the packet into the map, most likely because it's already in it.")
	}
}

func (b *BandwidthSampler) OnPacketAcknowledged(
	ackTime time.Time,
	packetNumber protocol.PacketNumber) BandwidthSample {
	sentPacketInterface :=
		b.connectionStateMap.GetEntry(packetNumber)
	if sentPacketInterface == nil {
		// See the TODO below.
		return *NewBandwidthSample()
	}
	sentPacket := sentPacketInterface.(ConnectionStateOnSentPacket)
	sample := b.OnPacketAcknowledgedInner(ackTime, packetNumber, &sentPacket)
	b.connectionStateMap.Remove(packetNumber)
	return sample
}

func (b *BandwidthSampler) OnPacketAcknowledgedInner(
	ackTime time.Time,
	packetNumber protocol.PacketNumber,
	sentPacket *ConnectionStateOnSentPacket) BandwidthSample {
	b.totalBytesAcked += sentPacket.size
	b.totalBytesSentAtLastAckedPacket = sentPacket.totalBytesSent
	b.lastAckedPacketSentTime = sentPacket.sentTime
	b.lastAckedPacketAckTime = ackTime

	// Exit app-limited phase once a packet that was sent while the connection is
	// not app-limited is acknowledged.
	if b.isAppLimited && packetNumber > b.endOfAppLimitedPhase {
		b.isAppLimited = false
	}

	// There might have been no packets acknowledged at the moment when the
	// current packet was sent. In that case, there is no bandwidth sample to
	// make.
	if time.Time.IsZero(sentPacket.lastAckedPacketSentTime) {
		return *NewBandwidthSample()
	}

	// Infinite rate indicates that the sampler is supposed to discard the
	// current send rate sample and use only the ack rate.
	sendRate := Bandwidth(^uint64(0))
	if sentPacket.sentTime.After(sentPacket.lastAckedPacketSentTime) {
		sendRate = BandwidthFromDelta(
			sentPacket.totalBytesSent-
				sentPacket.totalBytesSentAtLastAckedPacket,
			sentPacket.sentTime.Sub(sentPacket.lastAckedPacketSentTime))
	}

	// During the slope calculation, ensure that ack time of the current packet is
	// always larger than the time of the previous packet, otherwise division by
	// zero or integer underflow can occur.
	if (ackTime.Before(sentPacket.lastAckedPacketAckTime)) || ackTime.Equal(sentPacket.lastAckedPacketAckTime) {
		// TODO(wub): Compare this code count before and after fixing clock jitter
		// issue.
		if sentPacket.lastAckedPacketAckTime.Equal(sentPacket.sentTime) {
			// This is the 1st packet after quiescense.
			//QUIC_CODE_COUNT_N(quic_prev_ack_time_larger_than_current_ack_time, 1, 2);
		} else {
			//QUIC_CODE_COUNT_N(quic_prev_ack_time_larger_than_current_ack_time, 2, 2);
		}
		// QUIC_LOG(ERROR) << "Time of the previously acked packet:"
		//                 << sent_packet.lastAckedPacketAckTime.ToDebuggingValue()
		//                 << " is larger than the ack time of the current packet:"
		//                 << ack_time.ToDebuggingValue();
		return *NewBandwidthSample()
	}
	ackRate := BandwidthFromDelta(
		b.totalBytesAcked-sentPacket.totalBytesAckedAtTheLastAckedPacket,
		ackTime.Sub(sentPacket.lastAckedPacketAckTime))

	var sample BandwidthSample
	sample.bandwidth = Bandwidth(utils.MinUint64(uint64(sendRate), uint64(ackRate)))
	// Note: this sample does not account for delayed acknowledgement time.  This
	// means that the RTT measurements here can be artificially high, especially
	// on low bandwidth connections.
	sample.rtt = ackTime.Sub(sentPacket.sentTime)
	// A sample is app-limited if the packet was sent during the app-limited
	// phase.
	sample.isAppLimited = sentPacket.isAppLimited
	return sample
}

func (b *BandwidthSampler) OnPacketLost(packetNumber protocol.PacketNumber) {
	// TODO(vasilvv): see the comment for the case of missing packets in
	// func (b *BandwidthSampler) OnPacketAcknowledged on why this does not raise a
	// QUIC_BUG when removal fails.
	b.connectionStateMap.Remove(packetNumber)
}

func (b *BandwidthSampler) OnAppLimited() {
	b.isAppLimited = true
	b.endOfAppLimitedPhase = b.lastSentPacket
}

func (b *BandwidthSampler) RemoveObsoletePackets(least_unacked protocol.PacketNumber) {
	for !b.connectionStateMap.IsEmpty() &&
		b.connectionStateMap.FirstPacket() < least_unacked {
		b.connectionStateMap.Remove(b.connectionStateMap.FirstPacket())
	}
}

func (b *BandwidthSampler) TotalBytesAcked() protocol.ByteCount {
	return b.totalBytesAcked
}

func (b *BandwidthSampler) IsAppLimited() bool {
	return b.isAppLimited
}

func (b *BandwidthSampler) EndOfAppLimitedPhase() protocol.PacketNumber {
	return b.endOfAppLimitedPhase
}
