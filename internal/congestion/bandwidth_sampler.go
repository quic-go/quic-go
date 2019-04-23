package congestion

import (
	"time"

	"math"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type SendTimeState struct {
	isValid         bool
	isAppLimited    bool
	totalBytesSent  protocol.ByteCount
	totalBytesAcked protocol.ByteCount
	totalBytesLost  protocol.ByteCount
}

type ConnectionStateOnSentPacket struct {
	packetNumber                    protocol.PacketNumber
	sendTime                        time.Time
	size                            protocol.ByteCount
	totalBytesSentAtLastAckedPacket protocol.ByteCount
	lastAckedPacketSentTime         time.Time
	lastAckedPacketAckTime          time.Time
	sendTimeState                   SendTimeState
}

type ConnectionStates struct {
	stats       map[protocol.PacketNumber]*ConnectionStateOnSentPacket
	lastPacket  protocol.PacketNumber
	firstPacket protocol.PacketNumber
}

func (s *ConnectionStates) Insert(packetNumber protocol.PacketNumber, sentTime time.Time, bytes protocol.ByteCount, sampler *BandwidthSampler) bool {
	if len(s.stats) == 0 {
		s.stats[packetNumber] = NewConnectionStateOnSentPacket(packetNumber, sentTime, bytes, sampler)
		s.firstPacket, s.lastPacket = packetNumber, packetNumber
	}

	if packetNumber < s.lastPacket {
		return false
	}

	s.stats[packetNumber] = NewConnectionStateOnSentPacket(packetNumber, sentTime, bytes, sampler)
	s.lastPacket = packetNumber
	return true
}

func (s *ConnectionStates) Get(packetNumber protocol.PacketNumber) *ConnectionStateOnSentPacket {
	return s.stats[packetNumber]
}

func (s *ConnectionStates) Remove(packetNumber protocol.PacketNumber) (bool, *ConnectionStateOnSentPacket) {
	if s.firstPacket > packetNumber {
		return false, nil
	}

	if s.firstPacket == packetNumber {
		s.firstPacket++
	}

	state, ok := s.stats[packetNumber]
	delete(s.stats, packetNumber)
	return ok, state
}

func NewConnectionStateOnSentPacket(packetNumber protocol.PacketNumber, sentTime time.Time, bytes protocol.ByteCount, sampler *BandwidthSampler) *ConnectionStateOnSentPacket {
	return &ConnectionStateOnSentPacket{
		packetNumber: packetNumber,
		sendTime:     sentTime,
		size:         bytes,
		sendTimeState: SendTimeState{
			isValid:         true,
			isAppLimited:    sampler.isAppLimited,
			totalBytesSent:  sampler.totalBytesSent,
			totalBytesAcked: sampler.totalBytesAcked,
			totalBytesLost:  sampler.totalBytesLost,
		},
	}
}

type BandwidthSample struct {
	bandwidth   Bandwidth
	rtt         time.Duration
	stateAtSend SendTimeState
}

func NewBandwidthSample() *BandwidthSample {
	return &BandwidthSample{
		rtt: InfiniteRTT,
	}
}

type BandwidthSampler struct {
	totalBytesSentAtLastAckedPacket protocol.ByteCount
	lastAckedPacketSentTime         time.Time
	lastAckedPacketAckTime          time.Time
	totalBytesSent                  protocol.ByteCount
	totalBytesAcked                 protocol.ByteCount
	totalBytesLost                  protocol.ByteCount
	lastSendPacket                  protocol.PacketNumber
	isAppLimited                    bool
	endOfAppLimitedPhase            protocol.PacketNumber
	connectionStats                 *ConnectionStates
}

func NewBandwidthSampler() *BandwidthSampler {
	return &BandwidthSampler{
		connectionStats: &ConnectionStates{
			stats: make(map[protocol.PacketNumber]*ConnectionStateOnSentPacket),
		},
	}
}

func (s *BandwidthSampler) OnPacketSent(sentTime time.Time, lastSentPacket protocol.PacketNumber, sentBytes, bytesInFlight protocol.ByteCount, hasRetransmittableData bool) {
	s.lastSendPacket = lastSentPacket

	if !hasRetransmittableData {
		return
	}

	s.totalBytesSent += sentBytes

	// If there are no packets in flight, the time at which the new transmission
	// opens can be treated as the A_0 point for the purpose of bandwidth
	// sampling. This underestimates bandwidth to some extent, and produces some
	// artificially low samples for most packets in flight, but it provides with
	// samples at important points where we would not have them otherwise, most
	// importantly at the beginning of the connection.
	if bytesInFlight == 0 {
		s.lastAckedPacketAckTime = sentTime
		s.totalBytesSentAtLastAckedPacket = s.totalBytesSent

		// In this situation ack compression is not a concern, set send rate to
		// effectively infinite.
		s.lastAckedPacketSentTime = sentTime
	}

	s.connectionStats.Insert(lastSentPacket, sentTime, sentBytes, s)
}

func (s *BandwidthSampler) OnPacketAcked(ackTime time.Time, lastAckedPacket protocol.PacketNumber, ackedBytes protocol.ByteCount) *BandwidthSample {
	sentPacketState := s.connectionStats.Get(lastAckedPacket)
	if sentPacketState == nil {
		return NewBandwidthSample()
	}

	sample := s.onPacketAckedInner(ackTime, lastAckedPacket, ackedBytes, sentPacketState)
	s.connectionStats.Remove(lastAckedPacket)

	return sample
}

func (s *BandwidthSampler) onPacketAckedInner(ackTime time.Time, lastAckedPacket protocol.PacketNumber, ackedBytes protocol.ByteCount, sentPacket *ConnectionStateOnSentPacket) *BandwidthSample {
	s.totalBytesAcked += sentPacket.size
	s.totalBytesSentAtLastAckedPacket += sentPacket.sendTimeState.totalBytesSent
	s.lastAckedPacketSentTime = sentPacket.sendTime
	s.lastAckedPacketAckTime = ackTime

	if s.isAppLimited && lastAckedPacket > s.endOfAppLimitedPhase {
		s.isAppLimited = false
	}

	if sentPacket.lastAckedPacketSentTime.IsZero() {
		return NewBandwidthSample()
	}

	// Infinite rate indicates that the sampler is supposed to discard the
	// current send rate sample and use only the ack rate.
	sendRate := Bandwidth(math.MaxUint64)
	if sentPacket.sendTime.After(sentPacket.lastAckedPacketSentTime) {
		sendRate = BandwidthFromDelta(sentPacket.sendTimeState.totalBytesSent-sentPacket.totalBytesSentAtLastAckedPacket, sentPacket.sendTime.Sub(sentPacket.lastAckedPacketSentTime))
	}

	// During the slope calculation, ensure that ack time of the current packet is
	// always larger than the time of the previous packet, otherwise division by
	// zero or integer underflow can occur.
	if !ackTime.After(sentPacket.lastAckedPacketAckTime) {
		if sentPacket.lastAckedPacketAckTime.Equal(sentPacket.sendTime) {
			// This is the 1st packet after quiescense.
			return NewBandwidthSample()
		}
	}
	ackRate := BandwidthFromDelta(s.totalBytesAcked-sentPacket.sendTimeState.totalBytesAcked,
		ackTime.Sub(sentPacket.lastAckedPacketAckTime))

	sample := &BandwidthSample{
		bandwidth: minBandwidth(sendRate, ackRate),
		rtt:       ackTime.Sub(sentPacket.sendTime),
	}
	SentPacketToSendTimeState(sentPacket, &sample.stateAtSend)
	return sample
}

func (s *BandwidthSampler) OnPacketLost(packetNumber protocol.PacketNumber) SendTimeState {
	ok, sentPacket := s.connectionStats.Remove(packetNumber)
	sendTimeState := SendTimeState{
		isValid: ok,
	}
	if sentPacket != nil {
		s.totalBytesLost += sentPacket.size
		SentPacketToSendTimeState(sentPacket, &sendTimeState)
	}

	return sendTimeState
}

func (s *BandwidthSampler) RemoveObsoletePackets(leastUnacked protocol.PacketNumber) {
	s.connectionStats.Remove(leastUnacked)
}

func (s *BandwidthSampler) OnAppLimited() {
	s.isAppLimited = true
	s.endOfAppLimitedPhase = s.lastSendPacket
}

func SentPacketToSendTimeState(sentPacket *ConnectionStateOnSentPacket, sendTimeState *SendTimeState) {
	sendTimeState.isAppLimited = sentPacket.sendTimeState.isAppLimited
	sendTimeState.totalBytesSent = sentPacket.sendTimeState.totalBytesSent
	sendTimeState.totalBytesAcked = sentPacket.sendTimeState.totalBytesAcked
	sendTimeState.totalBytesLost = sentPacket.sendTimeState.totalBytesLost
	sendTimeState.isValid = true
}
