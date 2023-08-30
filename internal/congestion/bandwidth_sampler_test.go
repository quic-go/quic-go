package congestion

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

var _ = Describe("function", func() {
	It("BytesFromBandwidthAndTimeDelta", func() {
		Expect(
			bytesFromBandwidthAndTimeDelta(
				Bandwidth(80000),
				100*time.Millisecond,
			)).To(Equal(protocol.ByteCount(1000)))
	})

	It("TimeDeltaFromBytesAndBandwidth", func() {
		Expect(timeDeltaFromBytesAndBandwidth(
			protocol.ByteCount(50000),
			Bandwidth(400),
		)).To(Equal(1000 * time.Second))
	})
})

var _ = Describe("MaxAckHeightTracker", func() {
	var (
		tracker               *maxAckHeightTracker
		now                   time.Time
		rtt                   time.Duration
		bandwidth             Bandwidth
		lastSentPacketNumber  protocol.PacketNumber
		lastAckedPacketNumber protocol.PacketNumber

		getRoundTripCount = func() roundTripCount {
			return roundTripCount(now.Sub(time.Time{}) / rtt)
		}

		// Run a full aggregation episode, which is one or more aggregated acks,
		// followed by a quiet period in which no ack happens.
		// After this function returns, the time is set to the earliest point at which
		// any ack event will cause tracker_.Update() to start a new aggregation.
		aggregationEpisode = func(
			aggregationBandwidth Bandwidth,
			aggregationDuration time.Duration,
			bytesPerAck protocol.ByteCount,
			expectNewAggregationEpoch bool,
		) {
			Expect(aggregationBandwidth >= bandwidth).To(BeTrue())
			startTime := now
			aggregationBytes := bytesFromBandwidthAndTimeDelta(aggregationBandwidth, aggregationDuration)
			numAcks := aggregationBytes / bytesPerAck
			Expect(aggregationBytes).To(Equal(numAcks * bytesPerAck))
			timeBetweenAcks := aggregationDuration / time.Duration(numAcks)
			Expect(aggregationDuration).To(Equal(time.Duration(numAcks) * timeBetweenAcks))

			// The total duration of aggregation time and quiet period.
			totalDuration := timeDeltaFromBytesAndBandwidth(aggregationBytes, bandwidth)
			Expect(aggregationBytes).To(Equal(bytesFromBandwidthAndTimeDelta(bandwidth, totalDuration)))

			var lastExtraAcked protocol.ByteCount
			for bytes := protocol.ByteCount(0); bytes < aggregationBytes; bytes += bytesPerAck {
				extraAcked := tracker.Update(
					bandwidth, true, getRoundTripCount(),
					lastSentPacketNumber, lastAckedPacketNumber, now, bytesPerAck)
				// |extra_acked| should be 0 if either
				// [1] We are at the beginning of a aggregation epoch(bytes==0) and the
				//     the current tracker implementation can identify it, or
				// [2] We are not really aggregating acks.
				if (bytes == 0 && expectNewAggregationEpoch) || (aggregationBandwidth == bandwidth) {
					Expect(extraAcked).To(Equal(protocol.ByteCount(0)))
				} else {
					Expect(lastExtraAcked < extraAcked).To(BeTrue())
				}
				now = now.Add(timeBetweenAcks)
				lastExtraAcked = extraAcked
			}

			// Advance past the quiet period.
			now = startTime.Add(totalDuration)
		}
	)

	BeforeEach(func() {
		tracker = newMaxAckHeightTracker(10)
		tracker.SetAckAggregationBandwidthThreshold(float64(1.8))
		tracker.SetStartNewAggregationEpochAfterFullRound(true)

		now = time.Time{}.Add(1 * time.Millisecond)
		rtt = 60 * time.Millisecond
		bandwidth = Bandwidth(10 * 1000 * 8)
		lastSentPacketNumber = protocol.InvalidPacketNumber
		lastAckedPacketNumber = protocol.InvalidPacketNumber
	})

	It("VeryAggregatedLargeAck", func() {
		aggregationEpisode(bandwidth*20, time.Duration(6*time.Millisecond), 1200, true)
		aggregationEpisode(bandwidth*20, time.Duration(6*time.Millisecond), 1200, true)
		now.Add(-1 * time.Millisecond)

		if tracker.AckAggregationBandwidthThreshold() > float64(1.1) {
			aggregationEpisode(bandwidth*20, time.Duration(6*time.Millisecond), 1200, true)
			Expect(tracker.NumAckAggregationEpochs()).To(Equal(uint64(3)))
		} else {
			aggregationEpisode(bandwidth*20, time.Duration(6*time.Millisecond), 1200, false)
			Expect(tracker.NumAckAggregationEpochs()).To(Equal(uint64(2)))
		}
	})

	It("VeryAggregatedSmallAcks", func() {
		aggregationEpisode(bandwidth*20, time.Duration(6*time.Millisecond), 300, true)
		aggregationEpisode(bandwidth*20, time.Duration(6*time.Millisecond), 300, true)
		now.Add(-1 * time.Millisecond)

		if tracker.AckAggregationBandwidthThreshold() > float64(1.1) {
			aggregationEpisode(bandwidth*20, time.Duration(6*time.Millisecond), 300, true)
			Expect(tracker.NumAckAggregationEpochs()).To(Equal(uint64(3)))
		} else {
			aggregationEpisode(bandwidth*20, time.Duration(6*time.Millisecond), 300, false)
			Expect(tracker.NumAckAggregationEpochs()).To(Equal(uint64(2)))
		}
	})

	It("SomewhatAggregatedLargeAck", func() {
		aggregationEpisode(bandwidth*2, time.Duration(50*time.Millisecond), 1000, true)
		aggregationEpisode(bandwidth*2, time.Duration(50*time.Millisecond), 1000, true)
		now.Add(-1 * time.Millisecond)

		if tracker.AckAggregationBandwidthThreshold() > float64(1.1) {
			aggregationEpisode(bandwidth*2, time.Duration(50*time.Millisecond), 1000, true)
			Expect(tracker.NumAckAggregationEpochs()).To(Equal(uint64(3)))
		} else {
			aggregationEpisode(bandwidth*2, time.Duration(50*time.Millisecond), 1000, false)
			Expect(tracker.NumAckAggregationEpochs()).To(Equal(uint64(2)))
		}
	})

	It("SomewhatAggregatedSmallAcks", func() {
		aggregationEpisode(bandwidth*2, time.Duration(50*time.Millisecond), 100, true)
		aggregationEpisode(bandwidth*2, time.Duration(50*time.Millisecond), 100, true)
		now.Add(-1 * time.Millisecond)

		if tracker.AckAggregationBandwidthThreshold() > float64(1.1) {
			aggregationEpisode(bandwidth*2, time.Duration(50*time.Millisecond), 100, true)
			Expect(tracker.NumAckAggregationEpochs()).To(Equal(uint64(3)))
		} else {
			aggregationEpisode(bandwidth*2, time.Duration(50*time.Millisecond), 100, false)
			Expect(tracker.NumAckAggregationEpochs()).To(Equal(uint64(2)))
		}
	})

	It("NotAggregated", func() {
		aggregationEpisode(bandwidth, time.Duration(100*time.Millisecond), 100, true)
		Expect(uint64(2) < tracker.NumAckAggregationEpochs()).To(BeTrue())
	})

	It("StartNewEpochAfterAFullRound", func() {
		lastSentPacketNumber = protocol.PacketNumber(10)
		aggregationEpisode(bandwidth*2, time.Duration(50*time.Millisecond), 100, true)

		lastAckedPacketNumber = protocol.PacketNumber(11)
		// Update with a tiny bandwidth causes a very low expected bytes acked, which
		// in turn causes the current epoch to continue if the |tracker_| doesn't
		// check the packet numbers.
		tracker.Update(bandwidth/10, true, getRoundTripCount(), lastSentPacketNumber, lastAckedPacketNumber, now, 100)
		Expect(tracker.NumAckAggregationEpochs()).To(Equal(uint64(2)))
	})
})

var _ = Describe("BandwidthSampler", func() {
	var (
		now                      time.Time
		sampler                  *bandwidthSampler
		regularPacketSize        protocol.ByteCount
		samplerAppLimitedAtStart bool
		bytesInFlight            protocol.ByteCount
		maxBandwidth             Bandwidth // Max observed bandwidth from acks.
		estBandwidthUpperBound   Bandwidth
		roundTripCount           roundTripCount // Needed to calculate extra_acked.

		packetsToBytes = func(packetCount int) protocol.ByteCount {
			return protocol.ByteCount(packetCount) * regularPacketSize
		}

		getPacketSize = func(packetNumber protocol.PacketNumber) protocol.ByteCount {
			return sampler.connectionStateMap.GetEntry(packetNumber).size
		}

		getNumberOfTrackedPackets = func() int {
			return sampler.connectionStateMap.NumberOfPresentEntries()
		}

		sendPacketInner = func(
			packetNumber protocol.PacketNumber,
			bytes protocol.ByteCount,
			hasRetransmittableData bool,
		) {
			sampler.OnPacketSent(now, packetNumber, bytes, bytesInFlight, hasRetransmittableData)
			if hasRetransmittableData {
				bytesInFlight += bytes
			}
		}

		sendPacket = func(packetNumber protocol.PacketNumber) {
			sendPacketInner(packetNumber, regularPacketSize, true)
		}

		makeAckedPacket = func(packetNumber protocol.PacketNumber) protocol.AckedPacketInfo {
			return protocol.AckedPacketInfo{
				PacketNumber: packetNumber,
				BytesAcked:   getPacketSize(packetNumber),
				ReceivedTime: now,
			}
		}

		ackPacketInner = func(packetNumber protocol.PacketNumber) bandwidthSample {
			size := getPacketSize(packetNumber)
			bytesInFlight -= size
			ackedPacket := makeAckedPacket(packetNumber)
			sample := sampler.OnCongestionEvent(now, []protocol.AckedPacketInfo{ackedPacket}, nil,
				maxBandwidth, estBandwidthUpperBound, roundTripCount)
			maxBandwidth = utils.Max(maxBandwidth, sample.sampleMaxBandwidth)
			bwSample := newBandwidthSample()
			bwSample.bandwidth = sample.sampleMaxBandwidth
			bwSample.rtt = sample.sampleRtt
			bwSample.stateAtSend = sample.lastPacketSendState
			Expect(bwSample.stateAtSend.isValid).To(BeTrue())
			return *bwSample
		}

		ackPacket = func(packetNumber protocol.PacketNumber) Bandwidth {
			sample := ackPacketInner(packetNumber)
			return sample.bandwidth
		}

		makeLostPacket = func(packetNumber protocol.PacketNumber) protocol.LostPacketInfo {
			return protocol.LostPacketInfo{
				PacketNumber: packetNumber,
				BytesLost:    getPacketSize(packetNumber),
			}
		}

		losePacket = func(packetNumber protocol.PacketNumber) sendTimeState {
			size := getPacketSize(packetNumber)
			bytesInFlight -= size
			lostPacket := makeLostPacket(packetNumber)
			sample := sampler.OnCongestionEvent(now, nil, []protocol.LostPacketInfo{lostPacket},
				maxBandwidth, estBandwidthUpperBound, roundTripCount)

			Expect(sample.lastPacketSendState.isValid).To(BeTrue())
			Expect(sample.sampleMaxBandwidth).To(Equal(Bandwidth(0)))
			Expect(sample.sampleRtt).To(Equal(infRTT))
			return sample.lastPacketSendState
		}

		onCongestionEvent = func(ackedPacketNumbers, lostPacketNumbers []protocol.PacketNumber) congestionEventSample {
			ackedPackets := []protocol.AckedPacketInfo{}
			for _, packetNumber := range ackedPacketNumbers {
				ackedPacket := makeAckedPacket(packetNumber)
				ackedPackets = append(ackedPackets, makeAckedPacket(packetNumber))
				bytesInFlight -= ackedPacket.BytesAcked
			}
			lostPackets := []protocol.LostPacketInfo{}
			for _, packetNumber := range lostPacketNumbers {
				lostPacket := makeLostPacket(packetNumber)
				lostPackets = append(lostPackets, lostPacket)
				bytesInFlight -= lostPacket.BytesLost
			}

			sample := sampler.OnCongestionEvent(now, ackedPackets, lostPackets,
				maxBandwidth, estBandwidthUpperBound, roundTripCount)
			maxBandwidth = utils.Max(maxBandwidth, sample.sampleMaxBandwidth)
			return sample
		}

		// Sends one packet and acks it.  Then, send 20 packets.  Finally, send
		// another 20 packets while acknowledging previous 20.
		send40PacketsAndAckFirst20 = func(timeBetweenPackets time.Duration) {
			// Send 20 packets at a constant inter-packet time.
			for i := 1; i <= 20; i++ {
				sendPacket(protocol.PacketNumber(i))
				now = now.Add(timeBetweenPackets)
			}

			// Ack packets 1 to 20, while sending new packets at the same rate as
			// before.
			for i := 1; i <= 20; i++ {
				ackPacket(protocol.PacketNumber(i))
				sendPacket(protocol.PacketNumber(i + 20))
				now = now.Add(timeBetweenPackets)
			}
		}

		testParameters = []struct {
			overestimateAvoidance bool
		}{
			{
				overestimateAvoidance: false,
			},
			{
				overestimateAvoidance: true,
			},
		}

		initial = func(param struct {
			overestimateAvoidance bool
		}) {
			// Ensure that the clock does not start at zero.
			now = time.Time{}.Add(1 * time.Second)
			sampler = newBandwidthSampler(0)
			regularPacketSize = protocol.ByteCount(1280)
			samplerAppLimitedAtStart = false
			bytesInFlight = protocol.ByteCount(0)
			maxBandwidth = 0
			estBandwidthUpperBound = infBandwidth
			roundTripCount = 0

			if param.overestimateAvoidance {
				sampler.EnableOverestimateAvoidance()
			}
		}
	)

	// Test the sampler in a simple stop-and-wait sender setting.
	It("SendAndWait", func() {
		for _, param := range testParameters {
			initial(param)

			timeBetweenPackets := 10 * time.Millisecond
			expectedBandwidth := Bandwidth(regularPacketSize) * 100 * BytesPerSecond

			// Send packets at the constant bandwidth.
			for i := 1; i < 20; i++ {
				sendPacket(protocol.PacketNumber(i))
				now = now.Add(timeBetweenPackets)
				currentSample := ackPacket(protocol.PacketNumber(i))
				Expect(expectedBandwidth).To(Equal(currentSample))
			}

			// Send packets at the exponentially decreasing bandwidth.
			for i := 20; i < 25; i++ {
				timeBetweenPackets *= 2
				expectedBandwidth /= 2

				sendPacket(protocol.PacketNumber(i))
				now = now.Add(timeBetweenPackets)
				currentSample := ackPacket(protocol.PacketNumber(i))
				Expect(expectedBandwidth).To(Equal(currentSample))
			}
			sampler.RemoveObsoletePackets(protocol.PacketNumber(25))

			Expect(getNumberOfTrackedPackets()).To(Equal(int(0)))
			Expect(bytesInFlight).To(Equal(protocol.ByteCount(0)))
		}
	})

	It("SendTimeState", func() {
		for _, param := range testParameters {
			initial(param)

			timeBetweenPackets := 10 * time.Millisecond

			// Send packets 1-5.
			for i := 1; i <= 5; i++ {
				sendPacket(protocol.PacketNumber(i))
				Expect(packetsToBytes(i)).To(Equal(sampler.TotalBytesSent()))
				now = now.Add(timeBetweenPackets)
			}

			// Ack packet 1.
			sendTimeState := ackPacketInner(protocol.PacketNumber(1)).stateAtSend
			Expect(packetsToBytes(1)).To(Equal(sendTimeState.totalBytesSent))
			Expect(sendTimeState.totalBytesAcked).To(Equal(protocol.ByteCount(0)))
			Expect(sendTimeState.totalBytesLost).To(Equal(protocol.ByteCount(0)))
			Expect(packetsToBytes(1)).To(Equal(sampler.TotalBytesAcked()))

			// Lose packet 2.
			sendTimeState = losePacket(protocol.PacketNumber(2))
			Expect(packetsToBytes(2)).To(Equal(sendTimeState.totalBytesSent))
			Expect(sendTimeState.totalBytesAcked).To(Equal(protocol.ByteCount(0)))
			Expect(sendTimeState.totalBytesLost).To(Equal(protocol.ByteCount(0)))
			Expect(packetsToBytes(1)).To(Equal(sampler.TotalBytesLost()))

			// Lose packet 3.
			sendTimeState = losePacket(protocol.PacketNumber(3))
			Expect(packetsToBytes(3)).To(Equal(sendTimeState.totalBytesSent))
			Expect(sendTimeState.totalBytesAcked).To(Equal(protocol.ByteCount(0)))
			Expect(sendTimeState.totalBytesLost).To(Equal(protocol.ByteCount(0)))
			Expect(packetsToBytes(2)).To(Equal(sampler.TotalBytesLost()))

			// Send packets 6-10.
			for i := 6; i <= 10; i++ {
				sendPacket(protocol.PacketNumber(i))
				Expect(packetsToBytes(i)).To(Equal(sampler.TotalBytesSent()))
				now = now.Add(timeBetweenPackets)
			}

			// Ack all inflight packets.
			ackedPacketCount := 1
			Expect(packetsToBytes(ackedPacketCount)).To(Equal(sampler.TotalBytesAcked()))
			for i := 4; i <= 10; i++ {
				sendTimeState = ackPacketInner(protocol.PacketNumber(i)).stateAtSend
				ackedPacketCount++
				Expect(packetsToBytes(ackedPacketCount)).To(Equal(sampler.TotalBytesAcked()))
				Expect(packetsToBytes(i)).To(Equal(sendTimeState.totalBytesSent))
				if i <= 5 {
					Expect(sendTimeState.totalBytesAcked).To(Equal(protocol.ByteCount(0)))
					Expect(sendTimeState.totalBytesLost).To(Equal(protocol.ByteCount(0)))
				} else {
					Expect(sendTimeState.totalBytesAcked).To(Equal(packetsToBytes(1)))
					Expect(sendTimeState.totalBytesLost).To(Equal(packetsToBytes(2)))
				}

				// This equation works because there is no neutered bytes.
				Expect(sendTimeState.totalBytesSent - sendTimeState.totalBytesAcked - sendTimeState.totalBytesLost).
					To(Equal(sendTimeState.bytesInFlight))

				now = now.Add(timeBetweenPackets)
			}
		}
	})

	// Test the sampler during regular windowed sender scenario with fixed
	// CWND of 20.
	It("SendPaced", func() {
		for _, param := range testParameters {
			initial(param)

			timeBetweenPackets := 1 * time.Millisecond
			expectedBandwidth := Bandwidth(regularPacketSize) * 1000 * BytesPerSecond

			send40PacketsAndAckFirst20(timeBetweenPackets)

			// Ack the packets 21 to 40, arriving at the correct bandwidth.
			var lastBandwidth Bandwidth
			for i := 21; i <= 40; i++ {
				lastBandwidth = ackPacket(protocol.PacketNumber(i))
				Expect(expectedBandwidth).To(Equal(lastBandwidth))
				now = now.Add(timeBetweenPackets)
			}
			sampler.RemoveObsoletePackets(protocol.PacketNumber(41))

			Expect(getNumberOfTrackedPackets()).To(Equal(0))
			Expect(bytesInFlight).To(Equal(protocol.ByteCount(0)))
		}
	})

	// Test the sampler in a scenario where 50% of packets is consistently lost.
	It("SendWithLosses", func() {
		for _, param := range testParameters {
			initial(param)

			timeBetweenPackets := 1 * time.Millisecond
			expectedBandwidth := Bandwidth(regularPacketSize) * 500 * BytesPerSecond

			// Send 20 packets, each 1 ms apart.
			for i := 1; i <= 20; i++ {
				sendPacket(protocol.PacketNumber(i))
				now = now.Add(timeBetweenPackets)
			}

			// Ack packets 1 to 20, losing every even-numbered packet, while sending new
			// packets at the same rate as before.
			for i := 1; i <= 20; i++ {
				if i%2 == 0 {
					ackPacket(protocol.PacketNumber(i))
				} else {
					losePacket(protocol.PacketNumber(i))
				}
				sendPacket(protocol.PacketNumber(i + 20))
				now = now.Add(timeBetweenPackets)
			}

			// Ack the packets 21 to 40 with the same loss pattern.
			var lastBandwidth Bandwidth
			for i := 21; i <= 40; i++ {
				if i%2 == 0 {
					lastBandwidth = ackPacket(protocol.PacketNumber(i))
					Expect(expectedBandwidth).To(Equal(lastBandwidth))
				} else {
					losePacket(protocol.PacketNumber(i))
				}

				now = now.Add(timeBetweenPackets)
			}
			sampler.RemoveObsoletePackets(protocol.PacketNumber(41))

			Expect(getNumberOfTrackedPackets()).To(Equal(0))
			Expect(bytesInFlight).To(Equal(protocol.ByteCount(0)))
		}
	})

	// Test the sampler in a scenario where the 50% of packets are not
	// congestion controlled (specifically, non-retransmittable data is not
	// congestion controlled).  Should be functionally consistent in behavior with
	// the SendWithLosses test.
	It("NotCongestionControlled", func() {
		for _, param := range testParameters {
			initial(param)

			timeBetweenPackets := 1 * time.Millisecond
			expectedBandwidth := Bandwidth(regularPacketSize) * 500 * BytesPerSecond

			// Send 20 packets, each 1 ms apart. Every even packet is not congestion
			// controlled.
			for i := 1; i <= 20; i++ {
				sendPacketInner(protocol.PacketNumber(i), regularPacketSize, i%2 == 0)
				now = now.Add(timeBetweenPackets)
			}

			// Ensure only congestion controlled packets are tracked.
			Expect(getNumberOfTrackedPackets()).To(Equal(10))

			// Ack packets 2 to 21, ignoring every even-numbered packet, while sending new
			// packets at the same rate as before.
			for i := 1; i <= 20; i++ {
				if i%2 == 0 {
					ackPacket(protocol.PacketNumber(i))
				}
				sendPacketInner(protocol.PacketNumber(i+20), regularPacketSize, i%2 == 0)
				now = now.Add(timeBetweenPackets)
			}

			// Ack the packets 22 to 41 with the same congestion controlled pattern.
			var lastBandwidth Bandwidth
			for i := 21; i <= 40; i++ {
				if i%2 == 0 {
					lastBandwidth = ackPacket(protocol.PacketNumber(i))
					Expect(expectedBandwidth).To(Equal(lastBandwidth))
				}
				now = now.Add(timeBetweenPackets)
			}
			sampler.RemoveObsoletePackets(protocol.PacketNumber(41))

			// Since only congestion controlled packets are entered into the map, it has
			// to be empty at this point.
			Expect(getNumberOfTrackedPackets()).To(Equal(0))
			Expect(bytesInFlight).To(Equal(protocol.ByteCount(0)))
		}
	})

	// Simulate a situation where ACKs arrive in burst and earlier than usual, thus
	// producing an ACK rate which is higher than the original send rate.
	It("CompressedAck", func() {
		for _, param := range testParameters {
			initial(param)

			timeBetweenPackets := 1 * time.Millisecond
			expectedBandwidth := Bandwidth(regularPacketSize) * 1000 * BytesPerSecond

			send40PacketsAndAckFirst20(timeBetweenPackets)

			// Simulate an RTT somewhat lower than the one for 1-to-21 transmission.
			now = now.Add(timeBetweenPackets * 15)

			// Ack the packets 21 to 40 almost immediately at once.
			var lastBandwidth Bandwidth
			ridiculouslySmallTimeDelta := 20 * time.Microsecond
			for i := 21; i <= 40; i++ {
				lastBandwidth = ackPacket(protocol.PacketNumber(i))
				now = now.Add(ridiculouslySmallTimeDelta)
			}
			Expect(expectedBandwidth).To(Equal(lastBandwidth))

			sampler.RemoveObsoletePackets(protocol.PacketNumber(41))

			Expect(getNumberOfTrackedPackets()).To(Equal(0))
			Expect(bytesInFlight).To(Equal(protocol.ByteCount(0)))
		}
	})

	// Tests receiving ACK packets in the reverse order.
	It("ReorderedAck", func() {
		for _, param := range testParameters {
			initial(param)

			timeBetweenPackets := 1 * time.Millisecond
			expectedBandwidth := Bandwidth(regularPacketSize) * 1000 * BytesPerSecond

			send40PacketsAndAckFirst20(timeBetweenPackets)

			// Ack the packets 21 to 40 in the reverse order, while sending packets 41 to
			// 60.
			var lastBandwidth Bandwidth
			for i := 0; i < 20; i++ {
				lastBandwidth = ackPacket(protocol.PacketNumber(40 - i))
				Expect(expectedBandwidth).To(Equal(lastBandwidth))
				sendPacket(protocol.PacketNumber(41 + i))
				now = now.Add(timeBetweenPackets)
			}

			for i := 41; i <= 60; i++ {
				lastBandwidth = ackPacket(protocol.PacketNumber(i))
				Expect(expectedBandwidth).To(Equal(lastBandwidth))
				now = now.Add(timeBetweenPackets)
			}
			sampler.RemoveObsoletePackets(protocol.PacketNumber(61))

			Expect(getNumberOfTrackedPackets()).To(Equal(0))
			Expect(bytesInFlight).To(Equal(protocol.ByteCount(0)))
		}
	})

	// Test the app-limited logic.
	It("AppLimited", func() {
		for _, param := range testParameters {
			initial(param)

			timeBetweenPackets := 1 * time.Millisecond
			expectedBandwidth := Bandwidth(regularPacketSize) * 1000 * BytesPerSecond

			// Send 20 packets at a constant inter-packet time.
			for i := 1; i <= 20; i++ {
				sendPacket(protocol.PacketNumber(i))
				now = now.Add(timeBetweenPackets)
			}

			// Ack packets 1 to 20, while sending new packets at the same rate as
			// before.
			for i := 1; i <= 20; i++ {
				sample := ackPacketInner(protocol.PacketNumber(i))
				Expect(sample.stateAtSend.isAppLimited).To(Equal(samplerAppLimitedAtStart))
				sendPacket(protocol.PacketNumber(i + 20))
				now = now.Add(timeBetweenPackets)
			}

			// We are now app-limited. Ack 21 to 40 as usual, but do not send anything for
			// now.
			sampler.OnAppLimited()
			for i := 21; i <= 40; i++ {
				sample := ackPacketInner(protocol.PacketNumber(i))
				Expect(sample.stateAtSend.isAppLimited).To(BeFalse())
				Expect(expectedBandwidth).To(Equal(sample.bandwidth))
				now = now.Add(timeBetweenPackets)
			}

			// Enter quiescence.
			now = now.Add(1 * time.Second)

			// Send packets 41 to 60, all of which would be marked as app-limited.
			for i := 41; i <= 60; i++ {
				sendPacket(protocol.PacketNumber(i))
				now = now.Add(timeBetweenPackets)
			}

			// Ack packets 41 to 60, while sending packets 61 to 80.  41 to 60 should be
			// app-limited and underestimate the bandwidth due to that.
			for i := 41; i <= 60; i++ {
				sample := ackPacketInner(protocol.PacketNumber(i))
				Expect(sample.stateAtSend.isAppLimited).To(BeTrue())
				Expect(sample.bandwidth < expectedBandwidth*7/10).To(BeTrue())
				sendPacket(protocol.PacketNumber(i + 20))
				now = now.Add(timeBetweenPackets)
			}

			// Run out of packets, and then ack packet 61 to 80, all of which should have
			// correct non-app-limited samples.
			for i := 61; i <= 80; i++ {
				sample := ackPacketInner(protocol.PacketNumber(i))
				Expect(sample.stateAtSend.isAppLimited).To(BeFalse())
				Expect(expectedBandwidth).To(Equal(sample.bandwidth))
				now = now.Add(timeBetweenPackets)
			}
			sampler.RemoveObsoletePackets(protocol.PacketNumber(81))

			Expect(getNumberOfTrackedPackets()).To(Equal(0))
			Expect(bytesInFlight).To(Equal(protocol.ByteCount(0)))
		}
	})

	// Test the samples taken at the first flight of packets sent.
	It("FirstRoundTrip", func() {
		for _, param := range testParameters {
			initial(param)

			timeBetweenPackets := 1 * time.Millisecond
			rtt := 800 * time.Millisecond
			numPackets := 10
			numBytes := regularPacketSize * protocol.ByteCount(numPackets)
			realBandwidth := BandwidthFromDelta(numBytes, rtt)

			for i := 1; i <= 10; i++ {
				sendPacket(protocol.PacketNumber(i))
				now = now.Add(timeBetweenPackets)
			}

			now = now.Add(rtt - time.Duration(numPackets)*timeBetweenPackets)

			var lastSample Bandwidth
			for i := 1; i <= 10; i++ {
				sample := ackPacket(protocol.PacketNumber(i))
				Expect(sample > lastSample).To(BeTrue())
				lastSample = sample
				now = now.Add(timeBetweenPackets)
			}

			// The final measured sample for the first flight of sample is expected to be
			// smaller than the real bandwidth, yet it should not lose more than 10%. The
			// specific value of the error depends on the difference between the RTT and
			// the time it takes to exhaust the congestion window (i.e. in the limit when
			// all packets are sent simultaneously, last sample would indicate the real
			// bandwidth).
			Expect(lastSample < realBandwidth).To(BeTrue())
			Expect(lastSample > realBandwidth*9/10).To(BeTrue())
		}
	})

	// Test sampler's ability to remove obsolete packets.
	It("RemoveObsoletePackets", func() {
		for _, param := range testParameters {
			initial(param)

			for i := 1; i <= 5; i++ {
				sendPacket(protocol.PacketNumber(i))
			}

			now = now.Add(100 * time.Millisecond)

			Expect(getNumberOfTrackedPackets()).To(Equal(5))
			sampler.RemoveObsoletePackets(protocol.PacketNumber(4))
			Expect(getNumberOfTrackedPackets()).To(Equal(2))
			losePacket(protocol.PacketNumber(4))
			sampler.RemoveObsoletePackets(protocol.PacketNumber(5))

			Expect(getNumberOfTrackedPackets()).To(Equal(1))
			ackPacket(protocol.PacketNumber(5))

			sampler.RemoveObsoletePackets(protocol.PacketNumber(6))

			Expect(getNumberOfTrackedPackets()).To(Equal(0))
		}
	})

	It("NeuterPacket", func() {
		for _, param := range testParameters {
			initial(param)

			sendPacket(protocol.PacketNumber(1))
			Expect(sampler.TotalBytesNeutered()).To(Equal(protocol.ByteCount(0)))

			now = now.Add(10 * time.Millisecond)
			sampler.OnPacketNeutered(protocol.PacketNumber(1))

			Expect(sampler.TotalBytesNeutered() > 0).To(BeTrue())
			Expect(sampler.TotalBytesAcked() == 0).To(BeTrue())

			// If packet 1 is acked it should not produce a bandwidth sample.
			now = now.Add(10 * time.Millisecond)
			sample := sampler.OnCongestionEvent(now, []protocol.AckedPacketInfo{{
				PacketNumber: protocol.PacketNumber(1),
				BytesAcked:   regularPacketSize,
				ReceivedTime: now,
			}}, nil, maxBandwidth, estBandwidthUpperBound, roundTripCount)

			Expect(sampler.TotalBytesAcked() == 0).To(BeTrue())
			Expect(sample.sampleMaxBandwidth == 0).To(BeTrue())

			Expect(sample.sampleIsAppLimited).To(BeFalse())
			Expect(sample.sampleRtt == infRTT).To(BeTrue())
			Expect(sample.sampleMaxInflight == 0).To(BeTrue())
			Expect(sample.extraAcked == 0).To(BeTrue())
		}
	})

	It("CongestionEventSampleDefaultValues", func() {
		for _, param := range testParameters {
			initial(param)

			// Make sure a default constructed CongestionEventSample has the correct
			// initial values for BandwidthSampler::OnCongestionEvent() to work.
			sample := newCongestionEventSample()

			Expect(sample.sampleMaxBandwidth == 0).To(BeTrue())
			Expect(sample.sampleIsAppLimited).To(BeFalse())
			Expect(sample.sampleRtt == infRTT).To(BeTrue())
			Expect(sample.sampleMaxInflight == 0).To(BeTrue())
			Expect(sample.extraAcked == 0).To(BeTrue())
		}
	})

	// 1) Send 2 packets, 2) Ack both in 1 event, 3) Repeat.
	It("TwoAckedPacketsPerEvent", func() {
		for _, param := range testParameters {
			initial(param)

			timeBetweenPackets := 10 * time.Millisecond
			sendingRate := BandwidthFromDelta(regularPacketSize, timeBetweenPackets)

			for i := 1; i < 21; i++ {
				sendPacket(protocol.PacketNumber(i))
				now = now.Add(timeBetweenPackets)
				if i%2 != 0 {
					continue
				}

				sample := onCongestionEvent([]protocol.PacketNumber{
					protocol.PacketNumber(i - 1),
					protocol.PacketNumber(i),
				}, []protocol.PacketNumber{})

				Expect(sendingRate == sample.sampleMaxBandwidth).To(BeTrue())
				Expect(timeBetweenPackets == sample.sampleRtt).To(BeTrue())
				Expect(2*regularPacketSize == sample.sampleMaxInflight).To(BeTrue())
				Expect(sample.lastPacketSendState.isValid).To(BeTrue())
				Expect(2*regularPacketSize == sample.lastPacketSendState.bytesInFlight).To(BeTrue())
				Expect(protocol.ByteCount(i)*regularPacketSize == sample.lastPacketSendState.totalBytesSent).To(BeTrue())
				Expect(protocol.ByteCount(i-2)*regularPacketSize == sample.lastPacketSendState.totalBytesAcked).To(BeTrue())
				Expect(sample.lastPacketSendState.totalBytesLost == 0).To(BeTrue())
				sampler.RemoveObsoletePackets(protocol.PacketNumber(i - 2))
			}
		}
	})

	It("LoseEveryOtherPacket", func() {
		for _, param := range testParameters {
			initial(param)

			timeBetweenPackets := 10 * time.Millisecond
			sendingRate := BandwidthFromDelta(regularPacketSize, timeBetweenPackets)

			for i := 1; i < 21; i++ {
				sendPacket(protocol.PacketNumber(i))
				now = now.Add(timeBetweenPackets)
				if i%2 != 0 {
					continue
				}

				// Ack packet i and lose i-1.
				sample := onCongestionEvent([]protocol.PacketNumber{
					protocol.PacketNumber(i),
				}, []protocol.PacketNumber{
					protocol.PacketNumber(i - 1),
				})
				// Losing 50% packets means sending rate is twice the bandwidth.
				Expect(sendingRate == sample.sampleMaxBandwidth*2).To(BeTrue())
				Expect(timeBetweenPackets == sample.sampleRtt).To(BeTrue())
				Expect(regularPacketSize == sample.sampleMaxInflight).To(BeTrue())
				Expect(sample.lastPacketSendState.isValid).To(BeTrue())
				Expect(2*regularPacketSize == sample.lastPacketSendState.bytesInFlight).To(BeTrue())
				Expect(protocol.ByteCount(i)*regularPacketSize == sample.lastPacketSendState.totalBytesSent).To(BeTrue())
				Expect(protocol.ByteCount(i-2)*regularPacketSize/2 == sample.lastPacketSendState.totalBytesAcked).To(BeTrue())
				Expect(protocol.ByteCount(i-2)*regularPacketSize/2 == sample.lastPacketSendState.totalBytesLost).To(BeTrue())
				sampler.RemoveObsoletePackets(protocol.PacketNumber(i - 2))
			}
		}
	})

	It("AckHeightRespectBandwidthEstimateUpperBound", func() {
		for _, param := range testParameters {
			initial(param)

			timeBetweenPackets := 10 * time.Millisecond
			firstPacketSendingRate := BandwidthFromDelta(regularPacketSize, timeBetweenPackets)

			// Send packets 1 to 4 and ack packet 1.
			sendPacket(protocol.PacketNumber(1))
			now = now.Add(timeBetweenPackets)
			sendPacket(protocol.PacketNumber(2))
			sendPacket(protocol.PacketNumber(3))
			sendPacket(protocol.PacketNumber(4))
			sample := onCongestionEvent([]protocol.PacketNumber{
				protocol.PacketNumber(1),
			}, []protocol.PacketNumber{})
			Expect(firstPacketSendingRate == sample.sampleMaxBandwidth).To(BeTrue())
			Expect(firstPacketSendingRate == maxBandwidth).To(BeTrue())

			// Ack packet 2, 3 and 4, all of which uses S(1) to calculate ack rate since
			// there were no acks at the time they were sent.
			roundTripCount++
			estBandwidthUpperBound = firstPacketSendingRate * 3 / 10
			now = now.Add(timeBetweenPackets)
			sample = onCongestionEvent([]protocol.PacketNumber{
				protocol.PacketNumber(2),
				protocol.PacketNumber(3),
				protocol.PacketNumber(4),
			}, []protocol.PacketNumber{})
			Expect(firstPacketSendingRate*2 == sample.sampleMaxBandwidth).To(BeTrue())
			Expect(sample.sampleMaxBandwidth == maxBandwidth).To(BeTrue())

			Expect(2*regularPacketSize < sample.extraAcked).To(BeTrue())
		}
	})
})
