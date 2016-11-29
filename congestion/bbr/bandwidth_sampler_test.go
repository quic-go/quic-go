package bbr

import (
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const regularPacketSize protocol.ByteCount = 1280 // has to be five times divisible by 2

var _ = Describe("Bandwidth Sampler", func() {
	var (
		clock         time.Time
		sampler       bandwidthSampler
		bytesInFlight protocol.ByteCount
	)

	BeforeEach(func() {
		sampler = newBandwidthSampler()
		clock = time.Now()
		bytesInFlight = 0
	})

	getPacketSize := func(p protocol.PacketNumber) protocol.ByteCount {
		Expect(sampler.connectionStateMap).To(HaveKey(p))
		Expect(sampler.connectionStateMap[p].size).To(Equal(regularPacketSize))
		return sampler.connectionStateMap[p].size
	}

	sendPacket := func(p protocol.PacketNumber, hasRetransmittableData bool) {
		sampler.OnPacketSent(clock, p, regularPacketSize, bytesInFlight, hasRetransmittableData)

		if hasRetransmittableData {
			bytesInFlight += regularPacketSize
		}
	}

	ackPacketInner := func(p protocol.PacketNumber) bandwidthSample {
		bytesInFlight -= getPacketSize(p)
		return sampler.OnPacketAcknowledged(clock, p)
	}

	ackPacket := func(p protocol.PacketNumber) bandwidthSample {
		sample := ackPacketInner(p)
		Expect(sample.isAppLimited).To(BeFalse())
		return sample
	}

	losePacket := func(p protocol.PacketNumber) {
		bytesInFlight -= getPacketSize(p)
		sampler.OnPacketLost(p)
	}

	// Sends one packet and acks it.  Then, send 20 packets.  Finally, send
	// another 20 packets while acknowledging previous 20.
	send40PacketsAndAckFirst20 := func(timeBetweenPackets time.Duration) {
		// Send 20 packets at a constant inter-packet time.
		for p := protocol.PacketNumber(1); p <= 20; p++ {
			sendPacket(p, true)
			clock = clock.Add(timeBetweenPackets)
		}

		// Ack packets 1 to 20, while sending new packets at the same rate as before
		for p := protocol.PacketNumber(1); p <= 20; p++ {
			ackPacket(p)
			sendPacket(p+20, true)
			clock = clock.Add(timeBetweenPackets)
		}
	}

	It("test the sampler in a simple stop-and-wait sender setting", func() {
		timeBetweenPackets := 10 * time.Millisecond

		// Send packets at the constant bandwidth
		expectedBandwidth := protocol.BandwidthFromDelta(regularPacketSize*100, time.Second)
		p := protocol.PacketNumber(1)
		for ; p < 20; p++ {
			sendPacket(p, true)
			clock = clock.Add(timeBetweenPackets)
			currentSample := ackPacket(p)
			Expect(currentSample.bandwidth).To(Equal(expectedBandwidth))
		}

		// Send packets at the exponentially decreasing bandwidth.
		for p = 20; p < 25; p++ {
			timeBetweenPackets *= 2
			expectedBandwidth = expectedBandwidth / 2
			sendPacket(p, true)
			clock = clock.Add(timeBetweenPackets)
			currentSample := ackPacket(p)
			Expect(currentSample.bandwidth).To(Equal(expectedBandwidth))
		}

		Expect(sampler.connectionStateMap).To(HaveLen(0))
		Expect(bytesInFlight).To(BeZero())
	})

	It("tests the sampler during regular windowed sender scenario with fixed CWND of 20", func() {
		timeBetweenPackets := time.Millisecond
		expectedBandwidth := protocol.BandwidthFromDelta(regularPacketSize, timeBetweenPackets)
		send40PacketsAndAckFirst20(timeBetweenPackets)

		// Ack the packets 21 to 40, arriving at the correct bandwidth.
		for i := protocol.PacketNumber(21); i <= 40; i++ {
			sample := ackPacket(i)
			Expect(sample.bandwidth).To(Equal(expectedBandwidth))
			clock = clock.Add(timeBetweenPackets)
		}

		Expect(sampler.connectionStateMap).To(HaveLen(0))
		Expect(bytesInFlight).To(BeZero())
	})

	It("test the sampler in a scenario where 50% of packets is consistently lost", func() {
		timeBetweenPackets := time.Millisecond
		expectedBandwidth := protocol.BandwidthFromDelta(regularPacketSize, timeBetweenPackets) / 2

		// Send 20 packets, each 1 ms apart.
		for i := protocol.PacketNumber(1); i <= 20; i++ {
			sendPacket(i, true)
			clock = clock.Add(timeBetweenPackets)
		}

		// Ack packets 1 to 20, losing every even-numbered packet, while sending new
		// packets at the same rate as before.
		for i := protocol.PacketNumber(1); i <= 20; i++ {
			if i%2 == 0 {
				ackPacket(i)
			} else {
				losePacket(i)
			}
			sendPacket(i+20, true)
			clock = clock.Add(timeBetweenPackets)
		}

		// Ack the packets 21 to 40 with the same loss pattern.
		for i := protocol.PacketNumber(21); i <= 40; i++ {
			if i%2 == 0 {
				sample := ackPacket(i)
				Expect(sample.bandwidth).To(Equal(expectedBandwidth))
			} else {
				losePacket(i)
			}
			clock = clock.Add(timeBetweenPackets)
		}

		Expect(sampler.connectionStateMap).To(HaveLen(0))
		Expect(bytesInFlight).To(BeZero())
	})

	// Should be functionally consistent in behavior with the SendWithLosses test.
	It("tests the sampler in a scenario where the 50% of packets are not congestion controlled", func() {
		timeBetweenPackets := time.Millisecond
		expectedBandwidth := protocol.BandwidthFromDelta(regularPacketSize, timeBetweenPackets) / 2

		// Send 20 packets, each 1 ms apart. Every even packet is not congestion
		// controlled.
		for i := protocol.PacketNumber(1); i <= 20; i++ {
			retransmittable := (i%2 == 0)
			sendPacket(i, retransmittable)
			clock = clock.Add(timeBetweenPackets)
		}

		// Ensure only congestion controlled packets are tracked.
		Expect(sampler.connectionStateMap).To(HaveLen(10))

		// Ack packets 2 to 21, ignoring every even-numbered packet, while sending new
		// packets at the same rate as before.
		for i := protocol.PacketNumber(1); i <= 20; i++ {
			if i%2 == 0 {
				ackPacket(i)
			}
			retransmittable := (i%2 == 0)
			sendPacket(i+20, retransmittable)
			clock = clock.Add(timeBetweenPackets)
		}

		// Ack the packets 22 to 41 with the same congestion controlled pattern.
		for i := protocol.PacketNumber(21); i <= 40; i++ {
			if i%2 == 0 {
				sample := ackPacket(i)
				Expect(sample.bandwidth).To(Equal(expectedBandwidth))
			}
			clock = clock.Add(timeBetweenPackets)
		}

		// Since only congestion controlled packets are entered into the map, it has
		// to be empty at this point.
		Expect(sampler.connectionStateMap).To(HaveLen(0))
		Expect(bytesInFlight).To(BeZero())
	})

	It("Simulate a situation where ACKs arrive in burst and earlier than usual, thus producing an ACK rate which is higher than the original send rate", func() {
		timeBetweenPackets := time.Millisecond
		expectedBandwidth := protocol.BandwidthFromDelta(regularPacketSize, timeBetweenPackets)

		send40PacketsAndAckFirst20(timeBetweenPackets)
		// Simulate an RTT somewhat lower than the one for 1-to-21 transmission.
		clock = clock.Add(15 * timeBetweenPackets)

		// Ack the packets 21 to 40 almost immediately at once.
		var lastBandwidth protocol.Bandwidth
		// this value is higher than in Chrome, because this test otherfails on the CIs
		ridiculouslySmallTimeDelta := 200 * time.Microsecond
		for i := protocol.PacketNumber(21); i <= 40; i++ {
			sample := ackPacket(i)
			lastBandwidth = sample.bandwidth
			clock = clock.Add(ridiculouslySmallTimeDelta)
		}

		Expect(lastBandwidth).To(Equal(expectedBandwidth))
		Expect(sampler.connectionStateMap).To(HaveLen(0))
		Expect(bytesInFlight).To(BeZero())
	})

	It("tests receiving ACK packets in the reverse order", func() {
		timeBetweenPackets := time.Millisecond
		expectedBandwidth := protocol.BandwidthFromDelta(regularPacketSize, timeBetweenPackets)

		send40PacketsAndAckFirst20(timeBetweenPackets)

		// Ack the packets 21 to 40 in the reverse order, while sending packets 41 to 60
		for i := protocol.PacketNumber(0); i < 20; i++ {
			sample := ackPacket(40 - i)
			Expect(sample.bandwidth).To(Equal(expectedBandwidth))
			sendPacket(41+i, true)
			clock = clock.Add(timeBetweenPackets)
		}

		// Ack the packets 41 to 60, now in the regular order.
		for i := protocol.PacketNumber(41); i <= 60; i++ {
			sample := ackPacket(i)
			Expect(sample.bandwidth).To(Equal(expectedBandwidth))
		}

		Expect(sampler.connectionStateMap).To(HaveLen(0))
		Expect(bytesInFlight).To(BeZero())
	})

	It("tests the app-limited logic", func() {
		timeBetweenPackets := time.Millisecond
		expectedBandwidth := protocol.BandwidthFromDelta(regularPacketSize, timeBetweenPackets)

		send40PacketsAndAckFirst20(timeBetweenPackets)
		// We are now app-limited. Ack 21 to 40 as usual, but do not send anything for now
		sampler.OnAppLimited()
		for i := protocol.PacketNumber(21); i <= 40; i++ {
			currentSample := ackPacket(i)
			Expect(currentSample.bandwidth).To(Equal(expectedBandwidth))
			clock = clock.Add(timeBetweenPackets)
		}

		// Enter quiescence.
		clock = clock.Add(time.Second)

		// Send packets 41 to 60, all of which would be marked as app-limited.
		for i := protocol.PacketNumber(41); i <= 60; i++ {
			sendPacket(i, true)
			clock = clock.Add(timeBetweenPackets)
		}

		// Ack packets 41 to 60, while sending packets 61 to 80.  41 to 60 should be
		// app-limited and underestimate the bandwidth due to that.
		for i := protocol.PacketNumber(41); i <= 60; i++ {
			sample := ackPacketInner(i)
			Expect(sample.isAppLimited).To(BeTrue())
			Expect(sample.bandwidth).To(BeNumerically("<", expectedBandwidth*7/10))

			sendPacket(i+20, true)
			clock = clock.Add(timeBetweenPackets)
		}

		// Run out of packets, and then ack packet 61 to 80, all of which should have
		// correct non-app-limited samples.
		for i := protocol.PacketNumber(61); i <= 80; i++ {
			sample := ackPacket(i)
			Expect(sample.bandwidth).To(Equal(expectedBandwidth))
			clock = clock.Add(timeBetweenPackets)
		}

		Expect(sampler.connectionStateMap).To(HaveLen(0))
		Expect(bytesInFlight).To(BeZero())
	})

	It("test the samples taken at the first flight of packets sent", func() {
		timeBetweenPackets := time.Millisecond
		rtt := 800 * time.Millisecond
		numPackets := 10
		numBytes := protocol.ByteCount(numPackets) * regularPacketSize
		realBandwidth := protocol.BandwidthFromDelta(numBytes, rtt)

		for i := protocol.PacketNumber(1); i <= 10; i++ {
			sendPacket(i, true)
			clock = clock.Add(timeBetweenPackets)
		}

		clock = clock.Add(rtt - time.Duration(numPackets)*timeBetweenPackets)

		var lastSample protocol.Bandwidth
		for i := protocol.PacketNumber(1); i <= 10; i++ {
			sample := ackPacket(i)
			Expect(sample.bandwidth).To(BeNumerically(">", lastSample))
			lastSample = sample.bandwidth
			clock = clock.Add(timeBetweenPackets)
		}

		// The final measured sample for the first flight of sample is expected to be
		// smaller than the real bandwidth, yet it should not lose more than 10%. The
		// specific value of the error depends on the difference between the RTT and
		// the time it takes to exhaust the congestion window (i.e. in the limit when
		// all packets are sent simultaneously, last sample would indicate the real
		// bandwidth).
		Expect(lastSample).To(BeNumerically("<", realBandwidth))
		Expect(lastSample).To(BeNumerically(">", realBandwidth*9/10))
	})

	It("test sampler's ability to remove obsolete packets", func() {
		sendPacket(1, true)
		sendPacket(2, true)
		sendPacket(3, true)
		sendPacket(4, true)
		sendPacket(5, true)

		clock = clock.Add(100 * time.Millisecond)

		Expect(sampler.connectionStateMap).To(HaveLen(5))
		sampler.RemoveObsoletePackets(4)
		Expect(sampler.connectionStateMap).To(HaveLen(2))
		sampler.OnPacketLost(4)
		Expect(sampler.connectionStateMap).To(HaveLen(1))
		ackPacket(5)
		Expect(sampler.connectionStateMap).To(HaveLen(0))
	})
})
