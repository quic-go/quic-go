package congestion

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

var _ = Describe("function", func() {
	It("bdpFromRttAndBandwidth", func() {
		Expect(bdpFromRttAndBandwidth(3*time.Millisecond, Bandwidth(8e3))).To(Equal(protocol.ByteCount(3)))
	})
})

var _ = Describe("", func() {
	const (
		initialCongestionWindowPackets                    = 10
		defaultWindowTCP                                  = protocol.ByteCount(initialCongestionWindowPackets) * maxDatagramSize
		maxCongestionWindow            protocol.ByteCount = 200 * maxDatagramSize
	)

	var (
		sender        *bbrSender
		clock         mockClock
		bytesInFlight protocol.ByteCount
		packetNumber  protocol.PacketNumber
		rttStats      *utils.RTTStats
	)

	SendAvailableSendWindowLen := func(packetLength protocol.ByteCount) int {
		var packetsSent int
		for sender.CanSend(bytesInFlight) {
			sender.OnPacketSent(clock.Now(), bytesInFlight, packetNumber, packetLength, true)
			packetNumber++
			packetsSent++
			bytesInFlight += packetLength
		}
		return packetsSent
	}

	AckNPacketsLen := func(packetNums []protocol.PacketNumber, packetLength protocol.ByteCount) {
		infos := []protocol.AckedPacketInfo{}
		for _, p := range packetNums {
			infos = append(infos, protocol.AckedPacketInfo{
				PacketNumber: p,
				BytesAcked:   packetLength,
				ReceivedTime: clock.Now(),
			})
		}
		sender.OnCongestionEvent(bytesInFlight, clock.Now(), infos, nil)
		bytesInFlight -= protocol.ByteCount(len(packetNums)) * packetLength
	}

	LoseNPacketsLen := func(packetNums []protocol.PacketNumber, packetLength protocol.ByteCount) {
		infos := []protocol.LostPacketInfo{}
		for _, p := range packetNums {
			infos = append(infos, protocol.LostPacketInfo{
				PacketNumber: p,
				BytesLost:    packetLength,
			})
		}
		sender.OnCongestionEvent(bytesInFlight, clock.Now(), nil, infos)
		bytesInFlight -= protocol.ByteCount(len(packetNums)) * packetLength
	}

	SendAvailableSendWindow := func() int { return SendAvailableSendWindowLen(maxDatagramSize) }

	AckSeqPackets := func(start, end int) {
		Expect(start < end).To(BeTrue())
		ackPacketNums := []protocol.PacketNumber{}
		for i := start + 1; i <= end; i++ {
			ackPacketNums = append(ackPacketNums, protocol.PacketNumber(i))
		}
		AckNPacketsLen(ackPacketNums, maxDatagramSize)
	}

	LoseSeqPackets := func(start, end int) {
		Expect(start < end).To(BeTrue())
		losePacketNums := []protocol.PacketNumber{}
		for i := start + 1; i <= end; i++ {
			losePacketNums = append(losePacketNums, protocol.PacketNumber(i))
		}
		LoseNPacketsLen(losePacketNums, maxDatagramSize)
	}

	BeforeEach(func() {
		bytesInFlight = 0
		packetNumber = 1
		clock = mockClock{}
		rttStats = utils.NewRTTStats()
		sender = newBbrSender(
			&clock,
			rttStats,
			protocol.InitialPacketSizeIPv4,
			initialCongestionWindowPackets*maxDatagramSize,
			maxCongestionWindow,
			nil,
		)

	})

	It("has the right values at startup", func() {
		// At startup make sure we are at the default.
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))
		// Make sure we can send.
		Expect(sender.TimeUntilSend(0)).To(BeZero())
		Expect(sender.CanSend(bytesInFlight)).To(BeTrue())
		// And that window is un-affected.
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))

		// Fill the send window with data, then verify that we can't send.
		SendAvailableSendWindow()
		Expect(sender.CanSend(bytesInFlight)).To(BeFalse())
	})

	It("paces", func() {
		rttStats.UpdateRTT(10*time.Millisecond, 0, time.Now())
		clock.Advance(time.Hour)
		// Fill the send window with data, then verify that we can't send.
		SendAvailableSendWindow()
		AckSeqPackets(0, 1)
		delay := sender.TimeUntilSend(bytesInFlight)
		Expect(delay).ToNot(BeZero())
		Expect(delay).ToNot(Equal(utils.InfDuration))
	})

	It("send n packets and ack n packets", func() {
		Expect(sender.CanSend(0)).To(BeTrue())
		Expect(sender.TimeUntilSend(0)).To(BeZero())

		sentPacketsCount := SendAvailableSendWindow()
		Expect(sentPacketsCount).To(Equal(initialCongestionWindowPackets))

		clock.Advance(60 * time.Millisecond)
		AckSeqPackets(0, sentPacketsCount)

		bytesToSend := sender.GetCongestionWindow()
		Expect(bytesToSend).To(Equal(defaultWindowTCP + protocol.ByteCount(sentPacketsCount)*maxDatagramSize))
	})

	It("send n packets and lose n packets", func() {
		Expect(sender.CanSend(0)).To(BeTrue())
		Expect(sender.TimeUntilSend(0)).To(BeZero())

		sentPacketsCount := SendAvailableSendWindow()
		Expect(sentPacketsCount).To(Equal(initialCongestionWindowPackets))

		clock.Advance(60 * time.Millisecond)
		LoseSeqPackets(0, sentPacketsCount)

		bytesToSend := sender.GetCongestionWindow()
		Expect(bytesToSend).To(Equal(defaultWindowTCP))
	})

	It("max cwnd", func() {
		var sentPacketsCount int

		for i := 0; i < 10; i++ {
			n := SendAvailableSendWindow()
			clock.Advance(1 * time.Second)
			AckSeqPackets(sentPacketsCount, sentPacketsCount+n)
			sentPacketsCount += n
		}

		bytesToSend := sender.GetCongestionWindow()
		Expect(bytesToSend).To(Equal(maxCongestionWindow))
	})
})
