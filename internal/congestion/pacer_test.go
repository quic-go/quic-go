package congestion

import (
	"time"

	"github.com/quic-go/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Pacer", func() {
	var p *pacer

	const packetsPerSecond = 50
	var bandwidth uint64 // in bytes/s

	BeforeEach(func() {
		bandwidth = uint64(packetsPerSecond * initialMaxDatagramSize) // 50 full-size packets per second
		// The pacer will multiply the bandwidth with 1.25 to achieve a slightly higher pacing speed.
		// For the tests, cancel out this factor, so we can do the math using the exact bandwidth.
		p = newPacer(func() Bandwidth { return Bandwidth(bandwidth) * BytesPerSecond * 4 / 5 })
	})

	It("allows a burst at the beginning", func() {
		t := time.Now()
		Expect(p.TimeUntilSend()).To(BeZero())
		Expect(p.Budget(t)).To(BeEquivalentTo(maxBurstSizePackets * initialMaxDatagramSize))
	})

	It("allows a big burst for high pacing rates", func() {
		t := time.Now()
		bandwidth = uint64(10000 * packetsPerSecond * initialMaxDatagramSize)
		Expect(p.TimeUntilSend()).To(BeZero())
		Expect(p.Budget(t)).To(BeNumerically(">", maxBurstSizePackets*initialMaxDatagramSize))
	})

	It("reduces the budget when sending packets", func() {
		t := time.Now()
		budget := p.Budget(t)
		for budget > 0 {
			Expect(p.TimeUntilSend()).To(BeZero())
			Expect(p.Budget(t)).To(Equal(budget))
			p.SentPacket(t, initialMaxDatagramSize)
			budget -= initialMaxDatagramSize
		}
		Expect(p.Budget(t)).To(BeZero())
		Expect(p.TimeUntilSend()).ToNot(BeZero())
	})

	sendBurst := func(t time.Time) {
		for p.Budget(t) > 0 {
			p.SentPacket(t, initialMaxDatagramSize)
		}
	}

	It("paces packets after a burst", func() {
		t := time.Now()
		sendBurst(t)
		// send 100 exactly paced packets
		for i := 0; i < 100; i++ {
			t2 := p.TimeUntilSend()
			Expect(t2.Sub(t)).To(BeNumerically("~", time.Second/packetsPerSecond, time.Nanosecond))
			Expect(p.Budget(t2)).To(BeEquivalentTo(initialMaxDatagramSize))
			p.SentPacket(t2, initialMaxDatagramSize)
			t = t2
		}
	})

	It("accounts for non-full-size packets", func() {
		t := time.Now()
		sendBurst(t)
		t2 := p.TimeUntilSend()
		Expect(t2.Sub(t)).To(BeNumerically("~", time.Second/packetsPerSecond, time.Nanosecond))
		// send a half-full packet
		Expect(p.Budget(t2)).To(BeEquivalentTo(initialMaxDatagramSize))
		size := initialMaxDatagramSize / 2
		p.SentPacket(t2, size)
		Expect(p.Budget(t2)).To(Equal(initialMaxDatagramSize - size))
		Expect(p.TimeUntilSend()).To(BeTemporally("~", t2.Add(time.Second/packetsPerSecond/2), time.Nanosecond))
	})

	It("accumulates budget, if no packets are sent", func() {
		t := time.Now()
		sendBurst(t)
		t2 := p.TimeUntilSend()
		Expect(t2).To(BeTemporally(">", t))
		// wait for 5 times the duration
		Expect(p.Budget(t.Add(5 * t2.Sub(t)))).To(BeEquivalentTo(5 * initialMaxDatagramSize))
	})

	It("accumulates budget, if no packets are sent, for larger packet sizes", func() {
		t := time.Now()
		sendBurst(t)
		const packetSize = initialMaxDatagramSize + 200
		p.SetMaxDatagramSize(packetSize)
		t2 := p.TimeUntilSend()
		Expect(t2).To(BeTemporally(">", t))
		// wait for 5 times the duration
		Expect(p.Budget(t.Add(5 * t2.Sub(t)))).To(BeEquivalentTo(5 * packetSize))
	})

	It("never allows bursts larger than the maximum burst size", func() {
		t := time.Now()
		sendBurst(t)
		Expect(p.Budget(t.Add(time.Hour))).To(BeEquivalentTo(maxBurstSizePackets * initialMaxDatagramSize))
	})

	It("never allows bursts larger than the maximum burst size, for larger packets", func() {
		t := time.Now()
		const packetSize = initialMaxDatagramSize + 200
		p.SetMaxDatagramSize(packetSize)
		sendBurst(t)
		Expect(p.Budget(t.Add(time.Hour))).To(BeEquivalentTo(maxBurstSizePackets * packetSize))
	})

	It("changes the bandwidth", func() {
		t := time.Now()
		sendBurst(t)
		bandwidth = uint64(5 * initialMaxDatagramSize) // reduce the bandwidth to 5 packet per second
		Expect(p.TimeUntilSend()).To(Equal(t.Add(time.Second / 5)))
	})

	It("doesn't pace faster than the minimum pacing duration", func() {
		t := time.Now()
		sendBurst(t)
		bandwidth = uint64(1e6 * initialMaxDatagramSize)
		Expect(p.TimeUntilSend()).To(Equal(t.Add(protocol.MinPacingDelay)))
		Expect(p.Budget(t.Add(protocol.MinPacingDelay))).To(Equal(protocol.ByteCount(protocol.MinPacingDelay) * initialMaxDatagramSize * 1e6 / 1e9))
	})
})
