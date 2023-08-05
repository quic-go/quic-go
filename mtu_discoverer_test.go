package quic

import (
	"math/rand"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("MTU Discoverer", func() {
	const (
		rtt                         = 100 * time.Millisecond
		startMTU protocol.ByteCount = 1000
		maxMTU   protocol.ByteCount = 2000
	)

	var (
		d             *mtuFinder
		rttStats      *utils.RTTStats
		now           time.Time
		discoveredMTU protocol.ByteCount
	)

	BeforeEach(func() {
		rttStats = &utils.RTTStats{}
		rttStats.SetInitialRTT(rtt)
		Expect(rttStats.SmoothedRTT()).To(Equal(rtt))
		d = newMTUDiscoverer(rttStats, startMTU, func(s protocol.ByteCount) { discoveredMTU = s })
		d.Start(maxMTU)
		now = time.Now()
	})

	It("only allows a probe 5 RTTs after the handshake completes", func() {
		Expect(d.ShouldSendProbe(now)).To(BeFalse())
		Expect(d.ShouldSendProbe(now.Add(rtt * 9 / 2))).To(BeFalse())
		Expect(d.ShouldSendProbe(now.Add(rtt * 5))).To(BeTrue())
	})

	It("doesn't allow a probe if another probe is still in flight", func() {
		ping, _ := d.GetPing()
		Expect(d.ShouldSendProbe(now.Add(10 * rtt))).To(BeFalse())
		ping.Handler.OnLost(ping.Frame)
		Expect(d.ShouldSendProbe(now.Add(10 * rtt))).To(BeTrue())
	})

	It("tries a lower size when a probe is lost", func() {
		ping, size := d.GetPing()
		Expect(size).To(Equal(protocol.ByteCount(1500)))
		ping.Handler.OnLost(ping.Frame)
		_, size = d.GetPing()
		Expect(size).To(Equal(protocol.ByteCount(1250)))
	})

	It("tries a higher size and calls the callback when a probe is acknowledged", func() {
		ping, size := d.GetPing()
		Expect(size).To(Equal(protocol.ByteCount(1500)))
		ping.Handler.OnAcked(ping.Frame)
		Expect(discoveredMTU).To(Equal(protocol.ByteCount(1500)))
		_, size = d.GetPing()
		Expect(size).To(Equal(protocol.ByteCount(1750)))
	})

	It("stops discovery after getting close enough to the MTU", func() {
		var sizes []protocol.ByteCount
		t := now.Add(5 * rtt)
		for d.ShouldSendProbe(t) {
			ping, size := d.GetPing()
			ping.Handler.OnAcked(ping.Frame)
			sizes = append(sizes, size)
			t = t.Add(5 * rtt)
		}
		Expect(sizes).To(Equal([]protocol.ByteCount{1500, 1750, 1875, 1937, 1968, 1984}))
		Expect(d.ShouldSendProbe(t.Add(10 * rtt))).To(BeFalse())
	})

	It("doesn't do discovery before being started", func() {
		d := newMTUDiscoverer(rttStats, startMTU, func(s protocol.ByteCount) {})
		for i := 0; i < 5; i++ {
			Expect(d.ShouldSendProbe(time.Now())).To(BeFalse())
		}
	})

	It("finds the MTU", func() {
		const rep = 3000
		var maxDiff protocol.ByteCount
		for i := 0; i < rep; i++ {
			max := protocol.ByteCount(rand.Intn(int(3000-startMTU))) + startMTU + 1
			currentMTU := startMTU
			d := newMTUDiscoverer(rttStats, startMTU, func(s protocol.ByteCount) { currentMTU = s })
			d.Start(max)
			now := time.Now()
			realMTU := protocol.ByteCount(rand.Intn(int(max-startMTU))) + startMTU
			t := now.Add(mtuProbeDelay * rtt)
			var count int
			for d.ShouldSendProbe(t) {
				if count > 25 {
					Fail("too many iterations")
				}
				count++

				ping, size := d.GetPing()
				if size <= realMTU {
					ping.Handler.OnAcked(ping.Frame)
				} else {
					ping.Handler.OnLost(ping.Frame)
				}
				t = t.Add(mtuProbeDelay * rtt)
			}
			diff := realMTU - currentMTU
			Expect(diff).To(BeNumerically(">=", 0))
			maxDiff = utils.Max(maxDiff, diff)
		}
		Expect(maxDiff).To(BeEquivalentTo(maxMTUDiff))
	})
})
