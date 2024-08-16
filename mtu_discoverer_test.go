package quic

import (
	"fmt"
	"time"

	"golang.org/x/exp/rand"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"

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
	r := rand.New(rand.NewSource(uint64(GinkgoRandomSeed())))

	BeforeEach(func() {
		rttStats = &utils.RTTStats{}
		rttStats.SetInitialRTT(rtt)
		Expect(rttStats.SmoothedRTT()).To(Equal(rtt))
		d = newMTUDiscoverer(
			rttStats,
			startMTU,
			maxMTU,
			func(s protocol.ByteCount) { discoveredMTU = s },
			nil,
		)
		d.Start()
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
			fmt.Println("sending", size)
			ping.Handler.OnAcked(ping.Frame)
			sizes = append(sizes, size)
			t = t.Add(5 * rtt)
		}
		Expect(sizes).To(Equal([]protocol.ByteCount{1500, 1750, 1875, 1937, 1968, 1984}))
		Expect(d.ShouldSendProbe(t.Add(10 * rtt))).To(BeFalse())
	})

	It("doesn't do discovery before being started", func() {
		d := newMTUDiscoverer(rttStats, startMTU, protocol.MaxByteCount, func(s protocol.ByteCount) {}, nil)
		for i := 0; i < 5; i++ {
			Expect(d.ShouldSendProbe(time.Now())).To(BeFalse())
		}
	})

	It("finds the MTU", MustPassRepeatedly(300), func() {
		maxMTU := protocol.ByteCount(r.Intn(int(3000-startMTU))) + startMTU + 1
		currentMTU := startMTU
		var tracedMTU protocol.ByteCount
		var tracerDone bool
		d := newMTUDiscoverer(
			rttStats,
			startMTU,
			maxMTU,
			func(s protocol.ByteCount) { currentMTU = s },
			&logging.ConnectionTracer{
				UpdatedMTU: func(mtu logging.ByteCount, done bool) {
					tracedMTU = mtu
					tracerDone = done
				},
			},
		)
		d.Start()
		now := time.Now()
		realMTU := protocol.ByteCount(r.Intn(int(maxMTU-startMTU))) + startMTU
		fmt.Fprintf(GinkgoWriter, "MTU: %d, max: %d\n", realMTU, maxMTU)
		t := now.Add(mtuProbeDelay * rtt)
		var probes []protocol.ByteCount
		for d.ShouldSendProbe(t) {
			if len(probes) > 24 {
				Fail(fmt.Sprintf("too many iterations: %v", probes))
			}
			ping, size := d.GetPing()
			probes = append(probes, size)
			if size <= realMTU {
				ping.Handler.OnAcked(ping.Frame)
			} else {
				ping.Handler.OnLost(ping.Frame)
			}
			t = t.Add(mtuProbeDelay * rtt)
		}
		diff := realMTU - currentMTU
		Expect(diff).To(BeNumerically(">=", 0))
		if maxMTU > currentMTU+maxMTU {
			Expect(tracedMTU).To(Equal(currentMTU))
			Expect(tracerDone).To(BeTrue())
		}
		fmt.Fprintf(GinkgoWriter, "MTU discovered: %d (diff: %d)\n", currentMTU, diff)
		fmt.Fprintf(GinkgoWriter, "probes sent (%d): %v\n", len(probes), probes)
		Expect(diff).To(BeNumerically("<=", maxMTUDiff))
	})

	const maxRandomLoss = maxLostMTUProbes - 1
	It(fmt.Sprintf("finds the MTU, with up to %d packets lost", maxRandomLoss), MustPassRepeatedly(500), func() {
		maxMTU := protocol.ByteCount(r.Intn(int(3000-startMTU))) + startMTU + 1
		currentMTU := startMTU
		var tracedMTU protocol.ByteCount
		var tracerDone bool
		d := newMTUDiscoverer(
			rttStats,
			startMTU,
			maxMTU,
			func(s protocol.ByteCount) { currentMTU = s },
			&logging.ConnectionTracer{
				UpdatedMTU: func(mtu logging.ByteCount, done bool) {
					tracedMTU = mtu
					tracerDone = done
				},
			},
		)
		d.Start()
		now := time.Now()
		realMTU := protocol.ByteCount(r.Intn(int(maxMTU-startMTU))) + startMTU
		fmt.Fprintf(GinkgoWriter, "MTU: %d, max: %d\n", realMTU, maxMTU)
		t := now.Add(mtuProbeDelay * rtt)
		var probes, randomLosses []protocol.ByteCount
		for d.ShouldSendProbe(t) {
			if len(probes) > 32 {
				Fail(fmt.Sprintf("too many iterations: %v", probes))
			}
			ping, size := d.GetPing()
			probes = append(probes, size)
			packetFits := size <= realMTU
			var acked bool
			if packetFits {
				randomLoss := r.Intn(maxLostMTUProbes) == 0 && len(randomLosses) < maxRandomLoss
				if randomLoss {
					randomLosses = append(randomLosses, size)
				} else {
					ping.Handler.OnAcked(ping.Frame)
					acked = true
				}
			}
			if !acked {
				ping.Handler.OnLost(ping.Frame)
			}
			t = t.Add(mtuProbeDelay * rtt)
		}
		diff := realMTU - currentMTU
		Expect(diff).To(BeNumerically(">=", 0))
		if maxMTU > currentMTU+maxMTU {
			Expect(tracedMTU).To(Equal(currentMTU))
			Expect(tracerDone).To(BeTrue())
		}
		fmt.Fprintf(GinkgoWriter, "MTU discovered with random losses %v: %d (diff: %d)\n", randomLosses, currentMTU, diff)
		fmt.Fprintf(GinkgoWriter, "probes sent (%d): %v\n", len(probes), probes)
		Expect(diff).To(BeNumerically("<=", maxMTUDiff))
	})
})
