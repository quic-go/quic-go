package self_test

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func randomDuration(min, max time.Duration) time.Duration {
	return min + time.Duration(rand.Int63n(int64(max-min)))
}

var _ = Describe("Drop Tests", func() {
	var (
		proxy *quicproxy.QuicProxy
		ln    *quic.Listener
	)

	startListenerAndProxy := func(dropCallback quicproxy.DropCallback) {
		var err error
		ln, err = quic.ListenAddr(
			"localhost:0",
			getTLSConfig(),
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		serverPort := ln.Addr().(*net.UDPAddr).Port
		proxy, err = quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr: fmt.Sprintf("localhost:%d", serverPort),
			DelayPacket: func(dir quicproxy.Direction, _ []byte) time.Duration {
				return 5 * time.Millisecond // 10ms RTT
			},
			DropPacket: dropCallback,
		},
		)
		Expect(err).ToNot(HaveOccurred())
	}

	AfterEach(func() {
		Expect(proxy.Close()).To(Succeed())
		Expect(ln.Close()).To(Succeed())
	})

	for _, d := range directions {
		direction := d

		// The purpose of this test is to create a lot of tails, by sending 1 byte messages.
		// The interval, the length of the drop period, and the time when the drop period starts are randomized.
		// To cover different scenarios, repeat this test a few times.
		for rep := 0; rep < 3; rep++ {
			It(fmt.Sprintf("sends short messages, dropping packets in %s direction", direction), func() {
				const numMessages = 15

				messageInterval := randomDuration(10*time.Millisecond, 100*time.Millisecond)
				dropDuration := randomDuration(messageInterval*3/2, 2*time.Second)
				dropDelay := randomDuration(25*time.Millisecond, numMessages*messageInterval/2) // makes sure we don't interfere with the handshake
				fmt.Fprintf(GinkgoWriter, "Sending a message every %s, %d times.\n", messageInterval, numMessages)
				fmt.Fprintf(GinkgoWriter, "Dropping packets for %s, after a delay of %s\n", dropDuration, dropDelay)
				startTime := time.Now()

				var numDroppedPackets int32
				startListenerAndProxy(func(d quicproxy.Direction, _ []byte) bool {
					if !d.Is(direction) {
						return false
					}
					drop := time.Now().After(startTime.Add(dropDelay)) && time.Now().Before(startTime.Add(dropDelay).Add(dropDuration))
					if drop {
						atomic.AddInt32(&numDroppedPackets, 1)
					}
					return drop
				})

				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					conn, err := ln.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())
					str, err := conn.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					for i := uint8(1); i <= numMessages; i++ {
						n, err := str.Write([]byte{i})
						Expect(err).ToNot(HaveOccurred())
						Expect(n).To(Equal(1))
						time.Sleep(messageInterval)
					}
					<-done
					Expect(conn.CloseWithError(0, "")).To(Succeed())
				}()

				conn, err := quic.DialAddr(
					context.Background(),
					fmt.Sprintf("localhost:%d", proxy.LocalPort()),
					getTLSClientConfig(),
					getQuicConfig(nil),
				)
				Expect(err).ToNot(HaveOccurred())
				defer conn.CloseWithError(0, "")
				str, err := conn.AcceptStream(context.Background())
				Expect(err).ToNot(HaveOccurred())
				for i := uint8(1); i <= numMessages; i++ {
					b := []byte{0}
					n, err := str.Read(b)
					Expect(err).ToNot(HaveOccurred())
					Expect(n).To(Equal(1))
					Expect(b[0]).To(Equal(i))
				}
				close(done)
				numDropped := atomic.LoadInt32(&numDroppedPackets)
				fmt.Fprintf(GinkgoWriter, "Dropped %d packets.\n", numDropped)
				Expect(numDropped).To(BeNumerically(">", 0))
			})
		}
	}
})
