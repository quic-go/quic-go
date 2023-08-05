package self_test

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Connection ID lengths tests", func() {
	It("retransmits the CONNECTION_CLOSE packet", func() {
		server, err := quic.ListenAddr(
			"localhost:0",
			getTLSConfig(),
			getQuicConfig(&quic.Config{
				DisablePathMTUDiscovery: true,
			}),
		)
		Expect(err).ToNot(HaveOccurred())
		defer server.Close()

		var drop atomic.Bool
		dropped := make(chan []byte, 100)
		proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr: fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
			DelayPacket: func(dir quicproxy.Direction, _ []byte) time.Duration {
				return 5 * time.Millisecond // 10ms RTT
			},
			DropPacket: func(dir quicproxy.Direction, b []byte) bool {
				if drop := drop.Load(); drop && dir == quicproxy.DirectionOutgoing {
					dropped <- b
					return true
				}
				return false
			},
		})
		Expect(err).ToNot(HaveOccurred())
		defer proxy.Close()

		conn, err := quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", proxy.LocalPort()),
			getTLSClientConfig(),
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		defer conn.CloseWithError(0, "")

		sconn, err := server.Accept(context.Background())
		Expect(err).ToNot(HaveOccurred())
		time.Sleep(100 * time.Millisecond)
		drop.Store(true)
		sconn.CloseWithError(1337, "closing")

		// send 100 packets
		for i := 0; i < 100; i++ {
			str, err := conn.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			_, err = str.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())
			time.Sleep(time.Millisecond)
		}
		// Expect retransmissions of the CONNECTION_CLOSE for the
		// 1st, 2nd, 4th, 8th, 16th, 32th, 64th packet: 7 in total (+1 for the original packet)
		Eventually(dropped).Should(HaveLen(8))
		first := <-dropped
		for len(dropped) > 0 {
			Expect(<-dropped).To(Equal(first)) // these packets are all identical
		}
	})
})
