package self_test

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/logging"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packetization", func() {
	// In this test, the client sends 100 small messages. The server echoes these messages.
	// This means that every endpoint will send 100 ack-eliciting packets in short succession.
	// This test then tests that no more than 110 packets are sent in every direction, making sure that ACK are bundled.
	It("bundles ACKs", func() {
		const numMsg = 100

		serverCounter, serverTracer := newPacketTracer()
		server, err := quic.ListenAddr(
			"localhost:0",
			getTLSConfig(),
			getQuicConfig(&quic.Config{
				DisablePathMTUDiscovery: true,
				Tracer:                  newTracer(serverTracer),
			}),
		)
		Expect(err).ToNot(HaveOccurred())
		defer server.Close()
		serverAddr := fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port)

		proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr: serverAddr,
			DelayPacket: func(dir quicproxy.Direction, _ []byte) time.Duration {
				return 5 * time.Millisecond
			},
		})
		Expect(err).ToNot(HaveOccurred())
		defer proxy.Close()

		clientCounter, clientTracer := newPacketTracer()
		conn, err := quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", proxy.LocalPort()),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{
				DisablePathMTUDiscovery: true,
				Tracer:                  newTracer(clientTracer),
			}),
		)
		Expect(err).ToNot(HaveOccurred())
		defer conn.CloseWithError(0, "")

		go func() {
			defer GinkgoRecover()
			conn, err := server.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			str, err := conn.AcceptStream(context.Background())
			Expect(err).ToNot(HaveOccurred())
			b := make([]byte, 1)
			// Echo every byte received from the client.
			for {
				if _, err := str.Read(b); err != nil {
					break
				}
				_, err = str.Write(b)
				Expect(err).ToNot(HaveOccurred())
			}
		}()

		str, err := conn.OpenStreamSync(context.Background())
		Expect(err).ToNot(HaveOccurred())
		b := make([]byte, 1)
		// Send numMsg 1-byte messages.
		for i := 0; i < numMsg; i++ {
			_, err = str.Write([]byte{uint8(i)})
			Expect(err).ToNot(HaveOccurred())
			_, err = str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(b[0]).To(Equal(uint8(i)))
		}
		Expect(conn.CloseWithError(0, "")).To(Succeed())

		countBundledPackets := func(packets []shortHeaderPacket) (numBundled int) {
			for _, p := range packets {
				var hasAck, hasStreamFrame bool
				for _, f := range p.frames {
					switch f.(type) {
					case *logging.AckFrame:
						hasAck = true
					case *logging.StreamFrame:
						hasStreamFrame = true
					}
				}
				if hasAck && hasStreamFrame {
					numBundled++
				}
			}
			return
		}

		numBundledIncoming := countBundledPackets(clientCounter.getRcvdShortHeaderPackets())
		numBundledOutgoing := countBundledPackets(serverCounter.getRcvdShortHeaderPackets())
		fmt.Fprintf(GinkgoWriter, "bundled incoming packets: %d / %d\n", numBundledIncoming, numMsg)
		fmt.Fprintf(GinkgoWriter, "bundled outgoing packets: %d / %d\n", numBundledOutgoing, numMsg)
		Expect(numBundledIncoming).To(And(
			BeNumerically("<=", numMsg),
			BeNumerically(">", numMsg*9/10),
		))
		Expect(numBundledOutgoing).To(And(
			BeNumerically("<=", numMsg),
			BeNumerically(">", numMsg*9/10),
		))
	})
})
