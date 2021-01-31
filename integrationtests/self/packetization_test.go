package self_test

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/lucas-clemente/quic-go"
	quicproxy "github.com/lucas-clemente/quic-go/integrationtests/tools/proxy"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packetization", func() {
	var (
		server   quic.Listener
		proxy    *quicproxy.QuicProxy
		incoming uint32
		outgoing uint32
	)

	BeforeEach(func() {
		incoming = 0
		outgoing = 0
		var err error
		server, err = quic.ListenAddr(
			"localhost:0",
			getTLSConfig(),
			getQuicConfig(&quic.Config{
				AcceptToken:             func(net.Addr, *quic.Token) bool { return true },
				DisablePathMTUDiscovery: true,
			}),
		)
		Expect(err).ToNot(HaveOccurred())
		serverAddr := fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port)

		proxy, err = quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr: serverAddr,
			DelayPacket: func(dir quicproxy.Direction, _ []byte) time.Duration {
				//nolint:exhaustive
				switch dir {
				case quicproxy.DirectionIncoming:
					atomic.AddUint32(&incoming, 1)
				case quicproxy.DirectionOutgoing:
					atomic.AddUint32(&outgoing, 1)
				}
				return 5 * time.Millisecond
			},
		})
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		Expect(proxy.Close()).To(Succeed())
		Expect(server.Close()).To(Succeed())
	})

	// In this test, the client sends 100 small messages. The server echoes these messages.
	// This means that every endpoint will send 100 ack-eliciting packets in short succession.
	// This test then tests that no more than 110 packets are sent in every direction, making sure that ACK are bundled.
	It("bundles ACKs", func() {
		const numMsg = 100

		sess, err := quic.DialAddr(
			fmt.Sprintf("localhost:%d", proxy.LocalPort()),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
		)
		Expect(err).ToNot(HaveOccurred())

		go func() {
			defer GinkgoRecover()
			sess, err := server.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			str, err := sess.AcceptStream(context.Background())
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

		str, err := sess.OpenStreamSync(context.Background())
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
		Expect(sess.CloseWithError(0, "")).To(Succeed())

		numIncoming := atomic.LoadUint32(&incoming)
		numOutgoing := atomic.LoadUint32(&outgoing)
		fmt.Fprintf(GinkgoWriter, "incoming packets: %d\n", numIncoming)
		fmt.Fprintf(GinkgoWriter, "outgoing packets: %d\n", numOutgoing)
		Expect(numIncoming).To(And(
			BeNumerically(">", numMsg),
			BeNumerically("<", numMsg+10),
		))
		Expect(numOutgoing).To(And(
			BeNumerically(">", numMsg),
			BeNumerically("<", numMsg+10),
		))
	})
})
