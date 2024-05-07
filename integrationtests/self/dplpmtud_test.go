package self_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("DPLPMTUD", func() {
	It("discovers the MTU", func() {
		rtt := scaleDuration(10 * time.Millisecond)
		const mtu = 1400

		ln, err := quic.ListenAddr(
			"localhost:0",
			getTLSConfig(),
			getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true, EnableDatagrams: true}),
		)
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()
		go func() {
			defer GinkgoRecover()
			conn, err := ln.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			str, err := conn.AcceptStream(context.Background())
			Expect(err).ToNot(HaveOccurred())
			_, err = io.Copy(str, str)
			Expect(err).ToNot(HaveOccurred())
			str.Close()
		}()

		var mx sync.Mutex
		var maxPacketSizeClient, maxPacketSizeServer int
		serverPort := ln.Addr().(*net.UDPAddr).Port
		proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr:  fmt.Sprintf("localhost:%d", serverPort),
			DelayPacket: func(quicproxy.Direction, []byte) time.Duration { return rtt / 2 },
			DropPacket: func(dir quicproxy.Direction, packet []byte) bool {
				if len(packet) > mtu {
					return true
				}
				mx.Lock()
				defer mx.Unlock()
				switch dir {
				case quicproxy.DirectionIncoming:
					if len(packet) > maxPacketSizeClient {
						maxPacketSizeClient = len(packet)
					}
				case quicproxy.DirectionOutgoing:
					if len(packet) > maxPacketSizeServer {
						maxPacketSizeServer = len(packet)
					}
				}
				return false
			},
		})
		Expect(err).ToNot(HaveOccurred())
		defer proxy.Close()

		// Make sure to use v4-only socket here.
		// We can't reliably set the DF bit on dual-stack sockets on macOS.
		udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		Expect(err).ToNot(HaveOccurred())
		defer udpConn.Close()
		tr := &quic.Transport{Conn: udpConn}
		defer tr.Close()
		conn, err := tr.Dial(
			context.Background(),
			proxy.LocalAddr(),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{EnableDatagrams: true}),
		)
		Expect(err).ToNot(HaveOccurred())
		defer conn.CloseWithError(0, "")
		str, err := conn.OpenStream()
		Expect(err).ToNot(HaveOccurred())
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer GinkgoRecover()
			data, err := io.ReadAll(str)
			Expect(err).ToNot(HaveOccurred())
			Expect(data).To(Equal(PRDataLong))
		}()
		err = conn.SendDatagram(make([]byte, 2000))
		Expect(err).To(BeAssignableToTypeOf(&quic.DatagramTooLargeError{}))
		initialMaxDatagramSize := err.(*quic.DatagramTooLargeError).MaxDatagramPayloadSize
		_, err = str.Write(PRDataLong)
		Expect(err).ToNot(HaveOccurred())
		str.Close()
		Eventually(done, 20*time.Second).Should(BeClosed())
		err = conn.SendDatagram(make([]byte, 2000))
		Expect(err).To(BeAssignableToTypeOf(&quic.DatagramTooLargeError{}))
		finalMaxDatagramSize := err.(*quic.DatagramTooLargeError).MaxDatagramPayloadSize

		mx.Lock()
		defer mx.Unlock()
		fmt.Fprintf(GinkgoWriter, "max client packet size: %d, MTU: %d\n", maxPacketSizeClient, mtu)
		fmt.Fprintf(GinkgoWriter, "max datagram size: initial: %d, final: %d\n", initialMaxDatagramSize, finalMaxDatagramSize)
		fmt.Fprintf(GinkgoWriter, "max server packet size: %d, MTU: %d\n", maxPacketSizeServer, mtu)
		Expect(maxPacketSizeClient).To(BeNumerically(">=", mtu-25))
		const maxDiff = 40 // this includes the 21 bytes for the short header, 16 bytes for the encryption tag, and framing overhead
		Expect(initialMaxDatagramSize).To(BeNumerically(">=", 1252-maxDiff))
		Expect(finalMaxDatagramSize).To(BeNumerically(">=", maxPacketSizeClient-maxDiff))
		// MTU discovery was disabled on the server side
		Expect(maxPacketSizeServer).To(Equal(1252))
	})
})
