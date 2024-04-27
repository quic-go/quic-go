package self_test

import (
	"context"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/internal/wire"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Datagram test", func() {
	const concurrentSends = 100
	const maxDatagramSize = 250

	var (
		serverConn, clientConn *net.UDPConn
		dropped, total         atomic.Int32
	)

	startServerAndProxy := func(enableDatagram, expectDatagramSupport bool) (port int, closeFn func()) {
		addr, err := net.ResolveUDPAddr("udp", "localhost:0")
		Expect(err).ToNot(HaveOccurred())
		serverConn, err = net.ListenUDP("udp", addr)
		Expect(err).ToNot(HaveOccurred())
		ln, err := quic.Listen(
			serverConn,
			getTLSConfig(),
			getQuicConfig(&quic.Config{EnableDatagrams: enableDatagram}),
		)
		Expect(err).ToNot(HaveOccurred())

		accepted := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(accepted)
			conn, err := ln.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())

			if expectDatagramSupport {
				Expect(conn.ConnectionState().SupportsDatagrams).To(BeTrue())
				if enableDatagram {
					f := &wire.DatagramFrame{DataLenPresent: true}
					var wg sync.WaitGroup
					wg.Add(concurrentSends)
					for i := 0; i < concurrentSends; i++ {
						go func(i int) {
							defer GinkgoRecover()
							defer wg.Done()
							b := make([]byte, 8)
							binary.BigEndian.PutUint64(b, uint64(i))
							Expect(conn.SendDatagram(b)).To(Succeed())
						}(i)
					}
					maxDatagramMessageSize := f.MaxDataLen(maxDatagramSize, conn.ConnectionState().Version)
					b := make([]byte, maxDatagramMessageSize+1)
					Expect(conn.SendDatagram(b)).To(MatchError(&quic.DatagramTooLargeError{
						MaxDatagramPayloadSize: int64(maxDatagramMessageSize),
					}))
					wg.Wait()
				}
			} else {
				Expect(conn.ConnectionState().SupportsDatagrams).To(BeFalse())
			}
		}()

		serverPort := ln.Addr().(*net.UDPAddr).Port
		proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr: fmt.Sprintf("localhost:%d", serverPort),
			// drop 10% of Short Header packets sent from the server
			DropPacket: func(dir quicproxy.Direction, packet []byte) bool {
				if dir == quicproxy.DirectionIncoming {
					return false
				}
				// don't drop Long Header packets
				if wire.IsLongHeaderPacket(packet[0]) {
					return false
				}
				drop := mrand.Int()%10 == 0
				if drop {
					dropped.Add(1)
				}
				total.Add(1)
				return drop
			},
		})
		Expect(err).ToNot(HaveOccurred())
		return proxy.LocalPort(), func() {
			Eventually(accepted).Should(BeClosed())
			proxy.Close()
			ln.Close()
		}
	}

	BeforeEach(func() {
		addr, err := net.ResolveUDPAddr("udp", "localhost:0")
		Expect(err).ToNot(HaveOccurred())
		clientConn, err = net.ListenUDP("udp", addr)
		Expect(err).ToNot(HaveOccurred())
	})

	It("sends datagrams", func() {
		oldMaxDatagramSize := wire.MaxDatagramSize
		wire.MaxDatagramSize = maxDatagramSize
		proxyPort, close := startServerAndProxy(true, true)
		defer close()
		raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("localhost:%d", proxyPort))
		Expect(err).ToNot(HaveOccurred())
		conn, err := quic.Dial(
			context.Background(),
			clientConn,
			raddr,
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{EnableDatagrams: true}),
		)
		Expect(err).ToNot(HaveOccurred())
		Expect(conn.ConnectionState().SupportsDatagrams).To(BeTrue())
		var counter int
		for {
			// Close the connection if no message is received for 100 ms.
			timer := time.AfterFunc(scaleDuration(100*time.Millisecond), func() { conn.CloseWithError(0, "") })
			if _, err := conn.ReceiveDatagram(context.Background()); err != nil {
				break
			}
			timer.Stop()
			counter++
		}

		numDropped := int(dropped.Load())
		expVal := concurrentSends - numDropped
		fmt.Fprintf(GinkgoWriter, "Dropped %d out of %d packets.\n", numDropped, total.Load())
		fmt.Fprintf(GinkgoWriter, "Received %d out of %d sent datagrams.\n", counter, concurrentSends)
		Expect(counter).To(And(
			BeNumerically(">", expVal*9/10),
			BeNumerically("<", concurrentSends),
		))
		Eventually(conn.Context().Done).Should(BeClosed())
		wire.MaxDatagramSize = oldMaxDatagramSize
	})

	It("server can disable datagram", func() {
		proxyPort, close := startServerAndProxy(false, true)
		raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("localhost:%d", proxyPort))
		Expect(err).ToNot(HaveOccurred())
		conn, err := quic.Dial(
			context.Background(),
			clientConn,
			raddr,
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{EnableDatagrams: true}),
		)
		Expect(err).ToNot(HaveOccurred())
		Expect(conn.ConnectionState().SupportsDatagrams).To(BeFalse())

		close()
		conn.CloseWithError(0, "")
	})

	It("client can disable datagram", func() {
		proxyPort, close := startServerAndProxy(false, true)
		raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("localhost:%d", proxyPort))
		Expect(err).ToNot(HaveOccurred())
		conn, err := quic.Dial(
			context.Background(),
			clientConn,
			raddr,
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{EnableDatagrams: true}),
		)
		Expect(err).ToNot(HaveOccurred())
		Expect(conn.ConnectionState().SupportsDatagrams).To(BeFalse())

		Expect(conn.SendDatagram([]byte{0})).To(HaveOccurred())

		close()
		conn.CloseWithError(0, "")
	})
})
