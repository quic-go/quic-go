package self_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stateless Resets", func() {
	connIDLens := []int{0, 10}

	for i := range connIDLens {
		connIDLen := connIDLens[i]

		It(fmt.Sprintf("sends and recognizes stateless resets, for %d byte connection IDs", connIDLen), func() {
			var statelessResetKey quic.StatelessResetKey
			rand.Read(statelessResetKey[:])

			c, err := net.ListenUDP("udp", nil)
			Expect(err).ToNot(HaveOccurred())
			tr := &quic.Transport{
				Conn:               c,
				StatelessResetKey:  &statelessResetKey,
				ConnectionIDLength: connIDLen,
			}
			defer tr.Close()
			ln, err := tr.Listen(getTLSConfig(), getQuicConfig(nil))
			Expect(err).ToNot(HaveOccurred())
			serverPort := ln.Addr().(*net.UDPAddr).Port

			closeServer := make(chan struct{})

			go func() {
				defer GinkgoRecover()
				conn, err := ln.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				str, err := conn.OpenStream()
				Expect(err).ToNot(HaveOccurred())
				_, err = str.Write([]byte("foobar"))
				Expect(err).ToNot(HaveOccurred())
				<-closeServer
				Expect(ln.Close()).To(Succeed())
				Expect(tr.Close()).To(Succeed())
			}()

			var drop atomic.Bool
			proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
				RemoteAddr: fmt.Sprintf("localhost:%d", serverPort),
				DropPacket: func(quicproxy.Direction, []byte) bool {
					return drop.Load()
				},
			})
			Expect(err).ToNot(HaveOccurred())
			defer proxy.Close()

			addr, err := net.ResolveUDPAddr("udp", "localhost:0")
			Expect(err).ToNot(HaveOccurred())
			udpConn, err := net.ListenUDP("udp", addr)
			Expect(err).ToNot(HaveOccurred())
			defer udpConn.Close()
			cl := &quic.Transport{
				Conn:               udpConn,
				ConnectionIDLength: connIDLen,
			}
			defer cl.Close()
			conn, err := cl.Dial(
				context.Background(),
				&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: proxy.LocalPort()},
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{MaxIdleTimeout: 2 * time.Second}),
			)
			Expect(err).ToNot(HaveOccurred())
			str, err := conn.AcceptStream(context.Background())
			Expect(err).ToNot(HaveOccurred())
			data := make([]byte, 6)
			_, err = str.Read(data)
			Expect(err).ToNot(HaveOccurred())
			Expect(data).To(Equal([]byte("foobar")))

			// make sure that the CONNECTION_CLOSE is dropped
			drop.Store(true)
			close(closeServer)
			time.Sleep(100 * time.Millisecond)

			// We need to create a new Transport here, since the old one is still sending out
			// CONNECTION_CLOSE packets for (recently) closed connections).
			tr2 := &quic.Transport{
				Conn:               c,
				ConnectionIDLength: connIDLen,
				StatelessResetKey:  &statelessResetKey,
			}
			defer tr2.Close()
			ln2, err := tr2.Listen(getTLSConfig(), getQuicConfig(nil))
			Expect(err).ToNot(HaveOccurred())
			drop.Store(false)

			acceptStopped := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := ln2.Accept(context.Background())
				Expect(err).To(HaveOccurred())
				close(acceptStopped)
			}()

			// Trigger something (not too small) to be sent, so that we receive the stateless reset.
			// If the client already sent another packet, it might already have received a packet.
			_, serr := str.Write([]byte("Lorem ipsum dolor sit amet."))
			if serr == nil {
				_, serr = str.Read([]byte{0})
			}
			Expect(serr).To(HaveOccurred())
			Expect(serr).To(BeAssignableToTypeOf(&quic.StatelessResetError{}))
			Expect(ln2.Close()).To(Succeed())
			Eventually(acceptStopped).Should(BeClosed())
		})
	}
})
