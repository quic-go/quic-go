package self_test

import (
	"context"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type faultyConn struct {
	net.PacketConn

	MaxPackets int32
	counter    int32
}

func (c *faultyConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	counter := atomic.AddInt32(&c.counter, 1)
	if counter <= c.MaxPackets {
		return n, addr, err
	}
	return 0, nil, io.ErrClosedPipe
}

func (c *faultyConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	counter := atomic.AddInt32(&c.counter, 1)
	if counter <= c.MaxPackets {
		return c.PacketConn.WriteTo(p, addr)
	}
	return 0, io.ErrClosedPipe
}

var _ = Describe("Timeout tests", func() {
	checkTimeoutError := func(err error) {
		ExpectWithOffset(1, err).To(MatchError(&quic.IdleTimeoutError{}))
		nerr, ok := err.(net.Error)
		ExpectWithOffset(1, ok).To(BeTrue())
		ExpectWithOffset(1, nerr.Timeout()).To(BeTrue())
	}

	It("returns net.Error timeout errors when dialing", func() {
		errChan := make(chan error)
		go func() {
			_, err := quic.DialAddr(
				context.Background(),
				"localhost:12345",
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{HandshakeIdleTimeout: scaleDuration(50 * time.Millisecond)}),
			)
			errChan <- err
		}()
		var err error
		Eventually(errChan).Should(Receive(&err))
		checkTimeoutError(err)
	})

	It("returns the context error when the context expires", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		errChan := make(chan error)
		go func() {
			_, err := quic.DialAddr(
				ctx,
				"localhost:12345",
				getTLSClientConfig(),
				getQuicConfig(nil),
			)
			errChan <- err
		}()
		var err error
		Eventually(errChan).Should(Receive(&err))
		// This is not a net.Error timeout error
		Expect(err).To(MatchError(context.DeadlineExceeded))
	})

	It("returns the context error when the context expires with 0RTT enabled", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		errChan := make(chan error)
		go func() {
			_, err := quic.DialAddrEarly(
				ctx,
				"localhost:12345",
				getTLSClientConfig(),
				getQuicConfig(nil),
			)
			errChan <- err
		}()
		var err error
		Eventually(errChan).Should(Receive(&err))
		// This is not a net.Error timeout error
		Expect(err).To(MatchError(context.DeadlineExceeded))
	})

	It("returns net.Error timeout errors when an idle timeout occurs", func() {
		const idleTimeout = 500 * time.Millisecond

		server, err := quic.ListenAddr(
			"localhost:0",
			getTLSConfig(),
			getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
		)
		Expect(err).ToNot(HaveOccurred())
		defer server.Close()

		go func() {
			defer GinkgoRecover()
			conn, err := server.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			str, err := conn.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			_, err = str.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())
		}()

		var drop atomic.Bool
		proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr: fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
			DropPacket: func(quicproxy.Direction, []byte) bool {
				return drop.Load()
			},
		})
		Expect(err).ToNot(HaveOccurred())
		defer proxy.Close()

		conn, err := quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", proxy.LocalPort()),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true, MaxIdleTimeout: idleTimeout}),
		)
		Expect(err).ToNot(HaveOccurred())
		strIn, err := conn.AcceptStream(context.Background())
		Expect(err).ToNot(HaveOccurred())
		strOut, err := conn.OpenStream()
		Expect(err).ToNot(HaveOccurred())
		_, err = strIn.Read(make([]byte, 6))
		Expect(err).ToNot(HaveOccurred())

		drop.Store(true)
		time.Sleep(2 * idleTimeout)
		_, err = strIn.Write([]byte("test"))
		checkTimeoutError(err)
		_, err = strIn.Read([]byte{0})
		checkTimeoutError(err)
		_, err = strOut.Write([]byte("test"))
		checkTimeoutError(err)
		_, err = strOut.Read([]byte{0})
		checkTimeoutError(err)
		_, err = conn.OpenStream()
		checkTimeoutError(err)
		_, err = conn.OpenUniStream()
		checkTimeoutError(err)
		_, err = conn.AcceptStream(context.Background())
		checkTimeoutError(err)
		_, err = conn.AcceptUniStream(context.Background())
		checkTimeoutError(err)
	})

	Context("timing out at the right time", func() {
		var idleTimeout time.Duration

		BeforeEach(func() {
			idleTimeout = scaleDuration(500 * time.Millisecond)
		})

		It("times out after inactivity", func() {
			server, err := quic.ListenAddr(
				"localhost:0",
				getTLSConfig(),
				getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
			)
			Expect(err).ToNot(HaveOccurred())
			defer server.Close()

			serverConnClosed := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				conn, err := server.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				conn.AcceptStream(context.Background()) // blocks until the connection is closed
				close(serverConnClosed)
			}()

			counter, tr := newPacketTracer()
			conn, err := quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{
					MaxIdleTimeout:          idleTimeout,
					Tracer:                  newTracer(tr),
					DisablePathMTUDiscovery: true,
				}),
			)
			Expect(err).ToNot(HaveOccurred())
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := conn.AcceptStream(context.Background())
				checkTimeoutError(err)
				close(done)
			}()
			Eventually(done, 2*idleTimeout).Should(BeClosed())
			var lastAckElicitingPacketSentAt time.Time
			for _, p := range counter.getSentShortHeaderPackets() {
				var hasAckElicitingFrame bool
				for _, f := range p.frames {
					if _, ok := f.(*logging.AckFrame); ok {
						continue
					}
					hasAckElicitingFrame = true
					break
				}
				if hasAckElicitingFrame {
					lastAckElicitingPacketSentAt = p.time
				}
			}
			rcvdPackets := counter.getRcvdShortHeaderPackets()
			lastPacketRcvdAt := rcvdPackets[len(rcvdPackets)-1].time
			// We're ignoring here that only the first ack-eliciting packet sent resets the idle timeout.
			// This is ok since we're dealing with a lossless connection here,
			// and we'd expect to receive an ACK for additional other ack-eliciting packet sent.
			Expect(time.Since(utils.MaxTime(lastAckElicitingPacketSentAt, lastPacketRcvdAt))).To(And(
				BeNumerically(">=", idleTimeout),
				BeNumerically("<", idleTimeout*6/5),
			))
			Consistently(serverConnClosed).ShouldNot(BeClosed())

			// make the go routine return
			Expect(server.Close()).To(Succeed())
			Eventually(serverConnClosed).Should(BeClosed())
		})

		It("times out after sending a packet", func() {
			server, err := quic.ListenAddr(
				"localhost:0",
				getTLSConfig(),
				getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
			)
			Expect(err).ToNot(HaveOccurred())
			defer server.Close()

			var drop atomic.Bool
			proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
				RemoteAddr: fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				DropPacket: func(dir quicproxy.Direction, _ []byte) bool {
					if dir == quicproxy.DirectionOutgoing {
						return drop.Load()
					}
					return false
				},
			})
			Expect(err).ToNot(HaveOccurred())
			defer proxy.Close()

			serverConnClosed := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				conn, err := server.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				<-conn.Context().Done() // block until the connection is closed
				close(serverConnClosed)
			}()

			conn, err := quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", proxy.LocalPort()),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{MaxIdleTimeout: idleTimeout, DisablePathMTUDiscovery: true}),
			)
			Expect(err).ToNot(HaveOccurred())

			// wait half the idle timeout, then send a packet
			time.Sleep(idleTimeout / 2)
			drop.Store(true)
			str, err := conn.OpenUniStream()
			Expect(err).ToNot(HaveOccurred())
			_, err = str.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())

			// now make sure that the idle timeout is based on this packet
			startTime := time.Now()
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := conn.AcceptStream(context.Background())
				checkTimeoutError(err)
				close(done)
			}()
			Eventually(done, 2*idleTimeout).Should(BeClosed())
			dur := time.Since(startTime)
			Expect(dur).To(And(
				BeNumerically(">=", idleTimeout),
				BeNumerically("<", idleTimeout*12/10),
			))
			Consistently(serverConnClosed).ShouldNot(BeClosed())

			// make the go routine return
			Expect(server.Close()).To(Succeed())
			Eventually(serverConnClosed).Should(BeClosed())
		})
	})

	It("does not time out if keepalive is set", func() {
		const idleTimeout = 500 * time.Millisecond

		server, err := quic.ListenAddr(
			"localhost:0",
			getTLSConfig(),
			getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
		)
		Expect(err).ToNot(HaveOccurred())
		defer server.Close()

		serverConnClosed := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			conn, err := server.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			conn.AcceptStream(context.Background()) // blocks until the connection is closed
			close(serverConnClosed)
		}()

		var drop atomic.Bool
		proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr: fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
			DropPacket: func(quicproxy.Direction, []byte) bool {
				return drop.Load()
			},
		})
		Expect(err).ToNot(HaveOccurred())
		defer proxy.Close()

		conn, err := quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", proxy.LocalPort()),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{
				MaxIdleTimeout:          idleTimeout,
				KeepAlivePeriod:         idleTimeout / 2,
				DisablePathMTUDiscovery: true,
			}),
		)
		Expect(err).ToNot(HaveOccurred())

		// wait longer than the idle timeout
		time.Sleep(3 * idleTimeout)
		str, err := conn.OpenUniStream()
		Expect(err).ToNot(HaveOccurred())
		_, err = str.Write([]byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		Consistently(serverConnClosed).ShouldNot(BeClosed())

		// idle timeout will still kick in if pings are dropped
		drop.Store(true)
		time.Sleep(2 * idleTimeout)
		_, err = str.Write([]byte("foobar"))
		checkTimeoutError(err)

		Expect(server.Close()).To(Succeed())
		Eventually(serverConnClosed).Should(BeClosed())
	})

	Context("faulty packet conns", func() {
		const handshakeTimeout = time.Second / 2

		runServer := func(ln *quic.Listener) error {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return err
			}
			str, err := conn.OpenUniStream()
			if err != nil {
				return err
			}
			defer str.Close()
			_, err = str.Write(PRData)
			return err
		}

		runClient := func(conn quic.Connection) error {
			str, err := conn.AcceptUniStream(context.Background())
			if err != nil {
				return err
			}
			data, err := io.ReadAll(str)
			if err != nil {
				return err
			}
			Expect(data).To(Equal(PRData))
			return conn.CloseWithError(0, "done")
		}

		It("deals with an erroring packet conn, on the server side", func() {
			addr, err := net.ResolveUDPAddr("udp", "localhost:0")
			Expect(err).ToNot(HaveOccurred())
			conn, err := net.ListenUDP("udp", addr)
			Expect(err).ToNot(HaveOccurred())
			maxPackets := mrand.Int31n(25)
			fmt.Fprintf(GinkgoWriter, "blocking connection after %d packets\n", maxPackets)
			ln, err := quic.Listen(
				&faultyConn{PacketConn: conn, MaxPackets: maxPackets},
				getTLSConfig(),
				getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
			)
			Expect(err).ToNot(HaveOccurred())

			serverErrChan := make(chan error, 1)
			go func() {
				defer GinkgoRecover()
				serverErrChan <- runServer(ln)
			}()

			clientErrChan := make(chan error, 1)
			go func() {
				defer GinkgoRecover()
				conn, err := quic.DialAddr(
					context.Background(),
					fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
					getTLSClientConfig(),
					getQuicConfig(&quic.Config{
						HandshakeIdleTimeout:    handshakeTimeout,
						MaxIdleTimeout:          handshakeTimeout,
						DisablePathMTUDiscovery: true,
					}),
				)
				if err != nil {
					clientErrChan <- err
					return
				}
				clientErrChan <- runClient(conn)
			}()

			var clientErr error
			Eventually(clientErrChan, 5*handshakeTimeout).Should(Receive(&clientErr))
			Expect(clientErr).To(HaveOccurred())
			nErr, ok := clientErr.(net.Error)
			Expect(ok).To(BeTrue())
			Expect(nErr.Timeout()).To(BeTrue())

			select {
			case serverErr := <-serverErrChan:
				Expect(serverErr).To(HaveOccurred())
				Expect(serverErr.Error()).To(ContainSubstring(io.ErrClosedPipe.Error()))
				defer ln.Close()
			default:
				Expect(ln.Close()).To(Succeed())
				Eventually(serverErrChan).Should(Receive())
			}
		})

		It("deals with an erroring packet conn, on the client side", func() {
			ln, err := quic.ListenAddr(
				"localhost:0",
				getTLSConfig(),
				getQuicConfig(&quic.Config{
					HandshakeIdleTimeout:    handshakeTimeout,
					MaxIdleTimeout:          handshakeTimeout,
					KeepAlivePeriod:         handshakeTimeout / 2,
					DisablePathMTUDiscovery: true,
				}),
			)
			Expect(err).ToNot(HaveOccurred())
			defer ln.Close()

			serverErrChan := make(chan error, 1)
			go func() {
				defer GinkgoRecover()
				serverErrChan <- runServer(ln)
			}()

			addr, err := net.ResolveUDPAddr("udp", "localhost:0")
			Expect(err).ToNot(HaveOccurred())
			conn, err := net.ListenUDP("udp", addr)
			Expect(err).ToNot(HaveOccurred())
			maxPackets := mrand.Int31n(25)
			fmt.Fprintf(GinkgoWriter, "blocking connection after %d packets\n", maxPackets)
			clientErrChan := make(chan error, 1)
			go func() {
				defer GinkgoRecover()
				conn, err := quic.Dial(
					context.Background(),
					&faultyConn{PacketConn: conn, MaxPackets: maxPackets},
					ln.Addr(),
					getTLSClientConfig(),
					getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
				)
				if err != nil {
					clientErrChan <- err
					return
				}
				clientErrChan <- runClient(conn)
			}()

			var clientErr error
			Eventually(clientErrChan, 5*handshakeTimeout).Should(Receive(&clientErr))
			Expect(clientErr).To(HaveOccurred())
			Expect(clientErr.Error()).To(ContainSubstring(io.ErrClosedPipe.Error()))
			Eventually(areHandshakesRunning, 5*handshakeTimeout).Should(BeFalse())
			select {
			case serverErr := <-serverErrChan: // The handshake completed on the server side.
				Expect(serverErr).To(HaveOccurred())
				nErr, ok := serverErr.(net.Error)
				Expect(ok).To(BeTrue())
				Expect(nErr.Timeout()).To(BeTrue())
			default: // The handshake didn't complete
				Expect(ln.Close()).To(Succeed())
				Eventually(serverErrChan).Should(Receive())
			}
		})
	})
})
