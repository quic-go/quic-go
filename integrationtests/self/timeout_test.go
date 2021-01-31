package self_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	mrand "math/rand"
	"net"
	"runtime/pprof"
	"strings"
	"sync/atomic"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	quicproxy "github.com/lucas-clemente/quic-go/integrationtests/tools/proxy"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/logging"
	. "github.com/onsi/ginkgo"
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

type handshakeCompleteTracer struct {
	connTracer
	completionTime time.Time
}

func (t *handshakeCompleteTracer) DroppedEncryptionLevel(l protocol.EncryptionLevel) {
	if l == protocol.EncryptionHandshake {
		t.completionTime = time.Now()
	}
}

func areHandshakesRunning() bool {
	var b bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Contains(b.String(), "RunHandshake")
}

var _ = Describe("Timeout tests", func() {
	checkTimeoutError := func(err error) {
		ExpectWithOffset(1, err).To(HaveOccurred())
		nerr, ok := err.(net.Error)
		ExpectWithOffset(1, ok).To(BeTrue())
		ExpectWithOffset(1, nerr.Timeout()).To(BeTrue())
	}

	It("returns net.Error timeout errors when dialing", func() {
		errChan := make(chan error)
		go func() {
			_, err := quic.DialAddr(
				"localhost:12345",
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{HandshakeIdleTimeout: 10 * time.Millisecond}),
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
			_, err := quic.DialAddrContext(
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
			_, err := quic.DialAddrEarlyContext(
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
		const idleTimeout = 100 * time.Millisecond

		server, err := quic.ListenAddr(
			"localhost:0",
			getTLSConfig(),
			getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
		)
		Expect(err).ToNot(HaveOccurred())
		defer server.Close()

		go func() {
			defer GinkgoRecover()
			sess, err := server.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			str, err := sess.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			_, err = str.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())
		}()

		drop := utils.AtomicBool{}

		proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr: fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
			DropPacket: func(quicproxy.Direction, []byte) bool {
				return drop.Get()
			},
		})
		Expect(err).ToNot(HaveOccurred())
		defer proxy.Close()

		sess, err := quic.DialAddr(
			fmt.Sprintf("localhost:%d", proxy.LocalPort()),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true, MaxIdleTimeout: idleTimeout}),
		)
		Expect(err).ToNot(HaveOccurred())
		strIn, err := sess.AcceptStream(context.Background())
		Expect(err).ToNot(HaveOccurred())
		strOut, err := sess.OpenStream()
		Expect(err).ToNot(HaveOccurred())
		_, err = strIn.Read(make([]byte, 6))
		Expect(err).ToNot(HaveOccurred())

		drop.Set(true)
		time.Sleep(2 * idleTimeout)
		_, err = strIn.Write([]byte("test"))
		checkTimeoutError(err)
		_, err = strIn.Read([]byte{0})
		checkTimeoutError(err)
		_, err = strOut.Write([]byte("test"))
		checkTimeoutError(err)
		_, err = strOut.Read([]byte{0})
		checkTimeoutError(err)
		_, err = sess.OpenStream()
		checkTimeoutError(err)
		_, err = sess.OpenUniStream()
		checkTimeoutError(err)
		_, err = sess.AcceptStream(context.Background())
		checkTimeoutError(err)
		_, err = sess.AcceptUniStream(context.Background())
		checkTimeoutError(err)
	})

	Context("timing out at the right time", func() {
		var idleTimeout time.Duration

		BeforeEach(func() {
			idleTimeout = scaleDuration(100 * time.Millisecond)
		})

		It("times out after inactivity", func() {
			server, err := quic.ListenAddr(
				"localhost:0",
				getTLSConfig(),
				getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
			)
			Expect(err).ToNot(HaveOccurred())
			defer server.Close()

			serverSessionClosed := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				sess, err := server.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				sess.AcceptStream(context.Background()) // blocks until the session is closed
				close(serverSessionClosed)
			}()

			tr := &handshakeCompleteTracer{}
			sess, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{
					MaxIdleTimeout:          idleTimeout,
					Tracer:                  newTracer(func() logging.ConnectionTracer { return tr }),
					DisablePathMTUDiscovery: true,
				}),
			)
			Expect(err).ToNot(HaveOccurred())
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := sess.AcceptStream(context.Background())
				checkTimeoutError(err)
				close(done)
			}()
			Eventually(done, 2*idleTimeout).Should(BeClosed())
			Expect(tr.completionTime).ToNot(BeZero())
			dur := time.Since(tr.completionTime)
			Expect(dur).To(And(
				BeNumerically(">=", idleTimeout),
				BeNumerically("<", idleTimeout*6/5),
			))
			Consistently(serverSessionClosed).ShouldNot(BeClosed())

			// make the go routine return
			Expect(server.Close()).To(Succeed())
			Eventually(serverSessionClosed).Should(BeClosed())
		})

		It("times out after sending a packet", func() {
			server, err := quic.ListenAddr(
				"localhost:0",
				getTLSConfig(),
				getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
			)
			Expect(err).ToNot(HaveOccurred())
			defer server.Close()

			drop := utils.AtomicBool{}
			proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
				RemoteAddr: fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				DropPacket: func(dir quicproxy.Direction, _ []byte) bool {
					if dir == quicproxy.DirectionOutgoing {
						return drop.Get()
					}
					return false
				},
			})
			Expect(err).ToNot(HaveOccurred())
			defer proxy.Close()

			serverSessionClosed := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				sess, err := server.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				<-sess.Context().Done() // block until the session is closed
				close(serverSessionClosed)
			}()

			sess, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", proxy.LocalPort()),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{MaxIdleTimeout: idleTimeout, DisablePathMTUDiscovery: true}),
			)
			Expect(err).ToNot(HaveOccurred())

			// wait half the idle timeout, then send a packet
			time.Sleep(idleTimeout / 2)
			drop.Set(true)
			str, err := sess.OpenUniStream()
			Expect(err).ToNot(HaveOccurred())
			_, err = str.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())

			// now make sure that the idle timeout is based on this packet
			startTime := time.Now()
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := sess.AcceptStream(context.Background())
				checkTimeoutError(err)
				close(done)
			}()
			Eventually(done, 2*idleTimeout).Should(BeClosed())
			dur := time.Since(startTime)
			Expect(dur).To(And(
				BeNumerically(">=", idleTimeout),
				BeNumerically("<", idleTimeout*12/10),
			))
			Consistently(serverSessionClosed).ShouldNot(BeClosed())

			// make the go routine return
			Expect(server.Close()).To(Succeed())
			Eventually(serverSessionClosed).Should(BeClosed())
		})
	})

	It("does not time out if keepalive is set", func() {
		const idleTimeout = 100 * time.Millisecond

		server, err := quic.ListenAddr(
			"localhost:0",
			getTLSConfig(),
			getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
		)
		Expect(err).ToNot(HaveOccurred())
		defer server.Close()

		serverSessionClosed := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			sess, err := server.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			sess.AcceptStream(context.Background()) // blocks until the session is closed
			close(serverSessionClosed)
		}()

		drop := utils.AtomicBool{}
		proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr: fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
			DropPacket: func(quicproxy.Direction, []byte) bool {
				return drop.Get()
			},
		})
		Expect(err).ToNot(HaveOccurred())
		defer proxy.Close()

		sess, err := quic.DialAddr(
			fmt.Sprintf("localhost:%d", proxy.LocalPort()),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{
				MaxIdleTimeout:          idleTimeout,
				KeepAlive:               true,
				DisablePathMTUDiscovery: true,
			}),
		)
		Expect(err).ToNot(HaveOccurred())

		// wait longer than the idle timeout
		time.Sleep(3 * idleTimeout)
		str, err := sess.OpenUniStream()
		Expect(err).ToNot(HaveOccurred())
		_, err = str.Write([]byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		Consistently(serverSessionClosed).ShouldNot(BeClosed())

		// idle timeout will still kick in if pings are dropped
		drop.Set(true)
		time.Sleep(2 * idleTimeout)
		_, err = str.Write([]byte("foobar"))
		checkTimeoutError(err)

		Expect(server.Close()).To(Succeed())
		Eventually(serverSessionClosed).Should(BeClosed())
	})

	Context("faulty packet conns", func() {
		const handshakeTimeout = time.Second / 2

		BeforeEach(func() {
			Expect(areHandshakesRunning()).To(BeFalse())
		})

		AfterEach(func() {
			Expect(areHandshakesRunning()).To(BeFalse())
		})

		runServer := func(ln quic.Listener) error {
			sess, err := ln.Accept(context.Background())
			if err != nil {
				return err
			}
			str, err := sess.OpenUniStream()
			if err != nil {
				return err
			}
			defer str.Close()
			_, err = str.Write(PRData)
			return err
		}

		runClient := func(sess quic.Session) error {
			str, err := sess.AcceptUniStream(context.Background())
			if err != nil {
				return err
			}
			data, err := ioutil.ReadAll(str)
			if err != nil {
				return err
			}
			Expect(data).To(Equal(PRData))
			return sess.CloseWithError(0, "done")
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
				sess, err := quic.DialAddr(
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
				clientErrChan <- runClient(sess)
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
					KeepAlive:               true,
					DisablePathMTUDiscovery: true,
				}),
			)
			Expect(err).ToNot(HaveOccurred())

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
				sess, err := quic.Dial(
					&faultyConn{PacketConn: conn, MaxPackets: maxPackets},
					ln.Addr(),
					"localhost",
					getTLSClientConfig(),
					getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
				)
				if err != nil {
					clientErrChan <- err
					return
				}
				clientErrChan <- runClient(sess)
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
