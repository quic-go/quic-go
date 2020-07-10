package self_test

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	mrand "math/rand"
	"net"
	"os"
	"strconv"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	quicproxy "github.com/lucas-clemente/quic-go/integrationtests/tools/proxy"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type faultyConn struct {
	net.PacketConn
	Timeout time.Time
}

func (c *faultyConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if time.Now().Before(c.Timeout) {
		return c.PacketConn.ReadFrom(p)
	}
	return 0, nil, io.ErrClosedPipe
}

func (c *faultyConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if time.Now().Before(c.Timeout) {
		return c.PacketConn.WriteTo(p, addr)
	}
	return 0, io.ErrClosedPipe
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
				getQuicConfigForClient(&quic.Config{HandshakeTimeout: 10 * time.Millisecond}),
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
				getQuicConfigForClient(nil),
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
			getQuicConfigForServer(nil),
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
			getQuicConfigForClient(&quic.Config{MaxIdleTimeout: idleTimeout}),
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

		scaleDuration := func(d time.Duration) time.Duration {
			scaleFactor := 1
			if f, err := strconv.Atoi(os.Getenv("TIMESCALE_FACTOR")); err == nil { // parsing "" errors, so this works fine if the env is not set
				scaleFactor = f
			}
			Expect(scaleFactor).ToNot(BeZero())
			return time.Duration(scaleFactor) * d
		}

		BeforeEach(func() {
			idleTimeout = scaleDuration(100 * time.Millisecond)
		})

		It("times out after inactivity", func() {
			server, err := quic.ListenAddr(
				"localhost:0",
				getTLSConfig(),
				getQuicConfigForServer(nil),
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

			sess, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfigForClient(&quic.Config{MaxIdleTimeout: idleTimeout}),
			)
			Expect(err).ToNot(HaveOccurred())
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
				getQuicConfigForServer(nil),
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

			sess, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfigForClient(&quic.Config{MaxIdleTimeout: idleTimeout}),
			)
			Expect(err).ToNot(HaveOccurred())

			// wait half the idle timeout, then send a packet
			time.Sleep(idleTimeout / 2)
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
			getQuicConfigForServer(nil),
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
			getQuicConfigForClient(&quic.Config{
				MaxIdleTimeout: idleTimeout,
				KeepAlive:      true,
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
		runServer := func(ctx context.Context, ln quic.Listener) error {
			sess, err := ln.Accept(ctx)
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
			timeout := time.Duration(mrand.Intn(150)) * time.Millisecond
			fmt.Fprintf(GinkgoWriter, "Timeout: %s\n", timeout)
			ln, err := quic.Listen(
				&faultyConn{PacketConn: conn, Timeout: time.Now().Add(timeout)},
				getTLSConfig(),
				getQuicConfigForServer(nil),
			)
			Expect(err).ToNot(HaveOccurred())

			proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
				RemoteAddr:  fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
				DelayPacket: func(quicproxy.Direction, []byte) time.Duration { return 10 * time.Millisecond },
			})
			Expect(err).ToNot(HaveOccurred())
			defer proxy.Close()

			serverErrChan := make(chan error, 1)
			go func() {
				defer GinkgoRecover()
				serverErrChan <- runServer(context.Background(), ln)
			}()

			clientErrChan := make(chan error, 1)
			go func() {
				defer GinkgoRecover()
				sess, err := quic.DialAddr(
					fmt.Sprintf("localhost:%d", proxy.LocalPort()),
					getTLSClientConfig(),
					getQuicConfigForClient(&quic.Config{
						HandshakeTimeout: time.Second,
						MaxIdleTimeout:   time.Second,
					}),
				)
				if err != nil {
					clientErrChan <- err
					return
				}
				clientErrChan <- runClient(sess)
			}()

			var serverErr, clientErr error
			Eventually(serverErrChan, 5*time.Second).Should(Receive(&serverErr))
			if serverErr != nil {
				Expect(serverErr.Error()).To(ContainSubstring(io.ErrClosedPipe.Error()))
			}
			Eventually(clientErrChan, 5*time.Second).Should(Receive(&clientErr))
			if clientErr != nil {
				nErr, ok := clientErr.(net.Error)
				Expect(ok).To(BeTrue())
				Expect(nErr.Timeout()).To(BeTrue())
			}
		})

		It("deals with an erroring packet conn, on the client side", func() {
			ln, err := quic.ListenAddr(
				"localhost:0",
				getTLSConfig(),
				getQuicConfigForServer(&quic.Config{
					HandshakeTimeout: time.Second,
					MaxIdleTimeout:   time.Second,
					KeepAlive:        true,
				}),
			)
			Expect(err).ToNot(HaveOccurred())

			proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
				RemoteAddr:  fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
				DelayPacket: func(quicproxy.Direction, []byte) time.Duration { return 10 * time.Millisecond },
			})
			Expect(err).ToNot(HaveOccurred())
			defer proxy.Close()

			// If the connection errors before the handshake completes, the handshake will fail with a
			// handshake error on the server side. This means that the session will never be returned
			// on ln.Accept().
			// By using this context for ln.Accept(), we make sure that the runServer() still returns.
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			serverErrChan := make(chan error, 1)
			go func() {
				defer GinkgoRecover()
				serverErrChan <- runServer(ctx, ln)
			}()

			addr, err := net.ResolveUDPAddr("udp", "localhost:0")
			Expect(err).ToNot(HaveOccurred())
			conn, err := net.ListenUDP("udp", addr)
			Expect(err).ToNot(HaveOccurred())
			timeout := time.Duration(mrand.Intn(150)) * time.Millisecond
			fmt.Fprintf(GinkgoWriter, "Timeout: %s\n", timeout)
			clientErrChan := make(chan error, 1)
			go func() {
				defer GinkgoRecover()
				sess, err := quic.Dial(
					&faultyConn{PacketConn: conn, Timeout: time.Now().Add(timeout)},
					proxy.LocalAddr(),
					"localhost",
					getTLSClientConfig(),
					getQuicConfigForClient(nil),
				)
				if err != nil {
					clientErrChan <- err
					return
				}
				clientErrChan <- runClient(sess)
			}()

			var serverErr, clientErr error
			Eventually(clientErrChan, 5*time.Second).Should(Receive(&clientErr))
			if clientErr != nil {
				Expect(clientErr.Error()).To(ContainSubstring(io.ErrClosedPipe.Error()))
				cancel()
			}
			Eventually(serverErrChan, 5*time.Second).Should(Receive(&serverErr))
			if serverErr != nil && serverErr != context.Canceled {
				nErr, ok := serverErr.(net.Error)
				Expect(ok).To(BeTrue())
				Expect(nErr.Timeout()).To(BeTrue())
			}

		})
	})
})
