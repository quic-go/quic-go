package self_test

import (
	"context"
	"fmt"
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
				&quic.Config{HandshakeTimeout: 10 * time.Millisecond},
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
				nil,
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
			nil,
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
			&quic.Config{IdleTimeout: idleTimeout},
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
			server, err := quic.ListenAddr("localhost:0", getTLSConfig(), nil)
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
				&quic.Config{IdleTimeout: idleTimeout},
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
			server, err := quic.ListenAddr("localhost:0", getTLSConfig(), nil)
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
				&quic.Config{IdleTimeout: idleTimeout},
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
})
