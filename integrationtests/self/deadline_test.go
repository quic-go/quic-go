package self_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stream deadline tests", func() {
	setup := func() (serverStr, clientStr quic.Stream, close func()) {
		server, err := quic.ListenAddr("localhost:0", getTLSConfig(), getQuicConfig(nil))
		Expect(err).ToNot(HaveOccurred())
		strChan := make(chan quic.SendStream)
		go func() {
			defer GinkgoRecover()
			conn, err := server.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			str, err := conn.AcceptStream(context.Background())
			Expect(err).ToNot(HaveOccurred())
			_, err = str.Read([]byte{0})
			Expect(err).ToNot(HaveOccurred())
			strChan <- str
		}()

		conn, err := quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
			getTLSClientConfig(),
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		clientStr, err = conn.OpenStream()
		Expect(err).ToNot(HaveOccurred())
		_, err = clientStr.Write([]byte{0}) // need to write one byte so the server learns about the stream
		Expect(err).ToNot(HaveOccurred())
		Eventually(strChan).Should(Receive(&serverStr))
		return serverStr, clientStr, func() {
			Expect(server.Close()).To(Succeed())
			Expect(conn.CloseWithError(0, "")).To(Succeed())
		}
	}

	Context("read deadlines", func() {
		It("completes a transfer when the deadline is set", func() {
			serverStr, clientStr, closeFn := setup()
			defer closeFn()

			const timeout = time.Millisecond
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := serverStr.Write(PRDataLong)
				Expect(err).ToNot(HaveOccurred())
				close(done)
			}()

			var bytesRead int
			var timeoutCounter int
			buf := make([]byte, 1<<10)
			data := make([]byte, len(PRDataLong))
			clientStr.SetReadDeadline(time.Now().Add(timeout))
			for bytesRead < len(PRDataLong) {
				n, err := clientStr.Read(buf)
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					timeoutCounter++
					clientStr.SetReadDeadline(time.Now().Add(timeout))
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
				copy(data[bytesRead:], buf[:n])
				bytesRead += n
			}
			Expect(data).To(Equal(PRDataLong))
			// make sure the test actually worked and Read actually ran into the deadline a few times
			Expect(timeoutCounter).To(BeNumerically(">=", 10))
			Eventually(done).Should(BeClosed())
		})

		It("completes a transfer when the deadline is set concurrently", func() {
			serverStr, clientStr, closeFn := setup()
			defer closeFn()

			const timeout = time.Millisecond
			go func() {
				defer GinkgoRecover()
				_, err := serverStr.Write(PRDataLong)
				Expect(err).ToNot(HaveOccurred())
			}()

			var bytesRead int
			var timeoutCounter int
			buf := make([]byte, 1<<10)
			data := make([]byte, len(PRDataLong))
			clientStr.SetReadDeadline(time.Now().Add(timeout))
			deadlineDone := make(chan struct{})
			received := make(chan struct{})
			go func() {
				defer close(deadlineDone)
				for {
					select {
					case <-received:
						return
					default:
						time.Sleep(timeout)
					}
					clientStr.SetReadDeadline(time.Now().Add(timeout))
				}
			}()

			for bytesRead < len(PRDataLong) {
				n, err := clientStr.Read(buf)
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					timeoutCounter++
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
				copy(data[bytesRead:], buf[:n])
				bytesRead += n
			}
			close(received)
			Expect(data).To(Equal(PRDataLong))
			// make sure the test actually worked an Read actually ran into the deadline a few times
			Expect(timeoutCounter).To(BeNumerically(">=", 10))
			Eventually(deadlineDone).Should(BeClosed())
		})
	})

	Context("write deadlines", func() {
		It("completes a transfer when the deadline is set", func() {
			serverStr, clientStr, closeFn := setup()
			defer closeFn()

			const timeout = time.Millisecond
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				data, err := io.ReadAll(serverStr)
				Expect(err).ToNot(HaveOccurred())
				Expect(data).To(Equal(PRDataLong))
				close(done)
			}()

			var bytesWritten int
			var timeoutCounter int
			clientStr.SetWriteDeadline(time.Now().Add(timeout))
			for bytesWritten < len(PRDataLong) {
				n, err := clientStr.Write(PRDataLong[bytesWritten:])
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					timeoutCounter++
					clientStr.SetWriteDeadline(time.Now().Add(timeout))
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
				bytesWritten += n
			}
			clientStr.Close()
			// make sure the test actually worked an Read actually ran into the deadline a few times
			Expect(timeoutCounter).To(BeNumerically(">=", 10))
			Eventually(done).Should(BeClosed())
		})

		It("completes a transfer when the deadline is set concurrently", func() {
			serverStr, clientStr, closeFn := setup()
			defer closeFn()

			const timeout = time.Millisecond
			readDone := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				data, err := io.ReadAll(serverStr)
				Expect(err).ToNot(HaveOccurred())
				Expect(data).To(Equal(PRDataLong))
				close(readDone)
			}()

			clientStr.SetWriteDeadline(time.Now().Add(timeout))
			deadlineDone := make(chan struct{})
			go func() {
				defer close(deadlineDone)
				for {
					select {
					case <-readDone:
						return
					default:
						time.Sleep(timeout)
					}
					clientStr.SetWriteDeadline(time.Now().Add(timeout))
				}
			}()

			var bytesWritten int
			var timeoutCounter int
			clientStr.SetWriteDeadline(time.Now().Add(timeout))
			for bytesWritten < len(PRDataLong) {
				n, err := clientStr.Write(PRDataLong[bytesWritten:])
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					timeoutCounter++
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
				bytesWritten += n
			}
			clientStr.Close()
			// make sure the test actually worked an Read actually ran into the deadline a few times
			Expect(timeoutCounter).To(BeNumerically(">=", 10))
			Eventually(readDone).Should(BeClosed())
			Eventually(deadlineDone).Should(BeClosed())
		})
	})
})
