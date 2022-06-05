package self_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Bidirectional streams", func() {
	const numStreams = 300

	var (
		server     quic.Listener
		serverAddr string
		qconf      *quic.Config
	)

	for _, v := range []protocol.VersionNumber{protocol.VersionTLS} {
		version := v

		Context(fmt.Sprintf("with QUIC %s", version), func() {
			BeforeEach(func() {
				var err error
				qconf = &quic.Config{
					Versions:           []protocol.VersionNumber{version},
					MaxIncomingStreams: 0,
				}
				server, err = quic.ListenAddr("localhost:0", getTLSConfig(), getQuicConfig(qconf))
				Expect(err).ToNot(HaveOccurred())
				serverAddr = fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port)
			})

			AfterEach(func() {
				server.Close()
			})

			runSendingPeer := func(conn quic.Connection) {
				var wg sync.WaitGroup
				wg.Add(numStreams)
				for i := 0; i < numStreams; i++ {
					str, err := conn.OpenStreamSync(context.Background())
					Expect(err).ToNot(HaveOccurred())
					data := GeneratePRData(25 * i)
					go func() {
						defer GinkgoRecover()
						_, err := str.Write(data)
						Expect(err).ToNot(HaveOccurred())
						Expect(str.Close()).To(Succeed())
					}()
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						dataRead, err := io.ReadAll(str)
						Expect(err).ToNot(HaveOccurred())
						Expect(dataRead).To(Equal(data))
					}()
				}
				wg.Wait()
			}

			runReceivingPeer := func(conn quic.Connection) {
				var wg sync.WaitGroup
				wg.Add(numStreams)
				for i := 0; i < numStreams; i++ {
					str, err := conn.AcceptStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						// shouldn't use io.Copy here
						// we should read from the stream as early as possible, to free flow control credit
						data, err := io.ReadAll(str)
						Expect(err).ToNot(HaveOccurred())
						_, err = str.Write(data)
						Expect(err).ToNot(HaveOccurred())
						Expect(str.Close()).To(Succeed())
					}()
				}
				wg.Wait()
			}

			It(fmt.Sprintf("client opening %d streams to a server", numStreams), func() {
				var conn quic.Connection
				go func() {
					defer GinkgoRecover()
					var err error
					conn, err = server.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())
					runReceivingPeer(conn)
				}()

				client, err := quic.DialAddr(
					serverAddr,
					getTLSClientConfig(),
					getQuicConfig(qconf),
				)
				Expect(err).ToNot(HaveOccurred())
				runSendingPeer(client)
			})

			It(fmt.Sprintf("server opening %d streams to a client", numStreams), func() {
				go func() {
					defer GinkgoRecover()
					conn, err := server.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())
					runSendingPeer(conn)
					conn.CloseWithError(0, "")
				}()

				client, err := quic.DialAddr(
					serverAddr,
					getTLSClientConfig(),
					getQuicConfig(qconf),
				)
				Expect(err).ToNot(HaveOccurred())
				runReceivingPeer(client)
				Eventually(client.Context().Done()).Should(BeClosed())
			})

			It(fmt.Sprintf("client and server opening %d each and sending data to the peer", numStreams), func() {
				done1 := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					conn, err := server.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())
					done := make(chan struct{})
					go func() {
						defer GinkgoRecover()
						runReceivingPeer(conn)
						close(done)
					}()
					runSendingPeer(conn)
					<-done
					close(done1)
				}()

				client, err := quic.DialAddr(
					serverAddr,
					getTLSClientConfig(),
					getQuicConfig(qconf),
				)
				Expect(err).ToNot(HaveOccurred())
				done2 := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					runSendingPeer(client)
					close(done2)
				}()
				runReceivingPeer(client)
				<-done1
				<-done2
			})

			It("calls the OnStreamDone callback, for bidirectional streams", func() {
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					defer close(done)
					conn, err := server.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())
					str, err := conn.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					str.Write([]byte("foobar"))
					Expect(str.Close()).To(Succeed())
					<-conn.Context().Done()
				}()

				conf := getQuicConfig(qconf)
				streamCloseChan := make(chan quic.StreamID, 1)
				conf.OnStreamDone = func(_ quic.Connection, id quic.StreamID) { streamCloseChan <- id }
				conn, err := quic.DialAddr(
					serverAddr,
					getTLSClientConfig(),
					conf,
				)
				Expect(err).ToNot(HaveOccurred())
				str, err := conn.AcceptStream(context.Background())
				Expect(err).ToNot(HaveOccurred())
				_, err = io.ReadAll(str)
				Expect(err).ToNot(HaveOccurred())
				// only the read side is closed, we're still tracking this stream
				Consistently(streamCloseChan).ShouldNot(Receive())
				// now reset the write side of the stream (closing would work as well)
				str.CancelWrite(1337)
				Eventually(streamCloseChan).Should(Receive(Equal(quic.StreamID(1))))
				conn.CloseWithError(0, "")
				Eventually(done).Should(BeClosed())
			})

			It("calls the OnStreamDone callback, for unidirectional streams", func() {
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					defer close(done)
					conn, err := server.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())
					str, err := conn.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())
					str.Write([]byte("foobar"))
					Expect(str.Close()).To(Succeed())
					<-conn.Context().Done()
				}()

				conf := getQuicConfig(qconf)
				streamCloseChan := make(chan quic.StreamID, 1)
				conf.OnStreamDone = func(_ quic.Connection, id quic.StreamID) { streamCloseChan <- id }
				conn, err := quic.DialAddr(
					serverAddr,
					getTLSClientConfig(),
					conf,
				)
				Expect(err).ToNot(HaveOccurred())
				// At this point, the stream is already closed.
				// We only expect the callback to be called once we've actually accepted it though.
				Consistently(streamCloseChan).ShouldNot(Receive())
				str, err := conn.AcceptUniStream(context.Background())
				Expect(err).ToNot(HaveOccurred())
				_, err = io.ReadAll(str)
				Expect(err).ToNot(HaveOccurred())
				Eventually(streamCloseChan).Should(Receive(Equal(quic.StreamID(3))))
				conn.CloseWithError(0, "")
				Eventually(done).Should(BeClosed())
			})

			It("calls the OnStreamDone callback when closing", func() {
				done := make(chan struct{})
				closeChan := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					defer close(done)
					conn, err := server.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())
					ustr, err := conn.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())
					ustr.Write([]byte("foo"))
					str, err := conn.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					str.Write([]byte("bar"))
					<-closeChan
					conn.CloseWithError(0, "")
				}()

				conf := getQuicConfig(qconf)
				var doneStreams []quic.StreamID
				conf.OnStreamDone = func(_ quic.Connection, id quic.StreamID) { doneStreams = append(doneStreams, id) }
				conn, err := quic.DialAddr(
					serverAddr,
					getTLSClientConfig(),
					conf,
				)
				Expect(err).ToNot(HaveOccurred())
				// At this point, the stream is already closed.
				// We only expect the callback to be called once we've actually accepted it though.
				close(closeChan)
				<-conn.Context().Done()
				Expect(doneStreams).To(ContainElements(quic.StreamID(1), quic.StreamID(3)))
			})
		})
	}
})
