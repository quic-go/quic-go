package self_test

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stream Cancellations", func() {
	const numStreams = 80

	Context("canceling the read side", func() {
		var server quic.Listener

		// The server accepts a single connection, and then opens numStreams unidirectional streams.
		// On each of these streams, it (tries to) write PRData.
		// When done, it sends the number of canceled streams on the channel.
		runServer := func(data []byte) <-chan int32 {
			numCanceledStreamsChan := make(chan int32)
			var err error
			server, err = quic.ListenAddr("localhost:0", getTLSConfig(), getQuicConfig(nil))
			Expect(err).ToNot(HaveOccurred())

			var canceledCounter int32
			go func() {
				defer GinkgoRecover()
				var wg sync.WaitGroup
				wg.Add(numStreams)
				conn, err := server.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				for i := 0; i < numStreams; i++ {
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						str, err := conn.OpenUniStreamSync(context.Background())
						Expect(err).ToNot(HaveOccurred())
						if _, err := str.Write(data); err != nil {
							Expect(err).To(Equal(&quic.StreamError{
								StreamID:  str.StreamID(),
								ErrorCode: quic.StreamErrorCode(str.StreamID()),
								Remote:    true,
							}))
							atomic.AddInt32(&canceledCounter, 1)
							return
						}
						if err := str.Close(); err != nil {
							Expect(err).To(MatchError(fmt.Sprintf("close called for canceled stream %d", str.StreamID())))
							atomic.AddInt32(&canceledCounter, 1)
							return
						}
					}()
				}
				wg.Wait()
				numCanceledStreamsChan <- atomic.LoadInt32(&canceledCounter)
			}()
			return numCanceledStreamsChan
		}

		AfterEach(func() {
			Expect(server.Close()).To(Succeed())
		})

		It("downloads when the client immediately cancels most streams", func() {
			serverCanceledCounterChan := runServer(PRData)
			conn, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{MaxIncomingUniStreams: numStreams / 2}),
			)
			Expect(err).ToNot(HaveOccurred())

			var canceledCounter int32
			var wg sync.WaitGroup
			wg.Add(numStreams)
			for i := 0; i < numStreams; i++ {
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					str, err := conn.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					// cancel around 2/3 of the streams
					if rand.Int31()%3 != 0 {
						atomic.AddInt32(&canceledCounter, 1)
						resetErr := quic.StreamErrorCode(str.StreamID())
						str.CancelRead(resetErr)
						_, err := str.Read([]byte{0})
						Expect(err).To(Equal(&quic.StreamError{
							StreamID:  str.StreamID(),
							ErrorCode: resetErr,
							Remote:    false,
						}))
						return
					}
					data, err := io.ReadAll(str)
					Expect(err).ToNot(HaveOccurred())
					Expect(data).To(Equal(PRData))
				}()
			}
			wg.Wait()

			var serverCanceledCounter int32
			Eventually(serverCanceledCounterChan).Should(Receive(&serverCanceledCounter))
			Expect(conn.CloseWithError(0, "")).To(Succeed())

			clientCanceledCounter := atomic.LoadInt32(&canceledCounter)
			// The server will only count a stream as being reset if learns about the cancelation before it finished writing all data.
			Expect(clientCanceledCounter).To(BeNumerically(">=", serverCanceledCounter))
			fmt.Fprintf(GinkgoWriter, "Canceled reading on %d of %d streams.\n", clientCanceledCounter, numStreams)
			Expect(clientCanceledCounter).To(BeNumerically(">", numStreams/10))
			Expect(numStreams - clientCanceledCounter).To(BeNumerically(">", numStreams/10))
		})

		It("downloads when the client cancels streams after reading from them for a bit", func() {
			serverCanceledCounterChan := runServer(PRData)

			conn, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{MaxIncomingUniStreams: numStreams / 2}),
			)
			Expect(err).ToNot(HaveOccurred())

			var canceledCounter int32
			var wg sync.WaitGroup
			wg.Add(numStreams)
			for i := 0; i < numStreams; i++ {
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					str, err := conn.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					// only read some data from about 1/3 of the streams
					if rand.Int31()%3 != 0 {
						length := int(rand.Int31n(int32(len(PRData) - 1)))
						data, err := io.ReadAll(io.LimitReader(str, int64(length)))
						Expect(err).ToNot(HaveOccurred())
						str.CancelRead(quic.StreamErrorCode(str.StreamID()))
						Expect(data).To(Equal(PRData[:length]))
						atomic.AddInt32(&canceledCounter, 1)
						return
					}
					data, err := io.ReadAll(str)
					Expect(err).ToNot(HaveOccurred())
					Expect(data).To(Equal(PRData))
				}()
			}
			wg.Wait()

			var serverCanceledCounter int32
			Eventually(serverCanceledCounterChan).Should(Receive(&serverCanceledCounter))
			Expect(conn.CloseWithError(0, "")).To(Succeed())

			clientCanceledCounter := atomic.LoadInt32(&canceledCounter)
			// The server will only count a stream as being reset if learns about the cancelation before it finished writing all data.
			Expect(clientCanceledCounter).To(BeNumerically(">=", serverCanceledCounter))
			fmt.Fprintf(GinkgoWriter, "Canceled reading on %d of %d streams.\n", clientCanceledCounter, numStreams)
			Expect(clientCanceledCounter).To(BeNumerically(">", numStreams/10))
			Expect(numStreams - clientCanceledCounter).To(BeNumerically(">", numStreams/10))
		})

		It("allows concurrent Read and CancelRead calls", func() {
			// This test is especially valuable when run with race detector,
			// see https://github.com/quic-go/quic-go/issues/3239.
			serverCanceledCounterChan := runServer(make([]byte, 100)) // make sure the FIN is sent with the STREAM frame

			conn, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{MaxIncomingUniStreams: numStreams / 2}),
			)
			Expect(err).ToNot(HaveOccurred())

			var wg sync.WaitGroup
			wg.Add(numStreams)
			var counter int32
			for i := 0; i < numStreams; i++ {
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					str, err := conn.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())

					done := make(chan struct{})
					go func() {
						defer GinkgoRecover()
						defer close(done)
						b := make([]byte, 32)
						if _, err := str.Read(b); err != nil {
							atomic.AddInt32(&counter, 1)
							Expect(err).To(Equal(&quic.StreamError{
								StreamID:  str.StreamID(),
								ErrorCode: 1234,
								Remote:    false,
							}))
							return
						}
					}()
					go str.CancelRead(1234)
					Eventually(done).Should(BeClosed())
				}()
			}
			wg.Wait()
			Expect(conn.CloseWithError(0, "")).To(Succeed())
			numCanceled := atomic.LoadInt32(&counter)
			fmt.Fprintf(GinkgoWriter, "canceled %d out of %d streams", numCanceled, numStreams)
			Expect(numCanceled).ToNot(BeZero())
			Eventually(serverCanceledCounterChan).Should(Receive())
		})
	})

	Context("canceling the write side", func() {
		runClient := func(server quic.Listener) int32 /* number of canceled streams */ {
			conn, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{MaxIncomingUniStreams: numStreams / 2}),
			)
			Expect(err).ToNot(HaveOccurred())

			var wg sync.WaitGroup
			var counter int32
			wg.Add(numStreams)
			for i := 0; i < numStreams; i++ {
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					str, err := conn.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					data, err := io.ReadAll(str)
					if err != nil {
						atomic.AddInt32(&counter, 1)
						Expect(err).To(MatchError(&quic.StreamError{
							StreamID:  str.StreamID(),
							ErrorCode: quic.StreamErrorCode(str.StreamID()),
						}))
						return
					}
					Expect(data).To(Equal(PRData))
				}()
			}
			wg.Wait()

			streamCount := atomic.LoadInt32(&counter)
			fmt.Fprintf(GinkgoWriter, "Canceled writing on %d of %d streams\n", streamCount, numStreams)
			Expect(streamCount).To(BeNumerically(">", numStreams/10))
			Expect(numStreams - streamCount).To(BeNumerically(">", numStreams/10))
			Expect(conn.CloseWithError(0, "")).To(Succeed())
			Expect(server.Close()).To(Succeed())
			return streamCount
		}

		It("downloads when the server cancels some streams immediately", func() {
			server, err := quic.ListenAddr("localhost:0", getTLSConfig(), nil)
			Expect(err).ToNot(HaveOccurred())

			var canceledCounter int32
			go func() {
				defer GinkgoRecover()
				conn, err := server.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				for i := 0; i < numStreams; i++ {
					go func() {
						defer GinkgoRecover()
						str, err := conn.OpenUniStreamSync(context.Background())
						Expect(err).ToNot(HaveOccurred())
						// cancel about 2/3 of the streams
						if rand.Int31()%3 != 0 {
							str.CancelWrite(quic.StreamErrorCode(str.StreamID()))
							atomic.AddInt32(&canceledCounter, 1)
							return
						}
						_, err = str.Write(PRData)
						Expect(err).ToNot(HaveOccurred())
						Expect(str.Close()).To(Succeed())
					}()
				}
			}()

			clientCanceledStreams := runClient(server)
			Expect(clientCanceledStreams).To(Equal(atomic.LoadInt32(&canceledCounter)))
		})

		It("downloads when the server cancels some streams after sending some data", func() {
			server, err := quic.ListenAddr("localhost:0", getTLSConfig(), nil)
			Expect(err).ToNot(HaveOccurred())

			var canceledCounter int32
			go func() {
				defer GinkgoRecover()
				conn, err := server.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				for i := 0; i < numStreams; i++ {
					go func() {
						defer GinkgoRecover()
						str, err := conn.OpenUniStreamSync(context.Background())
						Expect(err).ToNot(HaveOccurred())
						// only write some data from about 1/3 of the streams, then cancel
						if rand.Int31()%3 != 0 {
							length := int(rand.Int31n(int32(len(PRData) - 1)))
							_, err = str.Write(PRData[:length])
							Expect(err).ToNot(HaveOccurred())
							str.CancelWrite(quic.StreamErrorCode(str.StreamID()))
							atomic.AddInt32(&canceledCounter, 1)
							return
						}
						_, err = str.Write(PRData)
						Expect(err).ToNot(HaveOccurred())
						Expect(str.Close()).To(Succeed())
					}()
				}
			}()

			clientCanceledStreams := runClient(server)
			Expect(clientCanceledStreams).To(Equal(atomic.LoadInt32(&canceledCounter)))
		})
	})

	Context("canceling both read and write side", func() {
		It("downloads data when both sides cancel streams immediately", func() {
			server, err := quic.ListenAddr("localhost:0", getTLSConfig(), nil)
			Expect(err).ToNot(HaveOccurred())

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				var wg sync.WaitGroup
				wg.Add(numStreams)
				conn, err := server.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				for i := 0; i < numStreams; i++ {
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						str, err := conn.OpenUniStreamSync(context.Background())
						Expect(err).ToNot(HaveOccurred())
						// cancel about half of the streams
						if rand.Int31()%2 == 0 {
							str.CancelWrite(quic.StreamErrorCode(str.StreamID()))
							return
						}
						if _, err = str.Write(PRData); err != nil {
							Expect(err).To(MatchError(&quic.StreamError{
								StreamID:  str.StreamID(),
								ErrorCode: quic.StreamErrorCode(str.StreamID()),
							}))
							return
						}
						if err := str.Close(); err != nil {
							Expect(err).To(MatchError(fmt.Sprintf("close called for canceled stream %d", str.StreamID())))
							return
						}
					}()
				}
				wg.Wait()
				close(done)
			}()

			conn, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{MaxIncomingUniStreams: numStreams / 2}),
			)
			Expect(err).ToNot(HaveOccurred())

			var wg sync.WaitGroup
			var counter int32
			wg.Add(numStreams)
			for i := 0; i < numStreams; i++ {
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					str, err := conn.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					// cancel around half of the streams
					if rand.Int31()%2 == 0 {
						str.CancelRead(quic.StreamErrorCode(str.StreamID()))
						return
					}
					data, err := io.ReadAll(str)
					if err != nil {
						Expect(err).To(MatchError(&quic.StreamError{
							StreamID:  str.StreamID(),
							ErrorCode: quic.StreamErrorCode(str.StreamID()),
						}))
						return
					}
					atomic.AddInt32(&counter, 1)
					Expect(data).To(Equal(PRData))
				}()
			}
			wg.Wait()

			count := atomic.LoadInt32(&counter)
			Expect(count).To(BeNumerically(">", numStreams/15))
			fmt.Fprintf(GinkgoWriter, "Successfully read from %d of %d streams.\n", count, numStreams)

			Expect(conn.CloseWithError(0, "")).To(Succeed())
			Eventually(done).Should(BeClosed())
			Expect(server.Close()).To(Succeed())
		})

		It("downloads data when both sides cancel streams after a while", func() {
			server, err := quic.ListenAddr("localhost:0", getTLSConfig(), nil)
			Expect(err).ToNot(HaveOccurred())

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				conn, err := server.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				var wg sync.WaitGroup
				wg.Add(numStreams)
				for i := 0; i < numStreams; i++ {
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						str, err := conn.OpenUniStreamSync(context.Background())
						Expect(err).ToNot(HaveOccurred())
						// cancel about half of the streams
						length := len(PRData)
						if rand.Int31()%2 == 0 {
							length = int(rand.Int31n(int32(len(PRData) - 1)))
						}
						if _, err = str.Write(PRData[:length]); err != nil {
							Expect(err).To(MatchError(&quic.StreamError{
								StreamID:  str.StreamID(),
								ErrorCode: quic.StreamErrorCode(str.StreamID()),
							}))
							return
						}
						if length < len(PRData) {
							str.CancelWrite(quic.StreamErrorCode(str.StreamID()))
						} else if err := str.Close(); err != nil {
							Expect(err).To(MatchError(fmt.Sprintf("close called for canceled stream %d", str.StreamID())))
							return
						}
					}()
				}
				wg.Wait()
			}()

			conn, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{MaxIncomingUniStreams: numStreams / 2}),
			)
			Expect(err).ToNot(HaveOccurred())

			var wg sync.WaitGroup
			var counter int32
			wg.Add(numStreams)
			for i := 0; i < numStreams; i++ {
				go func() {
					defer GinkgoRecover()
					defer wg.Done()

					str, err := conn.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())

					r := io.Reader(str)
					length := len(PRData)
					// cancel around half of the streams
					if rand.Int31()%2 == 0 {
						length = int(rand.Int31n(int32(len(PRData) - 1)))
						r = io.LimitReader(str, int64(length))
					}
					data, err := io.ReadAll(r)
					if err != nil {
						Expect(err).To(MatchError(&quic.StreamError{
							StreamID:  str.StreamID(),
							ErrorCode: quic.StreamErrorCode(str.StreamID()),
						}))
						return
					}
					Expect(data).To(Equal(PRData[:length]))
					if length < len(PRData) {
						str.CancelRead(quic.StreamErrorCode(str.StreamID()))
						return
					}

					atomic.AddInt32(&counter, 1)
					Expect(data).To(Equal(PRData))
				}()
			}
			wg.Wait()
			Eventually(done).Should(BeClosed())

			count := atomic.LoadInt32(&counter)
			Expect(count).To(BeNumerically(">", numStreams/15))
			fmt.Fprintf(GinkgoWriter, "Successfully read from %d of %d streams.\n", count, numStreams)

			Expect(conn.CloseWithError(0, "")).To(Succeed())
			Expect(server.Close()).To(Succeed())
		})
	})

	Context("canceling the context", func() {
		It("downloads data when the receiving peer cancels the context for accepting streams", func() {
			server, err := quic.ListenAddr("localhost:0", getTLSConfig(), getQuicConfig(nil))
			Expect(err).ToNot(HaveOccurred())

			go func() {
				defer GinkgoRecover()
				conn, err := server.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				ticker := time.NewTicker(5 * time.Millisecond)
				for i := 0; i < numStreams; i++ {
					<-ticker.C
					go func() {
						defer GinkgoRecover()
						str, err := conn.OpenUniStreamSync(context.Background())
						Expect(err).ToNot(HaveOccurred())
						_, err = str.Write(PRData)
						Expect(err).ToNot(HaveOccurred())
						Expect(str.Close()).To(Succeed())
					}()
				}
			}()

			conn, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{MaxIncomingUniStreams: numStreams / 3}),
			)
			Expect(err).ToNot(HaveOccurred())

			var numToAccept int
			var counter int32
			var wg sync.WaitGroup
			wg.Add(numStreams)
			for numToAccept < numStreams {
				ctx, cancel := context.WithCancel(context.Background())
				// cancel accepting half of the streams
				if rand.Int31()%2 == 0 {
					cancel()
				} else {
					numToAccept++
					defer cancel()
				}

				go func() {
					defer GinkgoRecover()
					str, err := conn.AcceptUniStream(ctx)
					if err != nil {
						if err.Error() == "context canceled" {
							atomic.AddInt32(&counter, 1)
						}
						return
					}
					data, err := io.ReadAll(str)
					Expect(err).ToNot(HaveOccurred())
					Expect(data).To(Equal(PRData))
					wg.Done()
				}()
			}
			wg.Wait()

			count := atomic.LoadInt32(&counter)
			fmt.Fprintf(GinkgoWriter, "Canceled AcceptStream %d times\n", count)
			Expect(count).To(BeNumerically(">", numStreams/2))
			Expect(conn.CloseWithError(0, "")).To(Succeed())
			Expect(server.Close()).To(Succeed())
		})

		It("downloads data when the sending peer cancels the context for opening streams", func() {
			const (
				numStreams         = 15
				maxIncomingStreams = 5
			)
			server, err := quic.ListenAddr("localhost:0", getTLSConfig(), getQuicConfig(nil))
			Expect(err).ToNot(HaveOccurred())

			msg := make(chan struct{}, 1)
			var numCanceled int32
			go func() {
				defer GinkgoRecover()
				defer close(msg)
				conn, err := server.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())

				var numOpened int
				for numOpened < numStreams {
					ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(20*time.Millisecond))
					defer cancel()
					str, err := conn.OpenUniStreamSync(ctx)
					if err != nil {
						Expect(err).To(MatchError(context.DeadlineExceeded))
						atomic.AddInt32(&numCanceled, 1)
						select {
						case msg <- struct{}{}:
						default:
						}
						continue
					}
					numOpened++
					go func(str quic.SendStream) {
						defer GinkgoRecover()
						_, err = str.Write(PRData)
						Expect(err).ToNot(HaveOccurred())
						Expect(str.Close()).To(Succeed())
					}(str)
				}
			}()

			conn, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{MaxIncomingUniStreams: maxIncomingStreams}),
			)
			Expect(err).ToNot(HaveOccurred())

			var wg sync.WaitGroup
			wg.Add(numStreams)
			for i := 0; i < numStreams; i++ {
				<-msg
				str, err := conn.AcceptUniStream(context.Background())
				Expect(err).ToNot(HaveOccurred())
				go func(str quic.ReceiveStream) {
					defer GinkgoRecover()
					data, err := io.ReadAll(str)
					Expect(err).ToNot(HaveOccurred())
					Expect(data).To(Equal(PRData))
					wg.Done()
				}(str)
			}
			wg.Wait()

			count := atomic.LoadInt32(&numCanceled)
			fmt.Fprintf(GinkgoWriter, "Canceled OpenStreamSync %d times\n", count)
			Expect(count).To(BeNumerically(">=", numStreams-maxIncomingStreams))
			Expect(conn.CloseWithError(0, "")).To(Succeed())
			Expect(server.Close()).To(Succeed())
		})
	})

	It("doesn't run into any errors when streams are canceled all the time", func() {
		const maxIncomingStreams = 1000
		server, err := quic.ListenAddr(
			"localhost:0",
			getTLSConfig(),
			getQuicConfig(&quic.Config{MaxIncomingStreams: maxIncomingStreams, MaxIdleTimeout: 10 * time.Second}),
		)
		Expect(err).ToNot(HaveOccurred())

		var wg sync.WaitGroup
		wg.Add(2 * 4 * maxIncomingStreams)
		handleStream := func(str quic.Stream) {
			str.SetDeadline(time.Now().Add(time.Second))
			go func() {
				defer wg.Done()
				if rand.Int31()%2 == 0 {
					defer GinkgoRecover()
					io.ReadAll(str)
				}
			}()
			go func() {
				defer wg.Done()
				if rand.Int31()%2 == 0 {
					str.Write([]byte("foobar"))
					if rand.Int31()%2 == 0 {
						str.Close()
					}
				}
			}()
			go func() {
				defer wg.Done()
				// Make sure we at least send out *something* for the last stream,
				// otherwise the peer might never receive this anything for this stream.
				if rand.Int31()%2 == 0 || str.StreamID() == 4*(maxIncomingStreams-1) {
					str.CancelWrite(1234)
				}
			}()
			go func() {
				defer wg.Done()
				if rand.Int31()%2 == 0 {
					str.CancelRead(1234)
				}
			}()
		}

		serverRunning := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(serverRunning)
			conn, err := server.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			for {
				str, err := conn.AcceptStream(context.Background())
				if err != nil {
					// Make sure the connection is closed regularly.
					Expect(err).To(BeAssignableToTypeOf(&quic.ApplicationError{}))
					return
				}
				handleStream(str)
			}
		}()

		conn, err := quic.DialAddr(
			fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{}),
		)
		Expect(err).ToNot(HaveOccurred())

		for i := 0; i < maxIncomingStreams; i++ {
			str, err := conn.OpenStreamSync(context.Background())
			Expect(err).ToNot(HaveOccurred())
			handleStream(str)
		}

		// We don't expect to accept any stream here.
		// We're just making sure the connection stays open and there's no error.
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		_, err = conn.AcceptStream(ctx)
		Expect(err).To(MatchError(context.DeadlineExceeded))

		wg.Wait()

		Expect(conn.CloseWithError(0, "")).To(Succeed())
		Eventually(serverRunning).Should(BeClosed())
	})
})
