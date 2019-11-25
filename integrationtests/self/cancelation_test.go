package self_test

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/lucas-clemente/quic-go"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stream Cancelations", func() {
	const numStreams = 80

	Context("canceling the read side", func() {
		var server quic.Listener

		runServer := func() <-chan int32 {
			numCanceledStreamsChan := make(chan int32)
			var err error
			server, err = quic.ListenAddr("localhost:0", getTLSConfig(), nil)
			Expect(err).ToNot(HaveOccurred())

			var canceledCounter int32
			go func() {
				defer GinkgoRecover()
				var wg sync.WaitGroup
				wg.Add(numStreams)
				sess, err := server.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				for i := 0; i < numStreams; i++ {
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						str, err := sess.OpenUniStreamSync(context.Background())
						Expect(err).ToNot(HaveOccurred())
						if _, err = str.Write(PRData); err != nil {
							Expect(err).To(MatchError(fmt.Sprintf("stream %d was reset with error code %d", str.StreamID(), str.StreamID())))
							atomic.AddInt32(&canceledCounter, 1)
							return
						}
						Expect(str.Close()).To(Succeed())
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
			serverCanceledCounterChan := runServer()
			sess, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				&quic.Config{MaxIncomingUniStreams: numStreams / 2},
			)
			Expect(err).ToNot(HaveOccurred())

			var canceledCounter int32
			var wg sync.WaitGroup
			wg.Add(numStreams)
			for i := 0; i < numStreams; i++ {
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					str, err := sess.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					// cancel around 2/3 of the streams
					if rand.Int31()%3 != 0 {
						atomic.AddInt32(&canceledCounter, 1)
						str.CancelRead(quic.ErrorCode(str.StreamID()))
						return
					}
					data, err := ioutil.ReadAll(str)
					Expect(err).ToNot(HaveOccurred())
					Expect(data).To(Equal(PRData))
				}()
			}
			wg.Wait()

			var serverCanceledCounter int32
			Eventually(serverCanceledCounterChan).Should(Receive(&serverCanceledCounter))
			Expect(sess.Close()).To(Succeed())

			clientCanceledCounter := atomic.LoadInt32(&canceledCounter)
			// The server will only count a stream as being reset if learns about the cancelation before it finished writing all data.
			Expect(clientCanceledCounter).To(BeNumerically(">=", serverCanceledCounter))
			fmt.Fprintf(GinkgoWriter, "Canceled reading on %d of %d streams.\n", clientCanceledCounter, numStreams)
			Expect(clientCanceledCounter).To(BeNumerically(">", numStreams/10))
			Expect(numStreams - clientCanceledCounter).To(BeNumerically(">", numStreams/10))
		})

		It("downloads when the client cancels streams after reading from them for a bit", func() {
			serverCanceledCounterChan := runServer()

			sess, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				&quic.Config{MaxIncomingUniStreams: numStreams / 2},
			)
			Expect(err).ToNot(HaveOccurred())

			var canceledCounter int32
			var wg sync.WaitGroup
			wg.Add(numStreams)
			for i := 0; i < numStreams; i++ {
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					str, err := sess.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					// only read some data from about 1/3 of the streams
					if rand.Int31()%3 != 0 {
						length := int(rand.Int31n(int32(len(PRData) - 1)))
						data, err := ioutil.ReadAll(io.LimitReader(str, int64(length)))
						Expect(err).ToNot(HaveOccurred())
						str.CancelRead(quic.ErrorCode(str.StreamID()))
						Expect(data).To(Equal(PRData[:length]))
						atomic.AddInt32(&canceledCounter, 1)
						return
					}
					data, err := ioutil.ReadAll(str)
					Expect(err).ToNot(HaveOccurred())
					Expect(data).To(Equal(PRData))
				}()
			}
			wg.Wait()

			var serverCanceledCounter int32
			Eventually(serverCanceledCounterChan).Should(Receive(&serverCanceledCounter))
			Expect(sess.Close()).To(Succeed())

			clientCanceledCounter := atomic.LoadInt32(&canceledCounter)
			// The server will only count a stream as being reset if learns about the cancelation before it finished writing all data.
			Expect(clientCanceledCounter).To(BeNumerically(">=", serverCanceledCounter))
			fmt.Fprintf(GinkgoWriter, "Canceled reading on %d of %d streams.\n", clientCanceledCounter, numStreams)
			Expect(clientCanceledCounter).To(BeNumerically(">", numStreams/10))
			Expect(numStreams - clientCanceledCounter).To(BeNumerically(">", numStreams/10))
		})
	})

	Context("canceling the write side", func() {
		runClient := func(server quic.Listener) int32 /* number of canceled streams */ {
			sess, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				&quic.Config{MaxIncomingUniStreams: numStreams / 2},
			)
			Expect(err).ToNot(HaveOccurred())

			var wg sync.WaitGroup
			var counter int32
			wg.Add(numStreams)
			for i := 0; i < numStreams; i++ {
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					str, err := sess.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					data, err := ioutil.ReadAll(str)
					if err != nil {
						atomic.AddInt32(&counter, 1)
						Expect(err).To(MatchError(fmt.Sprintf("stream %d was reset with error code %d", str.StreamID(), str.StreamID())))
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
			Expect(sess.Close()).To(Succeed())
			Expect(server.Close()).To(Succeed())
			return streamCount
		}

		It("downloads when the server cancels some streams immediately", func() {
			server, err := quic.ListenAddr("localhost:0", getTLSConfig(), nil)
			Expect(err).ToNot(HaveOccurred())

			var canceledCounter int32
			go func() {
				defer GinkgoRecover()
				sess, err := server.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				for i := 0; i < numStreams; i++ {
					go func() {
						defer GinkgoRecover()
						str, err := sess.OpenUniStreamSync(context.Background())
						Expect(err).ToNot(HaveOccurred())
						// cancel about 2/3 of the streams
						if rand.Int31()%3 != 0 {
							str.CancelWrite(quic.ErrorCode(str.StreamID()))
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
				sess, err := server.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				for i := 0; i < numStreams; i++ {
					go func() {
						defer GinkgoRecover()
						str, err := sess.OpenUniStreamSync(context.Background())
						Expect(err).ToNot(HaveOccurred())
						// only write some data from about 1/3 of the streams, then cancel
						if rand.Int31()%3 != 0 {
							length := int(rand.Int31n(int32(len(PRData) - 1)))
							_, err = str.Write(PRData[:length])
							Expect(err).ToNot(HaveOccurred())
							str.CancelWrite(quic.ErrorCode(str.StreamID()))
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
				sess, err := server.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				for i := 0; i < numStreams; i++ {
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						str, err := sess.OpenUniStreamSync(context.Background())
						Expect(err).ToNot(HaveOccurred())
						// cancel about half of the streams
						if rand.Int31()%2 == 0 {
							str.CancelWrite(quic.ErrorCode(str.StreamID()))
							return
						}
						if _, err = str.Write(PRData); err != nil {
							Expect(err).To(MatchError(fmt.Sprintf("stream %d was reset with error code %d", str.StreamID(), str.StreamID())))
							return
						}
						Expect(str.Close()).To(Succeed())
					}()
				}
				wg.Wait()
				close(done)
			}()

			sess, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				&quic.Config{MaxIncomingUniStreams: numStreams / 2},
			)
			Expect(err).ToNot(HaveOccurred())

			var wg sync.WaitGroup
			var counter int32
			wg.Add(numStreams)
			for i := 0; i < numStreams; i++ {
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					str, err := sess.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					// cancel around half of the streams
					if rand.Int31()%2 == 0 {
						str.CancelRead(quic.ErrorCode(str.StreamID()))
						return
					}
					data, err := ioutil.ReadAll(str)
					if err != nil {
						Expect(err).To(MatchError(fmt.Sprintf("stream %d was reset with error code %d", str.StreamID(), str.StreamID())))
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

			Expect(sess.Close()).To(Succeed())
			Eventually(done).Should(BeClosed())
			Expect(server.Close()).To(Succeed())
		})

		It("downloads data when both sides cancel streams after a while", func() {
			server, err := quic.ListenAddr("localhost:0", getTLSConfig(), nil)
			Expect(err).ToNot(HaveOccurred())

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				var wg sync.WaitGroup
				wg.Add(numStreams)
				sess, err := server.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				for i := 0; i < numStreams; i++ {
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						str, err := sess.OpenUniStreamSync(context.Background())
						Expect(err).ToNot(HaveOccurred())
						// cancel about half of the streams
						length := len(PRData)
						if rand.Int31()%2 == 0 {
							length = int(rand.Int31n(int32(len(PRData) - 1)))
						}
						if _, err = str.Write(PRData[:length]); err != nil {
							Expect(err).To(MatchError(fmt.Sprintf("stream %d was reset with error code %d", str.StreamID(), str.StreamID())))
							return
						}
						if length < len(PRData) {
							str.CancelWrite(quic.ErrorCode(str.StreamID()))
						} else {
							Expect(str.Close()).To(Succeed())
						}
					}()
				}
				wg.Wait()
				close(done)
			}()

			sess, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				&quic.Config{MaxIncomingUniStreams: numStreams / 2},
			)
			Expect(err).ToNot(HaveOccurred())

			var wg sync.WaitGroup
			var counter int32
			wg.Add(numStreams)
			for i := 0; i < numStreams; i++ {
				go func() {
					defer GinkgoRecover()
					defer wg.Done()

					str, err := sess.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())

					r := io.Reader(str)
					length := len(PRData)
					// cancel around half of the streams
					if rand.Int31()%2 == 0 {
						length = int(rand.Int31n(int32(len(PRData) - 1)))
						r = io.LimitReader(str, int64(length))
					}
					data, err := ioutil.ReadAll(r)
					if err != nil {
						Expect(err).To(MatchError(fmt.Sprintf("stream %d was reset with error code %d", str.StreamID(), str.StreamID())))
						return
					}
					Expect(data).To(Equal(PRData[:length]))
					if length < len(PRData) {
						str.CancelRead(quic.ErrorCode(str.StreamID()))
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

			Expect(sess.Close()).To(Succeed())
			Eventually(done).Should(BeClosed())
			Expect(server.Close()).To(Succeed())
		})
	})

	Context("canceling the context", func() {
		It("downloads data when the receiving peer cancels the context for accepting streams", func() {
			server, err := quic.ListenAddr("localhost:0", getTLSConfig(), nil)
			Expect(err).ToNot(HaveOccurred())

			go func() {
				defer GinkgoRecover()
				sess, err := server.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				ticker := time.NewTicker(5 * time.Millisecond)
				for i := 0; i < numStreams; i++ {
					<-ticker.C
					go func() {
						defer GinkgoRecover()
						str, err := sess.OpenUniStreamSync(context.Background())
						Expect(err).ToNot(HaveOccurred())
						_, err = str.Write(PRData)
						Expect(err).ToNot(HaveOccurred())
						Expect(str.Close()).To(Succeed())
					}()
				}
			}()

			sess, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				&quic.Config{MaxIncomingUniStreams: numStreams / 3},
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
					str, err := sess.AcceptUniStream(ctx)
					if err != nil {
						if err.Error() == "context canceled" {
							atomic.AddInt32(&counter, 1)
						}
						return
					}
					data, err := ioutil.ReadAll(str)
					Expect(err).ToNot(HaveOccurred())
					Expect(data).To(Equal(PRData))
					wg.Done()
				}()
			}
			wg.Wait()

			count := atomic.LoadInt32(&counter)
			fmt.Fprintf(GinkgoWriter, "Canceled AcceptStream %d times\n", count)
			Expect(count).To(BeNumerically(">", numStreams/2))
			Expect(sess.Close()).To(Succeed())
			Expect(server.Close()).To(Succeed())
		})

		It("downloads data when the sending peer cancels the context for opening streams", func() {
			server, err := quic.ListenAddr("localhost:0", getTLSConfig(), nil)
			Expect(err).ToNot(HaveOccurred())

			var numCanceled int32
			go func() {
				defer GinkgoRecover()
				sess, err := server.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())

				var numOpened int
				ticker := time.NewTicker(250 * time.Microsecond)
				for numOpened < numStreams {
					<-ticker.C
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					// cancel accepting half of the streams
					shouldCancel := rand.Int31()%2 == 0

					if shouldCancel {
						time.AfterFunc(5*time.Millisecond, cancel)
					}
					str, err := sess.OpenUniStreamSync(ctx)
					if err != nil {
						atomic.AddInt32(&numCanceled, 1)
						Expect(err).To(MatchError("context canceled"))
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

			sess, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				&quic.Config{
					MaxIncomingUniStreams: 5,
				},
			)
			Expect(err).ToNot(HaveOccurred())

			var wg sync.WaitGroup
			wg.Add(numStreams)
			ticker := time.NewTicker(10 * time.Millisecond)
			for i := 0; i < numStreams; i++ {
				<-ticker.C
				go func() {
					defer GinkgoRecover()
					str, err := sess.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					data, err := ioutil.ReadAll(str)
					Expect(err).ToNot(HaveOccurred())
					Expect(data).To(Equal(PRData))
					wg.Done()
				}()
			}
			wg.Wait()

			count := atomic.LoadInt32(&numCanceled)
			fmt.Fprintf(GinkgoWriter, "Canceled OpenStreamSync %d times\n", count)
			Expect(count).To(BeNumerically(">", numStreams/5))
			Expect(sess.Close()).To(Succeed())
			Expect(server.Close()).To(Succeed())
		})
	})
})
