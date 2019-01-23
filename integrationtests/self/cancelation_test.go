package self_test

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/integrationtests/tools/testserver"
	"github.com/lucas-clemente/quic-go/internal/testdata"

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
			server, err = quic.ListenAddr("localhost:0", testdata.GetTLSConfig(), nil)
			Expect(err).ToNot(HaveOccurred())

			var canceledCounter int32
			go func() {
				defer GinkgoRecover()
				var wg sync.WaitGroup
				wg.Add(numStreams)
				sess, err := server.Accept()
				Expect(err).ToNot(HaveOccurred())
				for i := 0; i < numStreams; i++ {
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						str, err := sess.OpenUniStreamSync()
						Expect(err).ToNot(HaveOccurred())
						if _, err = str.Write(testserver.PRData); err != nil {
							Expect(err).To(MatchError(fmt.Sprintf("Stream %d was reset with error code %d", str.StreamID(), str.StreamID())))
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
				&tls.Config{RootCAs: testdata.GetRootCA()},
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
					str, err := sess.AcceptUniStream()
					Expect(err).ToNot(HaveOccurred())
					// cancel around 2/3 of the streams
					if rand.Int31()%3 != 0 {
						atomic.AddInt32(&canceledCounter, 1)
						Expect(str.CancelRead(quic.ErrorCode(str.StreamID()))).To(Succeed())
						return
					}
					data, err := ioutil.ReadAll(str)
					Expect(err).ToNot(HaveOccurred())
					Expect(data).To(Equal(testserver.PRData))
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
				&tls.Config{RootCAs: testdata.GetRootCA()},
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
					str, err := sess.AcceptUniStream()
					Expect(err).ToNot(HaveOccurred())
					// only read some data from about 1/3 of the streams
					if rand.Int31()%3 != 0 {
						length := int(rand.Int31n(int32(len(testserver.PRData) - 1)))
						data, err := ioutil.ReadAll(io.LimitReader(str, int64(length)))
						Expect(err).ToNot(HaveOccurred())
						Expect(str.CancelRead(quic.ErrorCode(str.StreamID()))).To(Succeed())
						Expect(data).To(Equal(testserver.PRData[:length]))
						atomic.AddInt32(&canceledCounter, 1)
						return
					}
					data, err := ioutil.ReadAll(str)
					Expect(err).ToNot(HaveOccurred())
					Expect(data).To(Equal(testserver.PRData))
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
				&tls.Config{RootCAs: testdata.GetRootCA()},
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
					str, err := sess.AcceptUniStream()
					Expect(err).ToNot(HaveOccurred())
					data, err := ioutil.ReadAll(str)
					if err != nil {
						atomic.AddInt32(&counter, 1)
						Expect(err).To(MatchError(fmt.Sprintf("Stream %d was reset with error code %d", str.StreamID(), str.StreamID())))
						return
					}
					Expect(data).To(Equal(testserver.PRData))
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
			server, err := quic.ListenAddr("localhost:0", testdata.GetTLSConfig(), nil)
			Expect(err).ToNot(HaveOccurred())

			var canceledCounter int32
			go func() {
				defer GinkgoRecover()
				sess, err := server.Accept()
				Expect(err).ToNot(HaveOccurred())
				for i := 0; i < numStreams; i++ {
					go func() {
						defer GinkgoRecover()
						str, err := sess.OpenUniStreamSync()
						Expect(err).ToNot(HaveOccurred())
						// cancel about 2/3 of the streams
						if rand.Int31()%3 != 0 {
							Expect(str.CancelWrite(quic.ErrorCode(str.StreamID()))).To(Succeed())
							atomic.AddInt32(&canceledCounter, 1)
							return
						}
						_, err = str.Write(testserver.PRData)
						Expect(err).ToNot(HaveOccurred())
						Expect(str.Close()).To(Succeed())
					}()
				}
			}()

			clientCanceledStreams := runClient(server)
			Expect(clientCanceledStreams).To(Equal(atomic.LoadInt32(&canceledCounter)))
		})

		It("downloads when the server cancels some streams after sending some data", func() {
			server, err := quic.ListenAddr("localhost:0", testdata.GetTLSConfig(), nil)
			Expect(err).ToNot(HaveOccurred())

			var canceledCounter int32
			go func() {
				defer GinkgoRecover()
				sess, err := server.Accept()
				Expect(err).ToNot(HaveOccurred())
				for i := 0; i < numStreams; i++ {
					go func() {
						defer GinkgoRecover()
						str, err := sess.OpenUniStreamSync()
						Expect(err).ToNot(HaveOccurred())
						// only write some data from about 1/3 of the streams, then cancel
						if rand.Int31()%3 != 0 {
							length := int(rand.Int31n(int32(len(testserver.PRData) - 1)))
							_, err = str.Write(testserver.PRData[:length])
							Expect(err).ToNot(HaveOccurred())
							Expect(str.CancelWrite(quic.ErrorCode(str.StreamID()))).To(Succeed())
							atomic.AddInt32(&canceledCounter, 1)
							return
						}
						_, err = str.Write(testserver.PRData)
						Expect(err).ToNot(HaveOccurred())
						Expect(str.Close()).To(Succeed())
					}()
				}
			}()

			clientCanceledStreams := runClient(server)
			Expect(clientCanceledStreams).To(Equal(atomic.LoadInt32(&canceledCounter)))
		})
	})
})
