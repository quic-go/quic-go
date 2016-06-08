package integrationtests

import (
	"net"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type packetData []byte

var _ = Describe("Integrationtests", func() {
	var serverPort int

	BeforeEach(func() {
		serverPort = 7331
	})

	It("sets up the UDPProxy", func() {
		proxy, err := NewUDPProxy(13370, "localhost", serverPort, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(proxy.clientDict).To(HaveLen(0))

		// check that port 13370 is in use
		addr, err := net.ResolveUDPAddr("udp", ":13370")
		Expect(err).ToNot(HaveOccurred())
		_, err = net.ListenUDP("udp", addr)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError("listen udp :13370: bind: address already in use"))

		proxy.Stop() // stopping is tested in the next test
	})

	It("stops the UDPProxy", func() {
		proxy, err := NewUDPProxy(13371, "localhost", serverPort, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		proxy.Stop()

		// check that port 13370 is not in use anymore
		addr, err := net.ResolveUDPAddr("udp", ":13371")
		Expect(err).ToNot(HaveOccurred())
		ln, err := net.ListenUDP("udp", addr)
		Expect(err).ToNot(HaveOccurred())
		ln.Close()
	})

	Context("Proxy tests", func() {
		var serverConn *net.UDPConn
		var serverReceivedPackets []packetData
		var serverNumPacketsSent int
		var clientConn *net.UDPConn
		var proxy *UDPProxy

		BeforeEach(func() {
			var err error
			serverReceivedPackets = serverReceivedPackets[:0]
			serverNumPacketsSent = 0

			// setup a UDP server on port 7331
			serverAddr, err := net.ResolveUDPAddr("udp", ":"+strconv.Itoa(serverPort))
			Expect(err).ToNot(HaveOccurred())
			serverConn, err = net.ListenUDP("udp", serverAddr)
			Expect(err).ToNot(HaveOccurred())

			proxyAddr, err := net.ResolveUDPAddr("udp", ":10001")
			Expect(err).ToNot(HaveOccurred())

			go func() {
				defer GinkgoRecover()

				for {
					buf := make([]byte, 1500)
					n, addr, err2 := serverConn.ReadFromUDP(buf)
					if err2 != nil {
						return
					}
					data := buf[0:n]
					serverReceivedPackets = append(serverReceivedPackets, packetData(data))

					// echo each packet received back to the client
					serverConn.WriteToUDP(data, addr)
					serverNumPacketsSent++
				}
			}()

			// setup the client
			localAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
			Expect(err).ToNot(HaveOccurred())
			clientConn, err = net.DialUDP("udp", localAddr, proxyAddr)
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			proxy.Stop()
			serverConn.Close()
			time.Sleep(time.Millisecond)
		})

		Context("no packet drop", func() {
			BeforeEach(func() {
				// setup the proxy
				var err error
				proxy, err = NewUDPProxy(10001, "localhost", serverPort, nil, nil)
				Expect(err).ToNot(HaveOccurred())
			})

			It("relays packets from the client to the server", func() {
				_, err := clientConn.Write([]byte("foobar"))
				Expect(err).ToNot(HaveOccurred())
				time.Sleep(time.Millisecond)
				Expect(proxy.clientDict).To(HaveLen(1))
				var key string
				var conn *connection
				for key, conn = range proxy.clientDict {
					Expect(conn.incomingPacketCounter).To(Equal(PacketNumber(1)))
				}
				_, err = clientConn.Write([]byte("decafbad"))
				Expect(err).ToNot(HaveOccurred())
				time.Sleep(time.Millisecond)
				Expect(proxy.clientDict).To(HaveLen(1))
				Expect(proxy.clientDict[key].incomingPacketCounter).To(Equal(PacketNumber(2)))
				Expect(serverReceivedPackets).To(HaveLen(2))
				Expect(serverReceivedPackets[0]).To(Equal(packetData("foobar")))
				Expect(serverReceivedPackets[1]).To(Equal(packetData("decafbad")))
			})

			It("relays packets from the server to the client", func() {
				_, err := clientConn.Write([]byte("foobar"))
				Expect(err).ToNot(HaveOccurred())
				time.Sleep(time.Millisecond)
				Expect(proxy.clientDict).To(HaveLen(1))
				var key string
				var conn *connection
				for key, conn = range proxy.clientDict {
					Expect(conn.outgoingPacketCounter).To(Equal(PacketNumber(1)))
				}
				_, err = clientConn.Write([]byte("decafbad"))
				Expect(err).ToNot(HaveOccurred())
				time.Sleep(time.Millisecond)
				Expect(proxy.clientDict).To(HaveLen(1))
				Expect(proxy.clientDict[key].outgoingPacketCounter).To(Equal(PacketNumber(2)))

				var clientReceivedPackets []packetData

				// receive the packets echoed by the server on client side
				go func() {
					defer GinkgoRecover()

					for {
						buf := make([]byte, 1500)
						n, _, err2 := clientConn.ReadFromUDP(buf)
						if err2 != nil {
							return
						}
						data := buf[0:n]
						clientReceivedPackets = append(clientReceivedPackets, packetData(data))
					}
				}()

				time.Sleep(time.Millisecond)
				Expect(serverReceivedPackets).To(HaveLen(2))
				Expect(serverNumPacketsSent).To(Equal(2))
				Expect(clientReceivedPackets).To(HaveLen(2))
				Expect(clientReceivedPackets[0]).To(Equal(packetData("foobar")))
				Expect(clientReceivedPackets[1]).To(Equal(packetData("decafbad")))
			})
		})

		Context("Drop Callbacks", func() {
			It("drops incoming packets", func() {
				dropper := func(p PacketNumber) bool {
					return p%2 == 0
				}

				var err error
				proxy, err = NewUDPProxy(10001, "localhost", serverPort, dropper, nil)
				Expect(err).ToNot(HaveOccurred())

				for i := 1; i <= 6; i++ {
					_, err := clientConn.Write([]byte("foobar" + strconv.Itoa(i)))
					Expect(err).ToNot(HaveOccurred())
					time.Sleep(time.Millisecond)
				}
				Expect(serverReceivedPackets).To(HaveLen(3))
				Expect(serverReceivedPackets[0]).To(Equal(packetData("foobar1")))
				Expect(serverReceivedPackets[1]).To(Equal(packetData("foobar3")))
				Expect(serverReceivedPackets[2]).To(Equal(packetData("foobar5")))
			})

			It("drops outgoing packets", func() {
				dropper := func(p PacketNumber) bool {
					return p%2 == 0
				}

				var err error
				proxy, err = NewUDPProxy(10001, "localhost", serverPort, nil, dropper)
				Expect(err).ToNot(HaveOccurred())

				for i := 1; i <= 6; i++ {
					_, err := clientConn.Write([]byte("foobar" + strconv.Itoa(i)))
					Expect(err).ToNot(HaveOccurred())
					time.Sleep(time.Millisecond)
				}

				var clientReceivedPackets []packetData

				// receive the packets echoed by the server on client side
				go func() {
					defer GinkgoRecover()

					for {
						buf := make([]byte, 1500)
						n, _, err2 := clientConn.ReadFromUDP(buf)
						if err2 != nil {
							return
						}
						data := buf[0:n]
						clientReceivedPackets = append(clientReceivedPackets, packetData(data))
					}
				}()

				time.Sleep(time.Millisecond)
				Expect(clientReceivedPackets).To(HaveLen(3))
				Expect(clientReceivedPackets[0]).To(Equal(packetData("foobar1")))
				Expect(clientReceivedPackets[1]).To(Equal(packetData("foobar3")))
				Expect(clientReceivedPackets[2]).To(Equal(packetData("foobar5")))
			})
		})
	})
})
