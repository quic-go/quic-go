package integrationtests

import (
	"net"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type packetData []byte

var _ = Describe("Integrationtests", func() {
	It("sets up the UDPProxy", func() {
		proxy, err := NewUDPProxy(13370, "localhost", 7331)
		Expect(err).ToNot(HaveOccurred())

		// check that port 13370 is in use
		addr, err := net.ResolveUDPAddr("udp", ":13370")
		Expect(err).ToNot(HaveOccurred())
		_, err = net.ListenUDP("udp", addr)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError("listen udp :13370: bind: address already in use"))

		proxy.Stop() // stopping is tested in the next test
	})

	It("stops the UDPProxy", func() {
		proxy, err := NewUDPProxy(13370, "localhost", 7331)
		Expect(err).ToNot(HaveOccurred())
		proxy.Stop()

		// check that port 13370 is not in use anymore
		addr, err := net.ResolveUDPAddr("udp", ":13370")
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
			serverAddr, err := net.ResolveUDPAddr("udp", ":7331")
			Expect(err).ToNot(HaveOccurred())
			serverConn, err = net.ListenUDP("udp", serverAddr)
			Expect(err).ToNot(HaveOccurred())

			// setup the proxy
			proxy, err = NewUDPProxy(10001, "localhost", 7331)
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

		It("relays packets from the client to the server", func() {
			_, err := clientConn.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())
			time.Sleep(time.Millisecond)
			_, err = clientConn.Write([]byte("decafbad"))
			Expect(err).ToNot(HaveOccurred())
			time.Sleep(time.Millisecond)
			Expect(serverReceivedPackets).To(HaveLen(2))
			Expect(serverReceivedPackets[0]).To(Equal(packetData("foobar")))
			Expect(serverReceivedPackets[1]).To(Equal(packetData("decafbad")))
		})

		It("relays packets from the server to the client", func() {
			_, err := clientConn.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())
			time.Sleep(time.Millisecond)
			_, err = clientConn.Write([]byte("decafbad"))
			Expect(err).ToNot(HaveOccurred())
			time.Sleep(time.Millisecond)

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
})
