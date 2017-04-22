package quicproxy

import (
	"bytes"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type packetData []byte

var _ = Describe("QUIC Proxy", func() {
	var serverAddr string

	makePacket := func(p protocol.PacketNumber, payload []byte) []byte {
		b := &bytes.Buffer{}
		hdr := quic.PublicHeader{
			PacketNumber:         p,
			PacketNumberLen:      protocol.PacketNumberLen6,
			ConnectionID:         1337,
			TruncateConnectionID: false,
		}
		hdr.Write(b, protocol.VersionWhatever, protocol.PerspectiveServer)
		raw := b.Bytes()
		raw = append(raw, payload...)
		return raw
	}

	BeforeEach(func() {
		serverAddr = "localhost:7331"
	})

	Context("Proxy setup and teardown", func() {
		It("sets up the UDPProxy", func() {
			proxy, err := NewQuicProxy("localhost:13370", Opts{RemoteAddr: serverAddr})
			Expect(err).ToNot(HaveOccurred())
			Expect(proxy.clientDict).To(HaveLen(0))

			// check that port 13370 is in use
			addr, err := net.ResolveUDPAddr("udp", "localhost:13370")
			Expect(err).ToNot(HaveOccurred())
			_, err = net.ListenUDP("udp", addr)
			Expect(err).To(MatchError("listen udp 127.0.0.1:13370: bind: address already in use"))

			err = proxy.Close() // stopping is tested in the next test
			Expect(err).ToNot(HaveOccurred())
		})

		It("stops the UDPProxy", func() {
			proxy, err := NewQuicProxy("localhost:13371", Opts{RemoteAddr: serverAddr})
			Expect(err).ToNot(HaveOccurred())
			err = proxy.Close()
			Expect(err).ToNot(HaveOccurred())

			// check that port 13371 is not in use anymore
			addr, err := net.ResolveUDPAddr("udp", "localhost:13371")
			Expect(err).ToNot(HaveOccurred())
			ln, err := net.ListenUDP("udp", addr)
			Expect(err).ToNot(HaveOccurred())
			err = ln.Close()
			Expect(err).ToNot(HaveOccurred())
		})

		It("has the correct LocalAddr and LocalPort", func() {
			proxy, err := NewQuicProxy("localhost:13372", Opts{RemoteAddr: serverAddr})
			Expect(err).ToNot(HaveOccurred())

			Expect(proxy.LocalAddr().String()).To(Equal("127.0.0.1:13372"))
			Expect(proxy.LocalPort()).To(Equal(13372))

			err = proxy.Close()
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Context("Proxy tests", func() {
		var (
			serverConn            *net.UDPConn
			serverReceivedPackets []packetData
			serverNumPacketsSent  int
			clientConn            *net.UDPConn
			proxy                 *QuicProxy
		)

		// start the proxy on port 10001
		startProxy := func(opts Opts) {
			var err error
			proxy, err = NewQuicProxy("localhost:10001", opts)
			Expect(err).ToNot(HaveOccurred())
			clientConn, err = net.DialUDP("udp", nil, proxy.LocalAddr().(*net.UDPAddr))
			Expect(err).ToNot(HaveOccurred())
		}

		BeforeEach(func() {
			serverReceivedPackets = serverReceivedPackets[:0]
			serverNumPacketsSent = 0

			// setup a dump UDP server on port 7331
			// in production this would be a QUIC server
			raddr, err := net.ResolveUDPAddr("udp", serverAddr)
			Expect(err).ToNot(HaveOccurred())
			serverConn, err = net.ListenUDP("udp", raddr)
			Expect(err).ToNot(HaveOccurred())

			go func() {
				for {
					buf := make([]byte, protocol.MaxPacketSize)
					// the ReadFromUDP will error as soon as the UDP conn is closed
					n, addr, err2 := serverConn.ReadFromUDP(buf)
					if err2 != nil {
						return
					}
					data := buf[0:n]
					serverReceivedPackets = append(serverReceivedPackets, packetData(data))
					// echo the packet
					serverConn.WriteToUDP(data, addr)
					serverNumPacketsSent++
				}
			}()
		})

		AfterEach(func() {
			err := proxy.Close()
			Expect(err).ToNot(HaveOccurred())
			err = serverConn.Close()
			Expect(err).ToNot(HaveOccurred())
			err = clientConn.Close()
			Expect(err).ToNot(HaveOccurred())
			time.Sleep(200 * time.Millisecond)
		})

		Context("no packet drop", func() {
			It("relays packets from the client to the server", func() {
				startProxy(Opts{RemoteAddr: serverAddr})
				// send the first packet
				_, err := clientConn.Write(makePacket(1, []byte("foobar")))
				Expect(err).ToNot(HaveOccurred())

				Eventually(func() map[string]*connection { return proxy.clientDict }).Should(HaveLen(1))
				var conn *connection
				for _, conn = range proxy.clientDict {
					Expect(atomic.LoadUint64(&conn.incomingPacketCounter)).To(Equal(uint64(1)))
				}

				// send the second packet
				_, err = clientConn.Write(makePacket(2, []byte("decafbad")))
				Expect(err).ToNot(HaveOccurred())

				Eventually(func() []packetData { return serverReceivedPackets }).Should(HaveLen(2))
				Expect(proxy.clientDict).To(HaveLen(1))
				Expect(string(serverReceivedPackets[0])).To(ContainSubstring("foobar"))
				Expect(string(serverReceivedPackets[1])).To(ContainSubstring("decafbad"))
			})

			It("relays packets from the server to the client", func() {
				startProxy(Opts{RemoteAddr: serverAddr})
				// send the first packet
				_, err := clientConn.Write(makePacket(1, []byte("foobar")))
				Expect(err).ToNot(HaveOccurred())

				Eventually(func() map[string]*connection { return proxy.clientDict }).Should(HaveLen(1))
				var key string
				var conn *connection
				for key, conn = range proxy.clientDict {
					Eventually(func() uint64 { return atomic.LoadUint64(&conn.outgoingPacketCounter) }).Should(Equal(uint64(1)))
				}

				// send the second packet
				_, err = clientConn.Write(makePacket(2, []byte("decafbad")))
				Expect(err).ToNot(HaveOccurred())

				Expect(proxy.clientDict).To(HaveLen(1))
				Eventually(func() uint64 { return proxy.clientDict[key].outgoingPacketCounter }).Should(BeEquivalentTo(2))

				var clientReceivedPackets []packetData
				// receive the packets echoed by the server on client side
				go func() {
					for {
						buf := make([]byte, protocol.MaxPacketSize)
						// the ReadFromUDP will error as soon as the UDP conn is closed
						n, _, err2 := clientConn.ReadFromUDP(buf)
						if err2 != nil {
							return
						}
						data := buf[0:n]
						clientReceivedPackets = append(clientReceivedPackets, packetData(data))
					}
				}()

				Eventually(func() []packetData { return serverReceivedPackets }).Should(HaveLen(2))
				Expect(serverReceivedPackets).To(HaveLen(2))
				Expect(serverNumPacketsSent).To(Equal(2))
				Eventually(func() []packetData { return clientReceivedPackets }).Should(HaveLen(2))
				Expect(string(clientReceivedPackets[0])).To(ContainSubstring("foobar"))
				Expect(string(clientReceivedPackets[1])).To(ContainSubstring("decafbad"))
			})
		})

		Context("Drop Callbacks", func() {
			It("drops incoming packets", func() {
				opts := Opts{
					RemoteAddr: serverAddr,
					DropPacket: func(d Direction, p protocol.PacketNumber) bool {
						return d == DirectionIncoming && p%2 == 0
					},
				}
				startProxy(opts)

				// send 6 packets
				for i := 1; i <= 6; i++ {
					_, err := clientConn.Write(makePacket(protocol.PacketNumber(i), []byte("foobar"+strconv.Itoa(i))))
					Expect(err).ToNot(HaveOccurred())
				}
				Eventually(func() []packetData { return serverReceivedPackets }).Should(HaveLen(3))
				Consistently(func() []packetData { return serverReceivedPackets }).Should(HaveLen(3))
			})

			It("drops outgoing packets", func() {
				opts := Opts{
					RemoteAddr: serverAddr,
					DropPacket: func(d Direction, p protocol.PacketNumber) bool {
						return d == DirectionOutgoing && p%2 == 0
					},
				}
				startProxy(opts)

				var clientReceivedPackets []packetData
				// receive the packets echoed by the server on client side
				go func() {
					for {
						buf := make([]byte, protocol.MaxPacketSize)
						// the ReadFromUDP will error as soon as the UDP conn is closed
						n, _, err2 := clientConn.ReadFromUDP(buf)
						if err2 != nil {
							return
						}
						data := buf[0:n]
						clientReceivedPackets = append(clientReceivedPackets, packetData(data))
					}
				}()

				// send 6 packets
				for i := 1; i <= 6; i++ {
					_, err := clientConn.Write(makePacket(protocol.PacketNumber(i), []byte("foobar"+strconv.Itoa(i))))
					Expect(err).ToNot(HaveOccurred())
				}

				Eventually(func() []packetData { return clientReceivedPackets }).Should(HaveLen(3))
				Consistently(func() []packetData { return clientReceivedPackets }).Should(HaveLen(3))
			})
		})

		Context("Delay Callback", func() {
			It("delays incoming packets", func() {
				opts := Opts{
					RemoteAddr: serverAddr,
					// delay packet 1 by 200 ms
					// delay packet 2 by 400 ms
					// ...
					DelayPacket: func(d Direction, p protocol.PacketNumber) time.Duration {
						if d == DirectionOutgoing {
							return 0
						}
						return time.Duration(200*p) * time.Millisecond
					},
				}
				startProxy(opts)

				// send 3 packets
				start := time.Now()
				for i := 1; i <= 3; i++ {
					_, err := clientConn.Write(makePacket(protocol.PacketNumber(i), []byte("foobar"+strconv.Itoa(i))))
					Expect(err).ToNot(HaveOccurred())
				}
				Eventually(func() []packetData { return serverReceivedPackets }).Should(HaveLen(1))
				Expect(time.Now()).To(BeTemporally("~", start.Add(200*time.Millisecond), 50*time.Millisecond))
				Eventually(func() []packetData { return serverReceivedPackets }).Should(HaveLen(2))
				Expect(time.Now()).To(BeTemporally("~", start.Add(400*time.Millisecond), 50*time.Millisecond))
				Eventually(func() []packetData { return serverReceivedPackets }).Should(HaveLen(3))
				Expect(time.Now()).To(BeTemporally("~", start.Add(600*time.Millisecond), 50*time.Millisecond))
			})

			It("delays outgoing packets", func() {
				opts := Opts{
					RemoteAddr: serverAddr,
					// delay packet 1 by 200 ms
					// delay packet 2 by 400 ms
					// ...
					DelayPacket: func(d Direction, p protocol.PacketNumber) time.Duration {
						if d == DirectionIncoming {
							return 0
						}
						return time.Duration(200*p) * time.Millisecond
					},
				}
				startProxy(opts)

				var clientReceivedPackets []packetData
				// receive the packets echoed by the server on client side
				go func() {
					for {
						buf := make([]byte, protocol.MaxPacketSize)
						// the ReadFromUDP will error as soon as the UDP conn is closed
						n, _, err2 := clientConn.ReadFromUDP(buf)
						if err2 != nil {
							return
						}
						data := buf[0:n]
						clientReceivedPackets = append(clientReceivedPackets, packetData(data))
					}
				}()

				// send 3 packets
				start := time.Now()
				for i := 1; i <= 3; i++ {
					_, err := clientConn.Write(makePacket(protocol.PacketNumber(i), []byte("foobar"+strconv.Itoa(i))))
					Expect(err).ToNot(HaveOccurred())
				}
				// the packets should have arrived immediately at the server
				Eventually(func() []packetData { return serverReceivedPackets }).Should(HaveLen(3))
				Expect(time.Now()).To(BeTemporally("~", start, 50*time.Millisecond))
				Eventually(func() []packetData { return clientReceivedPackets }).Should(HaveLen(1))
				Expect(time.Now()).To(BeTemporally("~", start.Add(200*time.Millisecond), 50*time.Millisecond))
				Eventually(func() []packetData { return clientReceivedPackets }).Should(HaveLen(2))
				Expect(time.Now()).To(BeTemporally("~", start.Add(400*time.Millisecond), 50*time.Millisecond))
				Eventually(func() []packetData { return clientReceivedPackets }).Should(HaveLen(3))
				Expect(time.Now()).To(BeTemporally("~", start.Add(600*time.Millisecond), 50*time.Millisecond))
			})
		})
	})
})
