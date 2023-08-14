//go:build go1.21

package self_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type metadataClientSessionCache struct {
	toAdd    []byte
	restored func([]byte)

	cache tls.ClientSessionCache
}

func (m metadataClientSessionCache) Get(key string) (*tls.ClientSessionState, bool) {
	session, ok := m.cache.Get(key)
	if !ok || session == nil {
		return session, ok
	}
	ticket, state, err := session.ResumptionState()
	Expect(err).ToNot(HaveOccurred())
	Expect(state.Extra).To(HaveLen(2)) // ours, and the quic-go's
	m.restored(state.Extra[1])
	session, err = tls.NewResumptionState(ticket, state)
	Expect(err).ToNot(HaveOccurred())
	return session, true
}

func (m metadataClientSessionCache) Put(key string, session *tls.ClientSessionState) {
	ticket, state, err := session.ResumptionState()
	Expect(err).ToNot(HaveOccurred())
	state.Extra = append(state.Extra, m.toAdd)
	session, err = tls.NewResumptionState(ticket, state)
	Expect(err).ToNot(HaveOccurred())
	m.cache.Put(key, session)
}

var _ = Describe("0-RTT", func() {
	rtt := scaleDuration(5 * time.Millisecond)

	runCountingProxy := func(serverPort int) (*quicproxy.QuicProxy, *uint32) {
		var num0RTTPackets uint32 // to be used as an atomic
		proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr: fmt.Sprintf("localhost:%d", serverPort),
			DelayPacket: func(_ quicproxy.Direction, data []byte) time.Duration {
				for len(data) > 0 {
					if !wire.IsLongHeaderPacket(data[0]) {
						break
					}
					hdr, _, rest, err := wire.ParsePacket(data)
					Expect(err).ToNot(HaveOccurred())
					if hdr.Type == protocol.PacketType0RTT {
						atomic.AddUint32(&num0RTTPackets, 1)
						break
					}
					data = rest
				}
				return rtt / 2
			},
		})
		Expect(err).ToNot(HaveOccurred())

		return proxy, &num0RTTPackets
	}

	dialAndReceiveSessionTicket := func(serverTLSConf *tls.Config, serverConf *quic.Config, clientTLSConf *tls.Config) {
		if serverConf == nil {
			serverConf = getQuicConfig(nil)
		}
		serverConf.Allow0RTT = true
		ln, err := quic.ListenAddrEarly(
			"localhost:0",
			serverTLSConf,
			serverConf,
		)
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()

		proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr:  fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
			DelayPacket: func(_ quicproxy.Direction, data []byte) time.Duration { return rtt / 2 },
		})
		Expect(err).ToNot(HaveOccurred())
		defer proxy.Close()

		// dial the first connection in order to receive a session ticket
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			conn, err := ln.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			<-conn.Context().Done()
		}()

		puts := make(chan string, 100)
		cache := clientTLSConf.ClientSessionCache
		if cache == nil {
			cache = tls.NewLRUClientSessionCache(100)
		}
		clientTLSConf.ClientSessionCache = newClientSessionCache(cache, make(chan string, 100), puts)
		conn, err := quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", proxy.LocalPort()),
			clientTLSConf,
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		Eventually(puts).Should(Receive())
		// received the session ticket. We're done here.
		Expect(conn.CloseWithError(0, "")).To(Succeed())
		Eventually(done).Should(BeClosed())
	}

	transfer0RTTData := func(
		ln *quic.EarlyListener,
		proxyPort int,
		connIDLen int,
		clientTLSConf *tls.Config,
		clientConf *quic.Config,
		testdata []byte, // data to transfer
	) {
		// accept the second connection, and receive the data sent in 0-RTT
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			conn, err := ln.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			str, err := conn.AcceptStream(context.Background())
			Expect(err).ToNot(HaveOccurred())
			data, err := io.ReadAll(str)
			Expect(err).ToNot(HaveOccurred())
			Expect(data).To(Equal(testdata))
			Expect(str.Close()).To(Succeed())
			Expect(conn.ConnectionState().Used0RTT).To(BeTrue())
			<-conn.Context().Done()
			close(done)
		}()

		if clientConf == nil {
			clientConf = getQuicConfig(nil)
		}
		var conn quic.EarlyConnection
		if connIDLen == 0 {
			var err error
			conn, err = quic.DialAddrEarly(
				context.Background(),
				fmt.Sprintf("localhost:%d", proxyPort),
				clientTLSConf,
				clientConf,
			)
			Expect(err).ToNot(HaveOccurred())
		} else {
			addr, err := net.ResolveUDPAddr("udp", "localhost:0")
			Expect(err).ToNot(HaveOccurred())
			udpConn, err := net.ListenUDP("udp", addr)
			Expect(err).ToNot(HaveOccurred())
			defer udpConn.Close()
			tr := &quic.Transport{
				Conn:               udpConn,
				ConnectionIDLength: connIDLen,
			}
			defer tr.Close()
			conn, err = tr.DialEarly(
				context.Background(),
				&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: proxyPort},
				clientTLSConf,
				clientConf,
			)
			Expect(err).ToNot(HaveOccurred())
		}
		defer conn.CloseWithError(0, "")
		str, err := conn.OpenStream()
		Expect(err).ToNot(HaveOccurred())
		_, err = str.Write(testdata)
		Expect(err).ToNot(HaveOccurred())
		Expect(str.Close()).To(Succeed())
		<-conn.HandshakeComplete()
		Expect(conn.ConnectionState().Used0RTT).To(BeTrue())
		io.ReadAll(str) // wait for the EOF from the server to arrive before closing the conn
		conn.CloseWithError(0, "")
		Eventually(done).Should(BeClosed())
		Eventually(conn.Context().Done()).Should(BeClosed())
	}

	check0RTTRejected := func(
		ln *quic.EarlyListener,
		proxyPort int,
		clientConf *tls.Config,
	) {
		conn, err := quic.DialAddrEarly(
			context.Background(),
			fmt.Sprintf("localhost:%d", proxyPort),
			clientConf,
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		str, err := conn.OpenUniStream()
		Expect(err).ToNot(HaveOccurred())
		_, err = str.Write(make([]byte, 3000))
		Expect(err).ToNot(HaveOccurred())
		Expect(str.Close()).To(Succeed())
		Expect(conn.ConnectionState().Used0RTT).To(BeFalse())

		// make sure the server doesn't process the data
		ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(50*time.Millisecond))
		defer cancel()
		serverConn, err := ln.Accept(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(serverConn.ConnectionState().Used0RTT).To(BeFalse())
		_, err = serverConn.AcceptUniStream(ctx)
		Expect(err).To(Equal(context.DeadlineExceeded))
		Expect(serverConn.CloseWithError(0, "")).To(Succeed())
		Eventually(conn.Context().Done()).Should(BeClosed())
	}

	// can be used to extract 0-RTT from a packetTracer
	get0RTTPackets := func(packets []packet) []protocol.PacketNumber {
		var zeroRTTPackets []protocol.PacketNumber
		for _, p := range packets {
			if p.hdr.Type == protocol.PacketType0RTT {
				zeroRTTPackets = append(zeroRTTPackets, p.hdr.PacketNumber)
			}
		}
		return zeroRTTPackets
	}

	for _, l := range []int{0, 15} {
		connIDLen := l

		It(fmt.Sprintf("transfers 0-RTT data, with %d byte connection IDs", connIDLen), func() {
			tlsConf := getTLSConfig()
			clientTLSConf := getTLSClientConfig()
			dialAndReceiveSessionTicket(tlsConf, nil, clientTLSConf)

			tracer := newPacketTracer()
			ln, err := quic.ListenAddrEarly(
				"localhost:0",
				tlsConf,
				getQuicConfig(&quic.Config{
					Allow0RTT: true,
					Tracer:    newTracer(tracer),
				}),
			)
			Expect(err).ToNot(HaveOccurred())
			defer ln.Close()

			proxy, num0RTTPackets := runCountingProxy(ln.Addr().(*net.UDPAddr).Port)
			defer proxy.Close()

			transfer0RTTData(
				ln,
				proxy.LocalPort(),
				connIDLen,
				clientTLSConf,
				getQuicConfig(nil),
				PRData,
			)

			var numNewConnIDs int
			for _, p := range tracer.getRcvdLongHeaderPackets() {
				for _, f := range p.frames {
					if _, ok := f.(*logging.NewConnectionIDFrame); ok {
						numNewConnIDs++
					}
				}
			}
			if connIDLen == 0 {
				Expect(numNewConnIDs).To(BeZero())
			} else {
				Expect(numNewConnIDs).ToNot(BeZero())
			}

			num0RTT := atomic.LoadUint32(num0RTTPackets)
			fmt.Fprintf(GinkgoWriter, "Sent %d 0-RTT packets.", num0RTT)
			Expect(num0RTT).ToNot(BeZero())
			zeroRTTPackets := get0RTTPackets(tracer.getRcvdLongHeaderPackets())
			Expect(len(zeroRTTPackets)).To(BeNumerically(">", 10))
			Expect(zeroRTTPackets).To(ContainElement(protocol.PacketNumber(0)))
		})
	}

	// Test that data intended to be sent with 1-RTT protection is not sent in 0-RTT packets.
	It("waits for a connection until the handshake is done", func() {
		tlsConf := getTLSConfig()
		clientConf := getTLSClientConfig()
		dialAndReceiveSessionTicket(tlsConf, nil, clientConf)

		zeroRTTData := GeneratePRData(5 << 10)
		oneRTTData := PRData

		tracer := newPacketTracer()
		ln, err := quic.ListenAddrEarly(
			"localhost:0",
			tlsConf,
			getQuicConfig(&quic.Config{
				Allow0RTT: true,
				Tracer:    newTracer(tracer),
			}),
		)
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()

		// now accept the second connection, and receive the 0-RTT data
		go func() {
			defer GinkgoRecover()
			conn, err := ln.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			str, err := conn.AcceptUniStream(context.Background())
			Expect(err).ToNot(HaveOccurred())
			data, err := io.ReadAll(str)
			Expect(err).ToNot(HaveOccurred())
			Expect(data).To(Equal(zeroRTTData))
			str, err = conn.AcceptUniStream(context.Background())
			Expect(err).ToNot(HaveOccurred())
			data, err = io.ReadAll(str)
			Expect(err).ToNot(HaveOccurred())
			Expect(data).To(Equal(oneRTTData))
			Expect(conn.CloseWithError(0, "")).To(Succeed())
		}()

		proxy, _ := runCountingProxy(ln.Addr().(*net.UDPAddr).Port)
		defer proxy.Close()

		conn, err := quic.DialAddrEarly(
			context.Background(),
			fmt.Sprintf("localhost:%d", proxy.LocalPort()),
			clientConf,
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		firstStr, err := conn.OpenUniStream()
		Expect(err).ToNot(HaveOccurred())
		_, err = firstStr.Write(zeroRTTData)
		Expect(err).ToNot(HaveOccurred())
		Expect(firstStr.Close()).To(Succeed())

		// wait for the handshake to complete
		Eventually(conn.HandshakeComplete()).Should(BeClosed())
		str, err := conn.OpenUniStream()
		Expect(err).ToNot(HaveOccurred())
		_, err = str.Write(PRData)
		Expect(err).ToNot(HaveOccurred())
		Expect(str.Close()).To(Succeed())
		<-conn.Context().Done()

		// check that 0-RTT packets only contain STREAM frames for the first stream
		var num0RTT int
		for _, p := range tracer.getRcvdLongHeaderPackets() {
			if p.hdr.Header.Type != protocol.PacketType0RTT {
				continue
			}
			for _, f := range p.frames {
				sf, ok := f.(*logging.StreamFrame)
				if !ok {
					continue
				}
				num0RTT++
				Expect(sf.StreamID).To(Equal(firstStr.StreamID()))
			}
		}
		fmt.Fprintf(GinkgoWriter, "received %d STREAM frames in 0-RTT packets\n", num0RTT)
		Expect(num0RTT).ToNot(BeZero())
	})

	It("transfers 0-RTT data, when 0-RTT packets are lost", func() {
		var (
			num0RTTPackets uint32 // to be used as an atomic
			num0RTTDropped uint32
		)

		tlsConf := getTLSConfig()
		clientConf := getTLSClientConfig()
		dialAndReceiveSessionTicket(tlsConf, nil, clientConf)

		tracer := newPacketTracer()
		ln, err := quic.ListenAddrEarly(
			"localhost:0",
			tlsConf,
			getQuicConfig(&quic.Config{
				Allow0RTT: true,
				Tracer:    newTracer(tracer),
			}),
		)
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()

		proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr: fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
			DelayPacket: func(_ quicproxy.Direction, data []byte) time.Duration {
				if wire.IsLongHeaderPacket(data[0]) {
					hdr, _, _, err := wire.ParsePacket(data)
					Expect(err).ToNot(HaveOccurred())
					if hdr.Type == protocol.PacketType0RTT {
						atomic.AddUint32(&num0RTTPackets, 1)
					}
				}
				return rtt / 2
			},
			DropPacket: func(_ quicproxy.Direction, data []byte) bool {
				if !wire.IsLongHeaderPacket(data[0]) {
					return false
				}
				hdr, _, _, err := wire.ParsePacket(data)
				Expect(err).ToNot(HaveOccurred())
				if hdr.Type == protocol.PacketType0RTT {
					// drop 25% of the 0-RTT packets
					drop := mrand.Intn(4) == 0
					if drop {
						atomic.AddUint32(&num0RTTDropped, 1)
					}
					return drop
				}
				return false
			},
		})
		Expect(err).ToNot(HaveOccurred())
		defer proxy.Close()

		transfer0RTTData(ln, proxy.LocalPort(), protocol.DefaultConnectionIDLength, clientConf, nil, PRData)

		num0RTT := atomic.LoadUint32(&num0RTTPackets)
		numDropped := atomic.LoadUint32(&num0RTTDropped)
		fmt.Fprintf(GinkgoWriter, "Sent %d 0-RTT packets. Dropped %d of those.", num0RTT, numDropped)
		Expect(numDropped).ToNot(BeZero())
		Expect(num0RTT).ToNot(BeZero())
		Expect(get0RTTPackets(tracer.getRcvdLongHeaderPackets())).ToNot(BeEmpty())
	})

	It("retransmits all 0-RTT data when the server performs a Retry", func() {
		var mutex sync.Mutex
		var firstConnID, secondConnID *protocol.ConnectionID
		var firstCounter, secondCounter protocol.ByteCount

		tlsConf := getTLSConfig()
		clientConf := getTLSClientConfig()
		dialAndReceiveSessionTicket(tlsConf, nil, clientConf)

		countZeroRTTBytes := func(data []byte) (n protocol.ByteCount) {
			for len(data) > 0 {
				hdr, _, rest, err := wire.ParsePacket(data)
				if err != nil {
					return
				}
				data = rest
				if hdr.Type == protocol.PacketType0RTT {
					n += hdr.Length - 16 /* AEAD tag */
				}
			}
			return
		}

		tracer := newPacketTracer()
		ln, err := quic.ListenAddrEarly(
			"localhost:0",
			tlsConf,
			getQuicConfig(&quic.Config{
				RequireAddressValidation: func(net.Addr) bool { return true },
				Allow0RTT:                true,
				Tracer:                   newTracer(tracer),
			}),
		)
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()

		proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr: fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
			DelayPacket: func(dir quicproxy.Direction, data []byte) time.Duration {
				connID, err := wire.ParseConnectionID(data, 0)
				Expect(err).ToNot(HaveOccurred())

				mutex.Lock()
				defer mutex.Unlock()

				if zeroRTTBytes := countZeroRTTBytes(data); zeroRTTBytes > 0 {
					if firstConnID == nil {
						firstConnID = &connID
						firstCounter += zeroRTTBytes
					} else if firstConnID != nil && *firstConnID == connID {
						Expect(secondConnID).To(BeNil())
						firstCounter += zeroRTTBytes
					} else if secondConnID == nil {
						secondConnID = &connID
						secondCounter += zeroRTTBytes
					} else if secondConnID != nil && *secondConnID == connID {
						secondCounter += zeroRTTBytes
					} else {
						Fail("received 3 connection IDs on 0-RTT packets")
					}
				}
				return rtt / 2
			},
		})
		Expect(err).ToNot(HaveOccurred())
		defer proxy.Close()

		transfer0RTTData(ln, proxy.LocalPort(), protocol.DefaultConnectionIDLength, clientConf, nil, GeneratePRData(5000)) // ~5 packets

		mutex.Lock()
		defer mutex.Unlock()
		Expect(firstCounter).To(BeNumerically("~", 5000+100 /* framing overhead */, 100)) // the FIN bit might be sent extra
		Expect(secondCounter).To(BeNumerically("~", firstCounter, 20))
		zeroRTTPackets := get0RTTPackets(tracer.getRcvdLongHeaderPackets())
		Expect(len(zeroRTTPackets)).To(BeNumerically(">=", 5))
		Expect(zeroRTTPackets[0]).To(BeNumerically(">=", protocol.PacketNumber(5)))
	})

	It("doesn't reject 0-RTT when the server's transport stream limit increased", func() {
		const maxStreams = 1
		tlsConf := getTLSConfig()
		clientConf := getTLSClientConfig()
		dialAndReceiveSessionTicket(tlsConf, getQuicConfig(&quic.Config{
			MaxIncomingUniStreams: maxStreams,
		}), clientConf)

		tracer := newPacketTracer()
		ln, err := quic.ListenAddrEarly(
			"localhost:0",
			tlsConf,
			getQuicConfig(&quic.Config{
				MaxIncomingUniStreams: maxStreams + 1,
				Allow0RTT:             true,
				Tracer:                newTracer(tracer),
			}),
		)
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()
		proxy, _ := runCountingProxy(ln.Addr().(*net.UDPAddr).Port)
		defer proxy.Close()

		conn, err := quic.DialAddrEarly(
			context.Background(),
			fmt.Sprintf("localhost:%d", proxy.LocalPort()),
			clientConf,
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		str, err := conn.OpenUniStream()
		Expect(err).ToNot(HaveOccurred())
		_, err = str.Write([]byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		Expect(str.Close()).To(Succeed())
		// The client remembers the old limit and refuses to open a new stream.
		_, err = conn.OpenUniStream()
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("too many open streams"))
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err = conn.OpenUniStreamSync(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(conn.ConnectionState().Used0RTT).To(BeTrue())
		Expect(conn.CloseWithError(0, "")).To(Succeed())
	})

	It("rejects 0-RTT when the server's stream limit decreased", func() {
		const maxStreams = 42
		tlsConf := getTLSConfig()
		clientConf := getTLSClientConfig()
		dialAndReceiveSessionTicket(tlsConf, getQuicConfig(&quic.Config{
			MaxIncomingStreams: maxStreams,
		}), clientConf)

		tracer := newPacketTracer()
		ln, err := quic.ListenAddrEarly(
			"localhost:0",
			tlsConf,
			getQuicConfig(&quic.Config{
				MaxIncomingStreams: maxStreams - 1,
				Allow0RTT:          true,
				Tracer:             newTracer(tracer),
			}),
		)
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()
		proxy, num0RTTPackets := runCountingProxy(ln.Addr().(*net.UDPAddr).Port)
		defer proxy.Close()

		check0RTTRejected(ln, proxy.LocalPort(), clientConf)

		// The client should send 0-RTT packets, but the server doesn't process them.
		num0RTT := atomic.LoadUint32(num0RTTPackets)
		fmt.Fprintf(GinkgoWriter, "Sent %d 0-RTT packets.", num0RTT)
		Expect(num0RTT).ToNot(BeZero())
		Expect(get0RTTPackets(tracer.getRcvdLongHeaderPackets())).To(BeEmpty())
	})

	It("rejects 0-RTT when the ALPN changed", func() {
		tlsConf := getTLSConfig()
		clientConf := getTLSClientConfig()
		dialAndReceiveSessionTicket(tlsConf, nil, clientConf)

		// switch to different ALPN on the server side
		tlsConf.NextProtos = []string{"new-alpn"}
		// Append to the client's ALPN.
		// crypto/tls will attempt to resume with the ALPN from the original connection
		clientConf.NextProtos = append(clientConf.NextProtos, "new-alpn")
		tracer := newPacketTracer()
		ln, err := quic.ListenAddrEarly(
			"localhost:0",
			tlsConf,
			getQuicConfig(&quic.Config{
				Allow0RTT: true,
				Tracer:    newTracer(tracer),
			}),
		)
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()
		proxy, num0RTTPackets := runCountingProxy(ln.Addr().(*net.UDPAddr).Port)
		defer proxy.Close()

		check0RTTRejected(ln, proxy.LocalPort(), clientConf)

		// The client should send 0-RTT packets, but the server doesn't process them.
		num0RTT := atomic.LoadUint32(num0RTTPackets)
		fmt.Fprintf(GinkgoWriter, "Sent %d 0-RTT packets.", num0RTT)
		Expect(num0RTT).ToNot(BeZero())
		Expect(get0RTTPackets(tracer.getRcvdLongHeaderPackets())).To(BeEmpty())
	})

	It("rejects 0-RTT when the application doesn't allow it", func() {
		tlsConf := getTLSConfig()
		clientConf := getTLSClientConfig()
		dialAndReceiveSessionTicket(tlsConf, nil, clientConf)

		// now close the listener and dial new connection with a different ALPN
		tracer := newPacketTracer()
		ln, err := quic.ListenAddrEarly(
			"localhost:0",
			tlsConf,
			getQuicConfig(&quic.Config{
				Allow0RTT: false, // application rejects 0-RTT
				Tracer:    newTracer(tracer),
			}),
		)
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()
		proxy, num0RTTPackets := runCountingProxy(ln.Addr().(*net.UDPAddr).Port)
		defer proxy.Close()

		check0RTTRejected(ln, proxy.LocalPort(), clientConf)

		// The client should send 0-RTT packets, but the server doesn't process them.
		num0RTT := atomic.LoadUint32(num0RTTPackets)
		fmt.Fprintf(GinkgoWriter, "Sent %d 0-RTT packets.", num0RTT)
		Expect(num0RTT).ToNot(BeZero())
		Expect(get0RTTPackets(tracer.getRcvdLongHeaderPackets())).To(BeEmpty())
	})

	DescribeTable("flow control limits",
		func(addFlowControlLimit func(*quic.Config, uint64)) {
			tracer := newPacketTracer()
			firstConf := getQuicConfig(&quic.Config{Allow0RTT: true})
			addFlowControlLimit(firstConf, 3)
			tlsConf := getTLSConfig()
			clientConf := getTLSClientConfig()
			dialAndReceiveSessionTicket(tlsConf, firstConf, clientConf)

			secondConf := getQuicConfig(&quic.Config{
				Allow0RTT: true,
				Tracer:    newTracer(tracer),
			})
			addFlowControlLimit(secondConf, 100)
			ln, err := quic.ListenAddrEarly(
				"localhost:0",
				tlsConf,
				secondConf,
			)
			Expect(err).ToNot(HaveOccurred())
			defer ln.Close()
			proxy, _ := runCountingProxy(ln.Addr().(*net.UDPAddr).Port)
			defer proxy.Close()

			conn, err := quic.DialAddrEarly(
				context.Background(),
				fmt.Sprintf("localhost:%d", proxy.LocalPort()),
				clientConf,
				getQuicConfig(nil),
			)
			Expect(err).ToNot(HaveOccurred())
			str, err := conn.OpenUniStream()
			Expect(err).ToNot(HaveOccurred())
			written := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(written)
				_, err := str.Write([]byte("foobar"))
				Expect(err).ToNot(HaveOccurred())
				Expect(str.Close()).To(Succeed())
			}()

			Eventually(written).Should(BeClosed())

			serverConn, err := ln.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			rstr, err := serverConn.AcceptUniStream(context.Background())
			Expect(err).ToNot(HaveOccurred())
			data, err := io.ReadAll(rstr)
			Expect(err).ToNot(HaveOccurred())
			Expect(data).To(Equal([]byte("foobar")))
			Expect(serverConn.ConnectionState().Used0RTT).To(BeTrue())
			Expect(serverConn.CloseWithError(0, "")).To(Succeed())
			Eventually(conn.Context().Done()).Should(BeClosed())

			var processedFirst bool
			for _, p := range tracer.getRcvdLongHeaderPackets() {
				for _, f := range p.frames {
					if sf, ok := f.(*logging.StreamFrame); ok {
						if !processedFirst {
							// The first STREAM should have been sent in a 0-RTT packet.
							// Due to the flow control limit, the STREAM frame was limit to the first 3 bytes.
							Expect(p.hdr.Type).To(Equal(protocol.PacketType0RTT))
							Expect(sf.Length).To(BeEquivalentTo(3))
							processedFirst = true
						} else {
							Fail("STREAM was shouldn't have been sent in 0-RTT")
						}
					}
				}
			}
		},
		Entry("doesn't reject 0-RTT when the server's transport stream flow control limit increased", func(c *quic.Config, limit uint64) { c.InitialStreamReceiveWindow = limit }),
		Entry("doesn't reject 0-RTT when the server's transport connection flow control limit increased", func(c *quic.Config, limit uint64) { c.InitialConnectionReceiveWindow = limit }),
	)

	for _, l := range []int{0, 15} {
		connIDLen := l

		It(fmt.Sprintf("correctly deals with 0-RTT rejections, for %d byte connection IDs", connIDLen), func() {
			tlsConf := getTLSConfig()
			clientConf := getTLSClientConfig()
			dialAndReceiveSessionTicket(tlsConf, nil, clientConf)
			// now dial new connection with different transport parameters
			tracer := newPacketTracer()
			ln, err := quic.ListenAddrEarly(
				"localhost:0",
				tlsConf,
				getQuicConfig(&quic.Config{
					MaxIncomingUniStreams: 1,
					Tracer:                newTracer(tracer),
				}),
			)
			Expect(err).ToNot(HaveOccurred())
			defer ln.Close()
			proxy, num0RTTPackets := runCountingProxy(ln.Addr().(*net.UDPAddr).Port)
			defer proxy.Close()

			conn, err := quic.DialAddrEarly(
				context.Background(),
				fmt.Sprintf("localhost:%d", proxy.LocalPort()),
				clientConf,
				getQuicConfig(nil),
			)
			Expect(err).ToNot(HaveOccurred())
			// The client remembers that it was allowed to open 2 uni-directional streams.
			firstStr, err := conn.OpenUniStream()
			Expect(err).ToNot(HaveOccurred())
			written := make(chan struct{}, 2)
			go func() {
				defer GinkgoRecover()
				defer func() { written <- struct{}{} }()
				_, err := firstStr.Write([]byte("first flight"))
				Expect(err).ToNot(HaveOccurred())
			}()
			secondStr, err := conn.OpenUniStream()
			Expect(err).ToNot(HaveOccurred())
			go func() {
				defer GinkgoRecover()
				defer func() { written <- struct{}{} }()
				_, err := secondStr.Write([]byte("first flight"))
				Expect(err).ToNot(HaveOccurred())
			}()

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err = conn.AcceptStream(ctx)
			Expect(err).To(MatchError(quic.Err0RTTRejected))
			Eventually(written).Should(Receive())
			Eventually(written).Should(Receive())
			_, err = firstStr.Write([]byte("foobar"))
			Expect(err).To(MatchError(quic.Err0RTTRejected))
			_, err = conn.OpenUniStream()
			Expect(err).To(MatchError(quic.Err0RTTRejected))

			_, err = conn.AcceptStream(ctx)
			Expect(err).To(Equal(quic.Err0RTTRejected))

			newConn := conn.NextConnection()
			str, err := newConn.OpenUniStream()
			Expect(err).ToNot(HaveOccurred())
			_, err = newConn.OpenUniStream()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("too many open streams"))
			_, err = str.Write([]byte("second flight"))
			Expect(err).ToNot(HaveOccurred())
			Expect(str.Close()).To(Succeed())
			Expect(conn.CloseWithError(0, "")).To(Succeed())

			// The client should send 0-RTT packets, but the server doesn't process them.
			num0RTT := atomic.LoadUint32(num0RTTPackets)
			fmt.Fprintf(GinkgoWriter, "Sent %d 0-RTT packets.", num0RTT)
			Expect(num0RTT).ToNot(BeZero())
			Expect(get0RTTPackets(tracer.getRcvdLongHeaderPackets())).To(BeEmpty())
		})
	}

	It("queues 0-RTT packets, if the Initial is delayed", func() {
		tlsConf := getTLSConfig()
		clientConf := getTLSClientConfig()
		dialAndReceiveSessionTicket(tlsConf, nil, clientConf)

		tracer := newPacketTracer()
		ln, err := quic.ListenAddrEarly(
			"localhost:0",
			tlsConf,
			getQuicConfig(&quic.Config{
				Allow0RTT: true,
				Tracer:    newTracer(tracer),
			}),
		)
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()
		proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr: ln.Addr().String(),
			DelayPacket: func(dir quicproxy.Direction, data []byte) time.Duration {
				if dir == quicproxy.DirectionIncoming && wire.IsLongHeaderPacket(data[0]) && data[0]&0x30>>4 == 0 { // Initial packet from client
					return rtt/2 + rtt
				}
				return rtt / 2
			},
		})
		Expect(err).ToNot(HaveOccurred())
		defer proxy.Close()

		transfer0RTTData(ln, proxy.LocalPort(), protocol.DefaultConnectionIDLength, clientConf, nil, PRData)

		Expect(tracer.getRcvdLongHeaderPackets()[0].hdr.Type).To(Equal(protocol.PacketTypeInitial))
		zeroRTTPackets := get0RTTPackets(tracer.getRcvdLongHeaderPackets())
		Expect(len(zeroRTTPackets)).To(BeNumerically(">", 10))
		Expect(zeroRTTPackets[0]).To(Equal(protocol.PacketNumber(0)))
	})

	It("allows the application to attach data to the session ticket, for the server", func() {
		tlsConf := getTLSConfig()
		tlsConf.WrapSession = func(cs tls.ConnectionState, ss *tls.SessionState) ([]byte, error) {
			ss.Extra = append(ss.Extra, []byte("foobar"))
			return tlsConf.EncryptTicket(cs, ss)
		}
		var unwrapped bool
		tlsConf.UnwrapSession = func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
			defer GinkgoRecover()
			state, err := tlsConf.DecryptTicket(identity, cs)
			if err != nil {
				return nil, err
			}
			Expect(state.Extra).To(HaveLen(2))
			Expect(state.Extra[1]).To(Equal([]byte("foobar")))
			unwrapped = true
			return state, nil
		}
		clientTLSConf := getTLSClientConfig()
		dialAndReceiveSessionTicket(tlsConf, nil, clientTLSConf)

		tracer := newPacketTracer()
		ln, err := quic.ListenAddrEarly(
			"localhost:0",
			tlsConf,
			getQuicConfig(&quic.Config{
				Allow0RTT: true,
				Tracer:    newTracer(tracer),
			}),
		)
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()

		transfer0RTTData(
			ln,
			ln.Addr().(*net.UDPAddr).Port,
			10,
			clientTLSConf,
			getQuicConfig(nil),
			PRData,
		)
		Expect(unwrapped).To(BeTrue())
	})

	It("allows the application to attach data to the session ticket, for the client", func() {
		tlsConf := getTLSConfig()
		clientTLSConf := getTLSClientConfig()
		var restored bool
		clientTLSConf.ClientSessionCache = &metadataClientSessionCache{
			toAdd: []byte("foobar"),
			restored: func(b []byte) {
				defer GinkgoRecover()
				Expect(b).To(Equal([]byte("foobar")))
				restored = true
			},
			cache: tls.NewLRUClientSessionCache(100),
		}
		dialAndReceiveSessionTicket(tlsConf, nil, clientTLSConf)

		tracer := newPacketTracer()
		ln, err := quic.ListenAddrEarly(
			"localhost:0",
			tlsConf,
			getQuicConfig(&quic.Config{
				Allow0RTT: true,
				Tracer:    newTracer(tracer),
			}),
		)
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()

		transfer0RTTData(
			ln,
			ln.Addr().(*net.UDPAddr).Port,
			10,
			clientTLSConf,
			getQuicConfig(nil),
			PRData,
		)
		Expect(restored).To(BeTrue())
	})

	It("sends 0-RTT datagrams", func() {
		tlsConf := getTLSConfig()
		clientTLSConf := getTLSClientConfig()
		dialAndReceiveSessionTicket(tlsConf, getQuicConfig(&quic.Config{
			EnableDatagrams: true,
		}), clientTLSConf)

		tracer := newPacketTracer()
		ln, err := quic.ListenAddrEarly(
			"localhost:0",
			tlsConf,
			getQuicConfig(&quic.Config{
				Allow0RTT:       true,
				EnableDatagrams: true,
				Tracer:          newTracer(tracer),
			}),
		)
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()
		proxy, num0RTTPackets := runCountingProxy(ln.Addr().(*net.UDPAddr).Port)
		defer proxy.Close()

		// second connection
		sentMessage := GeneratePRData(100)
		var receivedMessage []byte
		received := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(received)
			conn, err := ln.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			receivedMessage, err = conn.ReceiveMessage(context.Background())
			Expect(err).ToNot(HaveOccurred())
			Expect(conn.ConnectionState().Used0RTT).To(BeTrue())
		}()
		conn, err := quic.DialAddrEarly(
			context.Background(),
			fmt.Sprintf("localhost:%d", proxy.LocalPort()),
			clientTLSConf,
			getQuicConfig(&quic.Config{
				EnableDatagrams: true,
			}),
		)
		Expect(err).ToNot(HaveOccurred())
		Expect(conn.ConnectionState().SupportsDatagrams).To(BeTrue())
		Expect(conn.SendMessage(sentMessage)).To(Succeed())
		<-conn.HandshakeComplete()
		<-received

		Expect(conn.ConnectionState().Used0RTT).To(BeTrue())
		Expect(receivedMessage).To(Equal(sentMessage))
		num0RTT := atomic.LoadUint32(num0RTTPackets)
		fmt.Fprintf(GinkgoWriter, "Sent %d 0-RTT packets.", num0RTT)
		Expect(num0RTT).ToNot(BeZero())
		zeroRTTPackets := get0RTTPackets(tracer.getRcvdLongHeaderPackets())
		Expect(zeroRTTPackets).To(HaveLen(1))
		Expect(conn.CloseWithError(0, "")).To(Succeed())
	})

	It("rejects 0-RTT datagrams when the server doesn't support datagrams anymore", func() {
		tlsConf := getTLSConfig()
		clientTLSConf := getTLSClientConfig()
		dialAndReceiveSessionTicket(tlsConf, getQuicConfig(&quic.Config{
			EnableDatagrams: true,
		}), clientTLSConf)

		tracer := newPacketTracer()
		ln, err := quic.ListenAddrEarly(
			"localhost:0",
			tlsConf,
			getQuicConfig(&quic.Config{
				Allow0RTT:       true,
				EnableDatagrams: false,
				Tracer:          newTracer(tracer),
			}),
		)
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()

		proxy, num0RTTPackets := runCountingProxy(ln.Addr().(*net.UDPAddr).Port)
		defer proxy.Close()

		// second connection
		go func() {
			defer GinkgoRecover()
			conn, err := ln.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			_, err = conn.ReceiveMessage(context.Background())
			Expect(err.Error()).To(Equal("datagram support disabled"))
			<-conn.HandshakeComplete()
			Expect(conn.ConnectionState().Used0RTT).To(BeFalse())
		}()
		conn, err := quic.DialAddrEarly(
			context.Background(),
			fmt.Sprintf("localhost:%d", proxy.LocalPort()),
			clientTLSConf,
			getQuicConfig(&quic.Config{
				EnableDatagrams: true,
			}),
		)
		Expect(err).ToNot(HaveOccurred())
		// the client can temporarily send datagrams but the server doesn't process them.
		Expect(conn.ConnectionState().SupportsDatagrams).To(BeTrue())
		Expect(conn.SendMessage(make([]byte, 100))).To(Succeed())
		<-conn.HandshakeComplete()

		Expect(conn.ConnectionState().SupportsDatagrams).To(BeFalse())
		Expect(conn.ConnectionState().Used0RTT).To(BeFalse())
		num0RTT := atomic.LoadUint32(num0RTTPackets)
		fmt.Fprintf(GinkgoWriter, "Sent %d 0-RTT packets.", num0RTT)
		Expect(num0RTT).ToNot(BeZero())
		Expect(get0RTTPackets(tracer.getRcvdLongHeaderPackets())).To(BeEmpty())
		Expect(conn.CloseWithError(0, "")).To(Succeed())
	})
})
