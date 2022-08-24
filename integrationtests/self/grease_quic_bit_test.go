package self_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"

	"github.com/lucas-clemente/quic-go"
	quicproxy "github.com/lucas-clemente/quic-go/integrationtests/tools/proxy"
	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("QUIC Bit Greasing", func() {
	type counter struct {
		incomingQUICBitSet, outgoingQUICBitSet       uint32
		incomingQUICBitNotSet, outgoingQUICBitNotSet uint32
	}

	runProxy := func(serverAddr string) (*counter, *quicproxy.QuicProxy) {
		var c counter
		proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr: serverAddr,
			DropPacket: func(dir quicproxy.Direction, packet []byte) bool {
				set := packet[0]&0x40 > 0
				switch {
				case dir == quicproxy.DirectionIncoming && set:
					atomic.AddUint32(&c.incomingQUICBitSet, 1)
				case dir == quicproxy.DirectionIncoming && !set:
					atomic.AddUint32(&c.incomingQUICBitNotSet, 1)
				case dir == quicproxy.DirectionOutgoing && set:
					atomic.AddUint32(&c.outgoingQUICBitSet, 1)
				case dir == quicproxy.DirectionOutgoing && !set:
					atomic.AddUint32(&c.outgoingQUICBitNotSet, 1)
				}
				return false
			},
		})
		Expect(err).ToNot(HaveOccurred())
		return &c, proxy
	}

	runTransfer := func(ln quic.Listener, clientConf *quic.Config, proxyPort int) {
		go func() {
			defer GinkgoRecover()
			conn, err := ln.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			str, err := conn.AcceptStream(context.Background())
			Expect(err).ToNot(HaveOccurred())
			defer str.Close()
			_, err = io.Copy(str, str)
			Expect(err).ToNot(HaveOccurred())
		}()

		conn, err := quic.DialAddr(fmt.Sprintf("localhost:%d", proxyPort), tlsClientConfig, clientConf)
		Expect(err).ToNot(HaveOccurred())
		str, err := conn.OpenStream()
		Expect(err).ToNot(HaveOccurred())
		_, err = str.Write(PRData)
		Expect(err).ToNot(HaveOccurred())
		Expect(str.Close()).To(Succeed())
		_, err = io.Copy(io.Discard, str)
		Expect(err).ToNot(HaveOccurred())
		conn.CloseWithError(0, "")
	}

	for _, v := range protocol.SupportedVersions {
		version := v

		Context(fmt.Sprintf("with QUIC version %s", version), func() {
			It("disables QUIC bit greasing on both sides", func() {
				ln, err := quic.ListenAddr(
					"localhost:0",
					tlsConfig,
					getQuicConfig(&quic.Config{
						DisableQUICBitGreasing: true,
						Versions:               []protocol.VersionNumber{version},
					}),
				)
				Expect(err).ToNot(HaveOccurred())
				defer ln.Close()
				c, proxy := runProxy(fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port))
				defer proxy.Close()
				runTransfer(
					ln,
					getQuicConfig(&quic.Config{Versions: []protocol.VersionNumber{version}, DisableQUICBitGreasing: true}),
					proxy.LocalPort(),
				)

				Expect(atomic.LoadUint32(&c.incomingQUICBitSet)).ToNot(BeZero())
				Expect(atomic.LoadUint32(&c.outgoingQUICBitSet)).ToNot(BeZero())
				Expect(atomic.LoadUint32(&c.incomingQUICBitNotSet)).To(BeZero())
				Expect(atomic.LoadUint32(&c.outgoingQUICBitNotSet)).To(BeZero())
			})

			It("enables QUIC bit greasing on the server side", func() {
				ln, err := quic.ListenAddr(
					"localhost:0",
					tlsConfig,
					getQuicConfig(&quic.Config{Versions: []protocol.VersionNumber{version}}),
				)
				Expect(err).ToNot(HaveOccurred())
				defer ln.Close()
				c, proxy := runProxy(fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port))
				defer proxy.Close()

				// When greasing is enabled by the quic.Config, we occasionally disable it to grease the greasing mechanism.
				// If we hit one of those cases, just rerun the transfer.
				for i := 0; i < 10; i++ {
					runTransfer(
						ln,
						getQuicConfig(&quic.Config{
							DisableQUICBitGreasing: true,
							Versions:               []protocol.VersionNumber{version},
						}),
						proxy.LocalPort(),
					)
					if atomic.LoadUint32(&c.incomingQUICBitNotSet) > 0 {
						break
					}
				}

				Expect(atomic.LoadUint32(&c.outgoingQUICBitSet)).ToNot(BeZero())
				Expect(atomic.LoadUint32(&c.incomingQUICBitNotSet)).ToNot(BeZero())
				Expect(atomic.LoadUint32(&c.outgoingQUICBitNotSet)).To(BeZero())
			})

			It("enables QUIC bit greasing on the client side", func() {
				ln, err := quic.ListenAddr(
					"localhost:0",
					tlsConfig,
					getQuicConfig(&quic.Config{DisableQUICBitGreasing: true}),
				)
				Expect(err).ToNot(HaveOccurred())
				defer ln.Close()
				c, proxy := runProxy(fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port))
				defer proxy.Close()

				// When greasing is enabled by the quic.Config, we occasionally disable it to grease the greasing mechanism.
				// If we hit one of those cases, just rerun the transfer.
				for i := 0; i < 10; i++ {
					runTransfer(ln, getQuicConfig(&quic.Config{Versions: []protocol.VersionNumber{version}}), proxy.LocalPort())
					if atomic.LoadUint32(&c.outgoingQUICBitNotSet) > 0 {
						break
					}
				}

				Expect(atomic.LoadUint32(&c.outgoingQUICBitNotSet)).ToNot(BeZero())
				Expect(atomic.LoadUint32(&c.incomingQUICBitSet)).ToNot(BeZero())
				Expect(atomic.LoadUint32(&c.incomingQUICBitNotSet)).To(BeZero())
			})
		})
	}
})
