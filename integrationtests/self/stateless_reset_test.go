package self_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stateless Resets", func() {
	connIDLens := []int{0, 10}

	for i := range connIDLens {
		connIDLen := connIDLens[i]

		It(fmt.Sprintf("sends and recognizes stateless resets, for %d byte connection IDs", connIDLen), func() {
			var statelessResetKey quic.StatelessResetKey
			rand.Read(statelessResetKey[:])
			serverConfig := getQuicConfig(&quic.Config{StatelessResetKey: &statelessResetKey})

			ln, err := quic.ListenAddr("localhost:0", getTLSConfig(), serverConfig)
			Expect(err).ToNot(HaveOccurred())
			serverPort := ln.Addr().(*net.UDPAddr).Port

			closeServer := make(chan struct{})

			go func() {
				defer GinkgoRecover()
				conn, err := ln.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				str, err := conn.OpenStream()
				Expect(err).ToNot(HaveOccurred())
				_, err = str.Write([]byte("foobar"))
				Expect(err).ToNot(HaveOccurred())
				<-closeServer
				ln.Close()
			}()

			var drop atomic.Bool
			proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
				RemoteAddr: fmt.Sprintf("localhost:%d", serverPort),
				DropPacket: func(quicproxy.Direction, []byte) bool {
					return drop.Load()
				},
			})
			Expect(err).ToNot(HaveOccurred())
			defer proxy.Close()

			conn, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", proxy.LocalPort()),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{
					ConnectionIDLength: connIDLen,
					MaxIdleTimeout:     2 * time.Second,
				}),
			)
			Expect(err).ToNot(HaveOccurred())
			str, err := conn.AcceptStream(context.Background())
			Expect(err).ToNot(HaveOccurred())
			data := make([]byte, 6)
			_, err = str.Read(data)
			Expect(err).ToNot(HaveOccurred())
			Expect(data).To(Equal([]byte("foobar")))

			// make sure that the CONNECTION_CLOSE is dropped
			drop.Store(true)
			close(closeServer)
			time.Sleep(100 * time.Millisecond)

			ln2, err := quic.ListenAddr(
				fmt.Sprintf("localhost:%d", serverPort),
				getTLSConfig(),
				serverConfig,
			)
			Expect(err).ToNot(HaveOccurred())
			drop.Store(false)

			acceptStopped := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := ln2.Accept(context.Background())
				Expect(err).To(HaveOccurred())
				close(acceptStopped)
			}()

			// Trigger something (not too small) to be sent, so that we receive the stateless reset.
			// If the client already sent another packet, it might already have received a packet.
			_, serr := str.Write([]byte("Lorem ipsum dolor sit amet."))
			if serr == nil {
				_, serr = str.Read([]byte{0})
			}
			Expect(serr).To(HaveOccurred())
			statelessResetErr := &quic.StatelessResetError{}
			Expect(errors.As(serr, &statelessResetErr)).To(BeTrue())
			Expect(ln2.Close()).To(Succeed())
			Eventually(acceptStopped).Should(BeClosed())
		})
	}
})
