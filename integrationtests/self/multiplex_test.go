package self_test

import (
	"context"
	"io"
	"net"
	"runtime"
	"time"

	"github.com/quic-go/quic-go"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Multiplexing", func() {
	runServer := func(ln *quic.Listener) {
		go func() {
			defer GinkgoRecover()
			for {
				conn, err := ln.Accept(context.Background())
				if err != nil {
					return
				}
				go func() {
					defer GinkgoRecover()
					str, err := conn.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					defer str.Close()
					_, err = str.Write(PRData)
					Expect(err).ToNot(HaveOccurred())
				}()
			}
		}()
	}

	dial := func(tr *quic.Transport, addr net.Addr) {
		conn, err := tr.Dial(
			context.Background(),
			addr,
			getTLSClientConfig(),
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		defer conn.CloseWithError(0, "")
		str, err := conn.AcceptStream(context.Background())
		Expect(err).ToNot(HaveOccurred())
		data, err := io.ReadAll(str)
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal(PRData))
	}

	Context("multiplexing clients on the same conn", func() {
		getListener := func() *quic.Listener {
			ln, err := quic.ListenAddr(
				"localhost:0",
				getTLSConfig(),
				getQuicConfig(nil),
			)
			Expect(err).ToNot(HaveOccurred())
			return ln
		}

		It("multiplexes connections to the same server", func() {
			server := getListener()
			runServer(server)
			defer server.Close()

			addr, err := net.ResolveUDPAddr("udp", "localhost:0")
			Expect(err).ToNot(HaveOccurred())
			conn, err := net.ListenUDP("udp", addr)
			Expect(err).ToNot(HaveOccurred())
			defer conn.Close()
			tr := &quic.Transport{Conn: conn}

			done1 := make(chan struct{})
			done2 := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				dial(tr, server.Addr())
				close(done1)
			}()
			go func() {
				defer GinkgoRecover()
				dial(tr, server.Addr())
				close(done2)
			}()
			timeout := 30 * time.Second
			if debugLog() {
				timeout = time.Minute
			}
			Eventually(done1, timeout).Should(BeClosed())
			Eventually(done2, timeout).Should(BeClosed())
		})

		It("multiplexes connections to different servers", func() {
			server1 := getListener()
			runServer(server1)
			defer server1.Close()
			server2 := getListener()
			runServer(server2)
			defer server2.Close()

			addr, err := net.ResolveUDPAddr("udp", "localhost:0")
			Expect(err).ToNot(HaveOccurred())
			conn, err := net.ListenUDP("udp", addr)
			Expect(err).ToNot(HaveOccurred())
			defer conn.Close()
			tr := &quic.Transport{Conn: conn}

			done1 := make(chan struct{})
			done2 := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				dial(tr, server1.Addr())
				close(done1)
			}()
			go func() {
				defer GinkgoRecover()
				dial(tr, server2.Addr())
				close(done2)
			}()
			timeout := 30 * time.Second
			if debugLog() {
				timeout = time.Minute
			}
			Eventually(done1, timeout).Should(BeClosed())
			Eventually(done2, timeout).Should(BeClosed())
		})
	})

	Context("multiplexing server and client on the same conn", func() {
		It("connects to itself", func() {
			addr, err := net.ResolveUDPAddr("udp", "localhost:0")
			Expect(err).ToNot(HaveOccurred())
			conn, err := net.ListenUDP("udp", addr)
			Expect(err).ToNot(HaveOccurred())
			defer conn.Close()
			tr := &quic.Transport{Conn: conn}
			server, err := tr.Listen(
				getTLSConfig(),
				getQuicConfig(nil),
			)
			Expect(err).ToNot(HaveOccurred())
			runServer(server)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				dial(tr, server.Addr())
				close(done)
			}()
			timeout := 30 * time.Second
			if debugLog() {
				timeout = time.Minute
			}
			Eventually(done, timeout).Should(BeClosed())
		})

		// This test would require setting of iptables rules, see https://stackoverflow.com/questions/23859164/linux-udp-socket-sendto-operation-not-permitted.
		if runtime.GOOS != "linux" {
			It("runs a server and client on the same conn", func() {
				addr1, err := net.ResolveUDPAddr("udp", "localhost:0")
				Expect(err).ToNot(HaveOccurred())
				conn1, err := net.ListenUDP("udp", addr1)
				Expect(err).ToNot(HaveOccurred())
				defer conn1.Close()
				tr1 := &quic.Transport{Conn: conn1}

				addr2, err := net.ResolveUDPAddr("udp", "localhost:0")
				Expect(err).ToNot(HaveOccurred())
				conn2, err := net.ListenUDP("udp", addr2)
				Expect(err).ToNot(HaveOccurred())
				defer conn2.Close()
				tr2 := &quic.Transport{Conn: conn2}

				server1, err := tr1.Listen(
					getTLSConfig(),
					getQuicConfig(nil),
				)
				Expect(err).ToNot(HaveOccurred())
				runServer(server1)
				defer server1.Close()

				server2, err := tr2.Listen(
					getTLSConfig(),
					getQuicConfig(nil),
				)
				Expect(err).ToNot(HaveOccurred())
				runServer(server2)
				defer server2.Close()

				done1 := make(chan struct{})
				done2 := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					dial(tr2, server1.Addr())
					close(done1)
				}()
				go func() {
					defer GinkgoRecover()
					dial(tr1, server2.Addr())
					close(done2)
				}()
				timeout := 30 * time.Second
				if debugLog() {
					timeout = time.Minute
				}
				Eventually(done1, timeout).Should(BeClosed())
				Eventually(done2, timeout).Should(BeClosed())
			})
		}
	})
})
