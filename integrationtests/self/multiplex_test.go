package self_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"runtime"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Multiplexing", func() {
	for _, v := range protocol.SupportedVersions {
		version := v

		Context(fmt.Sprintf("with QUIC version %s", version), func() {
			runServer := func(ln quic.Listener) {
				go func() {
					defer GinkgoRecover()
					for {
						sess, err := ln.Accept(context.Background())
						if err != nil {
							return
						}
						go func() {
							defer GinkgoRecover()
							str, err := sess.OpenStream()
							Expect(err).ToNot(HaveOccurred())
							defer str.Close()
							_, err = str.Write(PRData)
							Expect(err).ToNot(HaveOccurred())
						}()
					}
				}()
			}

			dial := func(conn net.PacketConn, addr net.Addr) {
				sess, err := quic.Dial(
					conn,
					addr,
					fmt.Sprintf("localhost:%d", addr.(*net.UDPAddr).Port),
					getTLSClientConfig(),
					&quic.Config{Versions: []protocol.VersionNumber{version}},
				)
				Expect(err).ToNot(HaveOccurred())
				defer sess.Close()
				str, err := sess.AcceptStream(context.Background())
				Expect(err).ToNot(HaveOccurred())
				data, err := ioutil.ReadAll(str)
				Expect(err).ToNot(HaveOccurred())
				Expect(data).To(Equal(PRData))
			}

			Context("multiplexing clients on the same conn", func() {
				getListener := func() quic.Listener {
					ln, err := quic.ListenAddr(
						"localhost:0",
						getTLSConfig(),
						&quic.Config{Versions: []protocol.VersionNumber{version}},
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

					done1 := make(chan struct{})
					done2 := make(chan struct{})
					go func() {
						defer GinkgoRecover()
						dial(conn, server.Addr())
						close(done1)
					}()
					go func() {
						defer GinkgoRecover()
						dial(conn, server.Addr())
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

					done1 := make(chan struct{})
					done2 := make(chan struct{})
					go func() {
						defer GinkgoRecover()
						dial(conn, server1.Addr())
						close(done1)
					}()
					go func() {
						defer GinkgoRecover()
						dial(conn, server2.Addr())
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

					server, err := quic.Listen(
						conn,
						getTLSConfig(),
						&quic.Config{Versions: []protocol.VersionNumber{version}},
					)
					Expect(err).ToNot(HaveOccurred())
					runServer(server)
					done := make(chan struct{})
					go func() {
						defer GinkgoRecover()
						dial(conn, server.Addr())
						close(done)
					}()
					timeout := 30 * time.Second
					if debugLog() {
						timeout = time.Minute
					}
					Eventually(done, timeout).Should(BeClosed())
				})

				It("runs a server and client on the same conn", func() {
					if runtime.GOOS == "linux" {
						Skip("This test would require setting of iptables rules, see https://stackoverflow.com/questions/23859164/linux-udp-socket-sendto-operation-not-permitted.")
					}
					addr1, err := net.ResolveUDPAddr("udp", "localhost:0")
					Expect(err).ToNot(HaveOccurred())
					conn1, err := net.ListenUDP("udp", addr1)
					Expect(err).ToNot(HaveOccurred())
					defer conn1.Close()

					addr2, err := net.ResolveUDPAddr("udp", "localhost:0")
					Expect(err).ToNot(HaveOccurred())
					conn2, err := net.ListenUDP("udp", addr2)
					Expect(err).ToNot(HaveOccurred())
					defer conn2.Close()

					server1, err := quic.Listen(
						conn1,
						getTLSConfig(),
						&quic.Config{Versions: []protocol.VersionNumber{version}},
					)
					Expect(err).ToNot(HaveOccurred())
					runServer(server1)
					defer server1.Close()

					server2, err := quic.Listen(
						conn2,
						getTLSConfig(),
						&quic.Config{Versions: []protocol.VersionNumber{version}},
					)
					Expect(err).ToNot(HaveOccurred())
					runServer(server2)
					defer server2.Close()

					done1 := make(chan struct{})
					done2 := make(chan struct{})
					go func() {
						defer GinkgoRecover()
						dial(conn2, server1.Addr())
						close(done1)
					}()
					go func() {
						defer GinkgoRecover()
						dial(conn1, server2.Addr())
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
		})
	}
})
