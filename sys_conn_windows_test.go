//go:build windows

package quic

import (
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Windows Conn Test", func() {
	It("works on IPv4", func() {
		addr, err := net.ResolveUDPAddr("udp4", "localhost:0")
		Expect(err).ToNot(HaveOccurred())
		udpConn, err := net.ListenUDP("udp4", addr)
		Expect(err).ToNot(HaveOccurred())
		conn, err := newConn(udpConn, true)
		Expect(err).ToNot(HaveOccurred())
		Expect(conn.Close()).To(Succeed())
		Expect(conn.capabilities().DF).To(BeTrue())
	})

	It("works on IPv6", func() {
		addr, err := net.ResolveUDPAddr("udp6", "[::1]:0")
		Expect(err).ToNot(HaveOccurred())
		udpConn, err := net.ListenUDP("udp6", addr)
		Expect(err).ToNot(HaveOccurred())
		conn, err := newConn(udpConn, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(conn.Close()).To(Succeed())
		Expect(conn.capabilities().DF).To(BeFalse())
	})
})
