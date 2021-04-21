// +build windows

package quic

import (
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Windows Conn Test", func() {
	It("try newConn", func() {
		addr, err := net.ResolveUDPAddr("udp4", "localhost:0")
		Expect(err).ToNot(HaveOccurred())
		udpConn, err := net.ListenUDP("udp4", addr)
		Expect(err).ToNot(HaveOccurred())
		conn, err := newConn(udpConn)
		Expect(err).ToNot(HaveOccurred())
		_ = conn.Close()
	})
})
