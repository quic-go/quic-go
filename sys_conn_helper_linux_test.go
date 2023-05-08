// We need root permissions to use RCVBUFFORCE.
// This test is therefore only compiled when the root build flag is set.
// It can only succeed if the tests are then also run with root permissions.
//go:build linux && root

package quic

import (
	"net"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Can change the receive buffer size", func() {
	It("Force a change (if we have CAP_NET_ADMIN)", func() {
		if os.Getuid() != 0 {
			Fail("Must be root to force change the receive buffer size")
		}

		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		Expect(err).ToNot(HaveOccurred())
		defer c.Close()
		syscallConn, err := c.(*net.UDPConn).SyscallConn()
		Expect(err).ToNot(HaveOccurred())
		forceSetReceiveBuffer(syscallConn, 256<<10)

		size, err := inspectReadBuffer(syscallConn)
		Expect(err).ToNot(HaveOccurred())
		//  The kernel doubles this value (to allow space for bookkeeping overhead)
		Expect(size).To(Equal(512 << 10))

		forceSetReceiveBuffer(syscallConn, 512<<10)
		size, err = inspectReadBuffer(syscallConn)
		Expect(err).ToNot(HaveOccurred())
		//  The kernel doubles this value (to allow space for bookkeeping overhead)
		Expect(size).To(Equal(1024 << 10))
	})
})
