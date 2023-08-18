//go:build linux

package quic

import (
	"errors"
	"net"
	"os"

	"golang.org/x/sys/unix"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var errGSO = &os.SyscallError{Err: unix.EIO}

var _ = Describe("forcing a change of send and receive buffer sizes", func() {
	It("forces a change of the receive buffer size", func() {
		if os.Getuid() != 0 {
			Skip("Must be root to force change the receive buffer size")
		}

		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		Expect(err).ToNot(HaveOccurred())
		defer c.Close()
		syscallConn, err := c.(*net.UDPConn).SyscallConn()
		Expect(err).ToNot(HaveOccurred())

		const small = 256 << 10 // 256 KB
		Expect(forceSetReceiveBuffer(syscallConn, small)).To(Succeed())

		size, err := inspectReadBuffer(syscallConn)
		Expect(err).ToNot(HaveOccurred())
		//  The kernel doubles this value (to allow space for bookkeeping overhead)
		Expect(size).To(Equal(2 * small))

		const large = 32 << 20 // 32 MB
		Expect(forceSetReceiveBuffer(syscallConn, large)).To(Succeed())
		size, err = inspectReadBuffer(syscallConn)
		Expect(err).ToNot(HaveOccurred())
		//  The kernel doubles this value (to allow space for bookkeeping overhead)
		Expect(size).To(Equal(2 * large))
	})

	It("forces a change of the send buffer size", func() {
		if os.Getuid() != 0 {
			Skip("Must be root to force change the send buffer size")
		}

		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		Expect(err).ToNot(HaveOccurred())
		defer c.Close()
		syscallConn, err := c.(*net.UDPConn).SyscallConn()
		Expect(err).ToNot(HaveOccurred())

		const small = 256 << 10 // 256 KB
		Expect(forceSetSendBuffer(syscallConn, small)).To(Succeed())

		size, err := inspectWriteBuffer(syscallConn)
		Expect(err).ToNot(HaveOccurred())
		//  The kernel doubles this value (to allow space for bookkeeping overhead)
		Expect(size).To(Equal(2 * small))

		const large = 32 << 20 // 32 MB
		Expect(forceSetSendBuffer(syscallConn, large)).To(Succeed())
		size, err = inspectWriteBuffer(syscallConn)
		Expect(err).ToNot(HaveOccurred())
		//  The kernel doubles this value (to allow space for bookkeeping overhead)
		Expect(size).To(Equal(2 * large))
	})

	It("detects GSO errors", func() {
		Expect(isGSOError(errGSO)).To(BeTrue())
		Expect(isGSOError(nil)).To(BeFalse())
		Expect(isGSOError(errors.New("test"))).To(BeFalse())
	})
})
