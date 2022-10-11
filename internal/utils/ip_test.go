package utils

import (
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("IP", func() {
	It("tells IPv4 and IPv6 addresses apart", func() {
		Expect(IsIPv4(net.IPv4(127, 0, 0, 1))).To(BeTrue())
		Expect(IsIPv4(net.IPv4zero)).To(BeTrue())
		Expect(IsIPv4(net.IPv6zero)).To(BeFalse())
		Expect(IsIPv4(net.IPv6loopback)).To(BeFalse())
	})
})
