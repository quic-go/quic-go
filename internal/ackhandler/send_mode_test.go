package ackhandler

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Send Mode", func() {
	It("has a string representation", func() {
		Expect(SendNone.String()).To(Equal("none"))
		Expect(SendAny.String()).To(Equal("any"))
		Expect(SendAck.String()).To(Equal("ack"))
		Expect(SendPTO.String()).To(Equal("pto"))
		Expect(SendRetransmission.String()).To(Equal("retransmission"))
		Expect(SendMode(123).String()).To(Equal("invalid send mode: 123"))
	})
})
