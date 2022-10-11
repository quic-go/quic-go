package ackhandler

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Send Mode", func() {
	It("has a string representation", func() {
		Expect(SendNone.String()).To(Equal("none"))
		Expect(SendAny.String()).To(Equal("any"))
		Expect(SendAck.String()).To(Equal("ack"))
		Expect(SendPTOInitial.String()).To(Equal("pto (Initial)"))
		Expect(SendPTOHandshake.String()).To(Equal("pto (Handshake)"))
		Expect(SendPTOAppData.String()).To(Equal("pto (Application Data)"))
		Expect(SendMode(123).String()).To(Equal("invalid send mode: 123"))
	})
})
