package wire

import (
	"math/rand"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ACK Frame (for IETF QUIC)", func() {
	It("gets an ACK frame from the pool", func() {
		for i := 0; i < 100; i++ {
			ack := GetAckFrame()
			Expect(ack.AckRanges).To(BeEmpty())
			Expect(ack.ECNCE).To(BeZero())
			Expect(ack.ECT0).To(BeZero())
			Expect(ack.ECT1).To(BeZero())
			Expect(ack.DelayTime).To(BeZero())

			ack.AckRanges = make([]AckRange, rand.Intn(10))
			ack.ECNCE = 1
			ack.ECT0 = 2
			ack.ECT1 = 3
			ack.DelayTime = time.Hour
			PutAckFrame(ack)
		}
	})
})
