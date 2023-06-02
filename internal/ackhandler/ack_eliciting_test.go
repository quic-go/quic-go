package ackhandler

import (
	"reflect"

	"github.com/quic-go/quic-go/internal/wire"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ack-eliciting frames", func() {
	for fl, el := range map[wire.Frame]bool{
		&wire.AckFrame{}:             false,
		&wire.ConnectionCloseFrame{}: false,
		&wire.DataBlockedFrame{}:     true,
		&wire.PingFrame{}:            true,
		&wire.ResetStreamFrame{}:     true,
		&wire.StreamFrame{}:          true,
		&wire.MaxDataFrame{}:         true,
		&wire.MaxStreamDataFrame{}:   true,
	} {
		f := fl
		e := el
		fName := reflect.ValueOf(f).Elem().Type().Name()

		It("works for "+fName, func() {
			Expect(IsFrameAckEliciting(f)).To(Equal(e))
		})

		It("HasAckElicitingFrames works for "+fName, func() {
			Expect(HasAckElicitingFrames([]Frame{{Frame: f}})).To(Equal(e))
		})
	}
})
