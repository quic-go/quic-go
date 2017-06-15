package ackhandler

import (
	"reflect"

	"github.com/lucas-clemente/quic-go/frames"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("retransmittable frames", func() {
	for fl, el := range map[frames.Frame]bool{
		&frames.AckFrame{}:             false,
		&frames.StopWaitingFrame{}:     false,
		&frames.BlockedFrame{}:         true,
		&frames.ConnectionCloseFrame{}: true,
		&frames.GoawayFrame{}:          true,
		&frames.PingFrame{}:            true,
		&frames.RstStreamFrame{}:       true,
		&frames.StreamFrame{}:          true,
		&frames.WindowUpdateFrame{}:    true,
	} {
		f := fl
		e := el
		fName := reflect.ValueOf(f).Elem().Type().Name()

		It("works for "+fName, func() {
			Expect(IsFrameRetransmittable(f)).To(Equal(e))
		})

		It("stripping non-retransmittable frames works for "+fName, func() {
			s := []frames.Frame{f}
			if e {
				Expect(stripNonRetransmittableFrames(s)).To(Equal([]frames.Frame{f}))
			} else {
				Expect(stripNonRetransmittableFrames(s)).To(BeEmpty())
			}
		})

		It("HasRetransmittableFrames works for "+fName, func() {
			Expect(HasRetransmittableFrames([]frames.Frame{f})).To(Equal(e))
		})
	}
})
