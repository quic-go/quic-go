package quic

import (
	"github.com/lucas-clemente/quic-go/frames"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("StreamFrame sorter", func() {
	var (
		s streamFrameSorter
	)

	BeforeEach(func() {
		s = streamFrameSorter{}
	})

	It("head returns nil when empty", func() {
		Expect(s.Head()).To(BeNil())
	})

	It("inserts and pops a single frame", func() {
		f := &frames.StreamFrame{}
		s.Push(f)
		Expect(s.Head()).To(Equal(f))
		Expect(s.Pop()).To(Equal(f))
		Expect(s.Head()).To(BeNil())
	})

	It("inserts two frames in order", func() {
		f1 := &frames.StreamFrame{Offset: 1}
		f2 := &frames.StreamFrame{Offset: 2}
		s.Push(f1)
		s.Push(f2)
		Expect(s.Pop()).To(Equal(f1))
		Expect(s.Pop()).To(Equal(f2))
		Expect(s.Head()).To(BeNil())
	})

	It("inserts two frames out of order", func() {
		f1 := &frames.StreamFrame{Offset: 1}
		f2 := &frames.StreamFrame{Offset: 2}
		s.Push(f2)
		s.Push(f1)
		Expect(s.Pop()).To(Equal(f1))
		Expect(s.Pop()).To(Equal(f2))
		Expect(s.Head()).To(BeNil())
	})
})
