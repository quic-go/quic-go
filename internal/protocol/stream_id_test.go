package protocol

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stream ID", func() {
	It("says who initiated a stream", func() {
		Expect(StreamID(4).InitiatedBy()).To(Equal(PerspectiveClient))
		Expect(StreamID(5).InitiatedBy()).To(Equal(PerspectiveServer))
		Expect(StreamID(6).InitiatedBy()).To(Equal(PerspectiveClient))
		Expect(StreamID(7).InitiatedBy()).To(Equal(PerspectiveServer))
	})

	It("tells the directionality", func() {
		Expect(StreamID(4).Type()).To(Equal(StreamTypeBidi))
		Expect(StreamID(5).Type()).To(Equal(StreamTypeBidi))
		Expect(StreamID(6).Type()).To(Equal(StreamTypeUni))
		Expect(StreamID(7).Type()).To(Equal(StreamTypeUni))
	})

	It("tells the first stream ID", func() {
		Expect(FirstStream(StreamTypeBidi, PerspectiveClient)).To(Equal(StreamID(0)))
		Expect(FirstStream(StreamTypeBidi, PerspectiveServer)).To(Equal(StreamID(1)))
		Expect(FirstStream(StreamTypeUni, PerspectiveClient)).To(Equal(StreamID(2)))
		Expect(FirstStream(StreamTypeUni, PerspectiveServer)).To(Equal(StreamID(3)))
	})

	It("tells the stream number", func() {
		Expect(StreamID(0).StreamNum()).To(BeEquivalentTo(1))
		Expect(StreamID(1).StreamNum()).To(BeEquivalentTo(1))
		Expect(StreamID(2).StreamNum()).To(BeEquivalentTo(1))
		Expect(StreamID(3).StreamNum()).To(BeEquivalentTo(1))
		Expect(StreamID(8).StreamNum()).To(BeEquivalentTo(3))
		Expect(StreamID(9).StreamNum()).To(BeEquivalentTo(3))
		Expect(StreamID(10).StreamNum()).To(BeEquivalentTo(3))
		Expect(StreamID(11).StreamNum()).To(BeEquivalentTo(3))
	})

	Context("maximum stream IDs", func() {
		It("doesn't allow any", func() {
			Expect(MaxStreamID(StreamTypeBidi, 0, PerspectiveClient)).To(Equal(StreamID(0)))
			Expect(MaxStreamID(StreamTypeBidi, 0, PerspectiveServer)).To(Equal(StreamID(0)))
			Expect(MaxStreamID(StreamTypeUni, 0, PerspectiveClient)).To(Equal(StreamID(0)))
			Expect(MaxStreamID(StreamTypeUni, 0, PerspectiveServer)).To(Equal(StreamID(0)))
		})

		It("allows one", func() {
			Expect(MaxStreamID(StreamTypeBidi, 1, PerspectiveClient)).To(Equal(StreamID(0)))
			Expect(MaxStreamID(StreamTypeBidi, 1, PerspectiveServer)).To(Equal(StreamID(1)))
			Expect(MaxStreamID(StreamTypeUni, 1, PerspectiveClient)).To(Equal(StreamID(2)))
			Expect(MaxStreamID(StreamTypeUni, 1, PerspectiveServer)).To(Equal(StreamID(3)))
		})

		It("allows many", func() {
			Expect(MaxStreamID(StreamTypeBidi, 100, PerspectiveClient)).To(Equal(StreamID(396)))
			Expect(MaxStreamID(StreamTypeBidi, 100, PerspectiveServer)).To(Equal(StreamID(397)))
			Expect(MaxStreamID(StreamTypeUni, 100, PerspectiveClient)).To(Equal(StreamID(398)))
			Expect(MaxStreamID(StreamTypeUni, 100, PerspectiveServer)).To(Equal(StreamID(399)))
		})
	})
})
