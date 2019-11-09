package protocol

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stream ID", func() {
	It("InvalidStreamID is smaller than all valid stream IDs", func() {
		Expect(InvalidStreamID).To(BeNumerically("<", 0))
	})

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

	Context("converting stream nums to stream IDs", func() {
		It("handles 0", func() {
			Expect(StreamNum(0).StreamID(StreamTypeBidi, PerspectiveClient)).To(Equal(InvalidStreamID))
			Expect(StreamNum(0).StreamID(StreamTypeBidi, PerspectiveServer)).To(Equal(InvalidStreamID))
			Expect(StreamNum(0).StreamID(StreamTypeUni, PerspectiveClient)).To(Equal(InvalidStreamID))
			Expect(StreamNum(0).StreamID(StreamTypeUni, PerspectiveServer)).To(Equal(InvalidStreamID))
		})

		It("handles the first", func() {
			Expect(StreamNum(1).StreamID(StreamTypeBidi, PerspectiveClient)).To(Equal(StreamID(0)))
			Expect(StreamNum(1).StreamID(StreamTypeBidi, PerspectiveServer)).To(Equal(StreamID(1)))
			Expect(StreamNum(1).StreamID(StreamTypeUni, PerspectiveClient)).To(Equal(StreamID(2)))
			Expect(StreamNum(1).StreamID(StreamTypeUni, PerspectiveServer)).To(Equal(StreamID(3)))
		})

		It("handles others", func() {
			Expect(StreamNum(100).StreamID(StreamTypeBidi, PerspectiveClient)).To(Equal(StreamID(396)))
			Expect(StreamNum(100).StreamID(StreamTypeBidi, PerspectiveServer)).To(Equal(StreamID(397)))
			Expect(StreamNum(100).StreamID(StreamTypeUni, PerspectiveClient)).To(Equal(StreamID(398)))
			Expect(StreamNum(100).StreamID(StreamTypeUni, PerspectiveServer)).To(Equal(StreamID(399)))
		})

		It("has the right value for MaxStreamCount", func() {
			const maxStreamID = StreamID(1<<62 - 1)
			for _, dir := range []StreamType{StreamTypeUni, StreamTypeBidi} {
				for _, pers := range []Perspective{PerspectiveClient, PerspectiveServer} {
					Expect(MaxStreamCount.StreamID(dir, pers)).To(BeNumerically("<=", maxStreamID))
					Expect((MaxStreamCount + 1).StreamID(dir, pers)).To(BeNumerically(">", maxStreamID))
				}
			}
		})
	})
})
