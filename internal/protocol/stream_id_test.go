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

	Context("maximum stream IDs", func() {
		Context("bidirectional streams", func() {
			It("doesn't allow any", func() {
				Expect(MaxBidiStreamID(0, PerspectiveClient)).To(Equal(StreamID(0)))
				Expect(MaxBidiStreamID(0, PerspectiveServer)).To(Equal(StreamID(0)))
			})

			It("allows one", func() {
				Expect(MaxBidiStreamID(1, PerspectiveClient)).To(Equal(StreamID(1)))
				Expect(MaxBidiStreamID(1, PerspectiveServer)).To(Equal(StreamID(0)))
			})

			It("allows many", func() {
				Expect(MaxBidiStreamID(100, PerspectiveClient)).To(Equal(StreamID(397)))
				Expect(MaxBidiStreamID(100, PerspectiveServer)).To(Equal(StreamID(396)))
			})
		})

		Context("unidirectional streams", func() {
			It("doesn't allow any", func() {
				Expect(MaxUniStreamID(0, PerspectiveClient)).To(Equal(StreamID(0)))
				Expect(MaxUniStreamID(0, PerspectiveServer)).To(Equal(StreamID(0)))
			})

			It("allows one", func() {
				Expect(MaxUniStreamID(1, PerspectiveClient)).To(Equal(StreamID(3)))
				Expect(MaxUniStreamID(1, PerspectiveServer)).To(Equal(StreamID(2)))
			})

			It("allows many", func() {
				Expect(MaxUniStreamID(100, PerspectiveClient)).To(Equal(StreamID(399)))
				Expect(MaxUniStreamID(100, PerspectiveServer)).To(Equal(StreamID(398)))
			})
		})
	})
})
