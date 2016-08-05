package quic

import (
	"errors"

	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Streams Map", func() {
	var (
		m *streamsMap
	)

	BeforeEach(func() {
		m = newStreamsMap()
	})

	It("returns an error for non-existant streams", func() {
		_, exists := m.GetStream(1)
		Expect(exists).To(BeFalse())
	})

	It("returns nil for previously existing streams", func() {
		err := m.PutStream(&stream{streamID: 1})
		Expect(err).NotTo(HaveOccurred())
		err = m.RemoveStream(1)
		Expect(err).NotTo(HaveOccurred())
		s, exists := m.GetStream(1)
		Expect(exists).To(BeTrue())
		Expect(s).To(BeNil())
	})

	Context("putting streams", func() {
		It("stores streams", func() {
			err := m.PutStream(&stream{streamID: 5})
			Expect(err).NotTo(HaveOccurred())
			s, exists := m.GetStream(5)
			Expect(exists).To(BeTrue())
			Expect(s.streamID).To(Equal(protocol.StreamID(5)))
			Expect(m.openStreams).To(HaveLen(1))
			Expect(m.openStreams[0]).To(Equal(protocol.StreamID(5)))
		})

		It("does not store multiple streams with the same ID", func() {
			err := m.PutStream(&stream{streamID: 5})
			Expect(err).NotTo(HaveOccurred())
			err = m.PutStream(&stream{streamID: 5})
			Expect(err).To(MatchError("a stream with ID 5 already exists"))
			Expect(m.openStreams).To(HaveLen(1))
		})
	})

	Context("deleting streams", func() {
		BeforeEach(func() {
			for i := 1; i <= 5; i++ {
				err := m.PutStream(&stream{streamID: protocol.StreamID(i)})
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(m.openStreams).To(Equal([]protocol.StreamID{1, 2, 3, 4, 5}))
		})

		It("errors when removing non-existing stream", func() {
			err := m.RemoveStream(1337)
			Expect(err).To(MatchError("attempted to remove non-existing stream: 1337"))
		})

		It("removes the first stream", func() {
			err := m.RemoveStream(1)
			Expect(err).ToNot(HaveOccurred())
			Expect(m.openStreams).To(HaveLen(4))
			Expect(m.openStreams).To(Equal([]protocol.StreamID{2, 3, 4, 5}))
		})

		It("removes a stream in the middle", func() {
			err := m.RemoveStream(3)
			Expect(err).ToNot(HaveOccurred())
			Expect(m.openStreams).To(HaveLen(4))
			Expect(m.openStreams).To(Equal([]protocol.StreamID{1, 2, 4, 5}))
		})

		It("removes a stream at the end", func() {
			err := m.RemoveStream(5)
			Expect(err).ToNot(HaveOccurred())
			Expect(m.openStreams).To(HaveLen(4))
			Expect(m.openStreams).To(Equal([]protocol.StreamID{1, 2, 3, 4}))
		})

		It("removes all streams", func() {
			for i := 1; i <= 5; i++ {
				err := m.RemoveStream(protocol.StreamID(i))
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(m.openStreams).To(BeEmpty())
		})
	})

	Context("number of streams", func() {
		It("returns 0 in the beginning", func() {
			Expect(m.NumberOfStreams()).To(Equal(0))
		})

		It("increases the counter when a new stream is added", func() {
			err := m.PutStream(&stream{streamID: 5})
			Expect(err).ToNot(HaveOccurred())
			Expect(m.NumberOfStreams()).To(Equal(1))
		})

		It("decreases the counter when removing a stream", func() {
			err := m.PutStream(&stream{streamID: 5})
			Expect(err).ToNot(HaveOccurred())
			err = m.RemoveStream(5)
			Expect(err).ToNot(HaveOccurred())
			Expect(m.NumberOfStreams()).To(BeZero())
		})
	})

	Context("Lambda", func() {
		// create 5 streams, ids 1 to 3
		BeforeEach(func() {
			for i := 1; i <= 3; i++ {
				err := m.PutStream(&stream{streamID: protocol.StreamID(i)})
				Expect(err).NotTo(HaveOccurred())
			}
		})

		It("executes the lambda exactly once for every stream", func() {
			var numIterations int
			callbackCalled := make(map[protocol.StreamID]bool)
			fn := func(str *stream) (bool, error) {
				callbackCalled[str.StreamID()] = true
				numIterations++
				return true, nil
			}
			err := m.Iterate(fn)
			Expect(err).ToNot(HaveOccurred())
			Expect(callbackCalled).To(HaveKey(protocol.StreamID(1)))
			Expect(callbackCalled).To(HaveKey(protocol.StreamID(2)))
			Expect(callbackCalled).To(HaveKey(protocol.StreamID(3)))
			Expect(numIterations).To(Equal(3))
		})

		It("stops iterating when the callback returns false", func() {
			var numIterations int
			fn := func(str *stream) (bool, error) {
				numIterations++
				return false, nil
			}
			err := m.Iterate(fn)
			Expect(err).ToNot(HaveOccurred())
			// due to map access randomization, we don't know for which stream the callback was executed
			// but it must only be executed once
			Expect(numIterations).To(Equal(1))
		})

		It("returns the error, if the lambda returns one", func() {
			var numIterations int
			expectedError := errors.New("test")
			fn := func(str *stream) (bool, error) {
				numIterations++
				return true, expectedError
			}
			err := m.Iterate(fn)
			Expect(err).To(MatchError(expectedError))
			Expect(numIterations).To(Equal(1))
		})
	})
})
