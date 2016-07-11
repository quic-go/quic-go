package quic

import (
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
		_, err := m.GetStream(1)
		Expect(err).To(MatchError("unknown stream: 1"))
	})

	It("returns nil for previously existing streams", func() {
		err := m.PutStream(&stream{streamID: 1})
		Expect(err).NotTo(HaveOccurred())
		err = m.RemoveStream(1)
		Expect(err).NotTo(HaveOccurred())
		s, err := m.GetStream(1)
		Expect(err).NotTo(HaveOccurred())
		Expect(s).To(BeNil())
	})

	It("errors when removing non-existing stream", func() {
		err := m.RemoveStream(1)
		Expect(err).To(MatchError("attempted to remove non-existing stream: 1"))
	})

	It("stores streams", func() {
		err := m.PutStream(&stream{streamID: 5})
		Expect(err).NotTo(HaveOccurred())
		s, err := m.GetStream(5)
		Expect(err).NotTo(HaveOccurred())
		Expect(s.streamID).To(Equal(protocol.StreamID(5)))
	})

	It("does not store multiple streams with the same ID", func() {
		err := m.PutStream(&stream{streamID: 5})
		Expect(err).NotTo(HaveOccurred())
		err = m.PutStream(&stream{streamID: 5})
		Expect(err).To(MatchError("a stream with ID 5 already exists"))
	})

	It("gets the number of streams", func() {
		Expect(m.NumberOfStreams()).To(Equal(0))
		m.PutStream(&stream{streamID: 5})
		Expect(m.NumberOfStreams()).To(Equal(1))
		m.RemoveStream(5)
		Expect(m.NumberOfStreams()).To(Equal(0))
	})
})
