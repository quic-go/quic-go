package quic

import (
	"errors"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Streams Map (outgoing)", func() {
	const firstNewStream protocol.StreamID = 10
	var (
		m       *outgoingItemsMap
		newItem func(id protocol.StreamID) item
	)

	BeforeEach(func() {
		newItem = func(id protocol.StreamID) item {
			return id
		}
		m = newOutgoingItemsMap(firstNewStream, newItem)
	})

	It("opens streams", func() {
		str, err := m.OpenStream()
		Expect(err).ToNot(HaveOccurred())
		Expect(str).To(Equal(firstNewStream))
		str, err = m.OpenStream()
		Expect(err).ToNot(HaveOccurred())
		Expect(str).To(Equal(firstNewStream + 4))
	})

	It("doesn't open streams after it has been closed", func() {
		testErr := errors.New("close")
		m.CloseWithError(testErr)
		_, err := m.OpenStream()
		Expect(err).To(MatchError(testErr))
	})

	It("gets streams", func() {
		_, err := m.OpenStream()
		Expect(err).ToNot(HaveOccurred())
		str, err := m.GetStream(firstNewStream)
		Expect(err).ToNot(HaveOccurred())
		Expect(str).To(Equal(firstNewStream))
	})

	It("errors when trying to get a stream that has not yet been opened", func() {
		_, err := m.GetStream(10)
		Expect(err).To(MatchError(qerr.Error(qerr.InvalidStreamID, "peer attempted to open stream 10")))
	})

	It("deletes streams", func() {
		_, err := m.OpenStream() // opens stream 10
		Expect(err).ToNot(HaveOccurred())
		err = m.DeleteStream(10)
		Expect(err).ToNot(HaveOccurred())
		str, err := m.GetStream(10)
		Expect(err).ToNot(HaveOccurred())
		Expect(str).To(BeNil())
	})

	It("errors when deleting a non-existing stream", func() {
		err := m.DeleteStream(1337)
		Expect(err).To(MatchError("Tried to delete unknown stream 1337"))
	})

	It("errors when deleting a stream twice", func() {
		_, err := m.OpenStream() // opens stream 10
		Expect(err).ToNot(HaveOccurred())
		err = m.DeleteStream(10)
		Expect(err).ToNot(HaveOccurred())
		err = m.DeleteStream(10)
		Expect(err).To(MatchError("Tried to delete unknown stream 10"))
	})
})
