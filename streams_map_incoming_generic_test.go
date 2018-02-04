package quic

import (
	"errors"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Streams Map (outgoing)", func() {
	const (
		firstNewStream protocol.StreamID = 20
		maxStream      protocol.StreamID = firstNewStream + 4*100
	)

	var (
		m              *incomingItemsMap
		newItem        func(id protocol.StreamID) item
		newItemCounter int
	)

	BeforeEach(func() {
		newItemCounter = 0
		newItem = func(id protocol.StreamID) item {
			newItemCounter++
			return id
		}
		m = newIncomingItemsMap(firstNewStream, maxStream, newItem)
	})

	It("opens all streams up to the id on GetOrOpenStream", func() {
		_, err := m.GetOrOpenStream(firstNewStream + 4*5)
		Expect(err).ToNot(HaveOccurred())
		Expect(newItemCounter).To(Equal(6))
	})

	It("starts opening streams at the right position", func() {
		// like the test above, but with 2 calls to GetOrOpenStream
		_, err := m.GetOrOpenStream(firstNewStream + 4)
		Expect(err).ToNot(HaveOccurred())
		Expect(newItemCounter).To(Equal(2))
		_, err = m.GetOrOpenStream(firstNewStream + 4*5)
		Expect(err).ToNot(HaveOccurred())
		Expect(newItemCounter).To(Equal(6))
	})

	It("accepts streams in the right order", func() {
		_, err := m.GetOrOpenStream(firstNewStream + 4) // open stream 20 and 24
		Expect(err).ToNot(HaveOccurred())
		str, err := m.AcceptStream()
		Expect(err).ToNot(HaveOccurred())
		Expect(str).To(Equal(firstNewStream))
		str, err = m.AcceptStream()
		Expect(err).ToNot(HaveOccurred())
		Expect(str).To(Equal(firstNewStream + 4))
	})

	It("allows opening the maximum stream ID", func() {
		str, err := m.GetOrOpenStream(maxStream)
		Expect(err).ToNot(HaveOccurred())
		Expect(str).To(Equal(maxStream))
	})

	It("errors when trying to get a stream ID higher than the maximum", func() {
		_, err := m.GetOrOpenStream(maxStream + 4)
		Expect(err).To(MatchError(fmt.Errorf("peer tried to open stream %d (current limit: %d)", maxStream+4, maxStream)))
	})

	It("blocks AcceptStream until a new stream is available", func() {
		strChan := make(chan item)
		go func() {
			defer GinkgoRecover()
			str, err := m.AcceptStream()
			Expect(err).ToNot(HaveOccurred())
			strChan <- str
		}()
		Consistently(strChan).ShouldNot(Receive())
		str, err := m.GetOrOpenStream(firstNewStream)
		Expect(err).ToNot(HaveOccurred())
		Expect(str).To(Equal(firstNewStream))
		Eventually(strChan).Should(Receive(Equal(firstNewStream)))
	})

	It("unblocks AcceptStream when it is closed", func() {
		testErr := errors.New("test error")
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			_, err := m.AcceptStream()
			Expect(err).To(MatchError(testErr))
			close(done)
		}()
		Consistently(done).ShouldNot(BeClosed())
		m.CloseWithError(testErr)
		Eventually(done).Should(BeClosed())
	})

	It("errors AcceptStream immediately if it is closed", func() {
		testErr := errors.New("test error")
		m.CloseWithError(testErr)
		_, err := m.AcceptStream()
		Expect(err).To(MatchError(testErr))
	})

	It("deletes streams", func() {
		_, err := m.GetOrOpenStream(20)
		Expect(err).ToNot(HaveOccurred())
		err = m.DeleteStream(20)
		Expect(err).ToNot(HaveOccurred())
		str, err := m.GetOrOpenStream(20)
		Expect(err).ToNot(HaveOccurred())
		Expect(str).To(BeNil())
	})

	It("errors when deleting a non-existing stream", func() {
		err := m.DeleteStream(1337)
		Expect(err).To(MatchError("Tried to delete unknown stream 1337"))
	})
})
