package quic

import (
	"context"
	"time"

	"golang.org/x/exp/rand"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Streams Map (incoming)", func() {
	var (
		m                   *incomingStreamsMap[*mockGenericStream]
		newItemCounter      int
		maxNumStreams       uint64
		queuedControlFrames []wire.Frame
	)
	streamType := []protocol.StreamType{protocol.StreamTypeUni, protocol.StreamTypeUni}[rand.Intn(2)]

	// check that the frame can be serialized and deserialized
	checkFrameSerialization := func(f wire.Frame) {
		b, err := f.Append(nil, protocol.Version1)
		ExpectWithOffset(1, err).ToNot(HaveOccurred())
		_, frame, err := wire.NewFrameParser(false).ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		ExpectWithOffset(1, err).ToNot(HaveOccurred())
		Expect(f).To(Equal(frame))
	}

	BeforeEach(func() { maxNumStreams = 5 })

	JustBeforeEach(func() {
		queuedControlFrames = []wire.Frame{}
		newItemCounter = 0
		m = newIncomingStreamsMap(
			streamType,
			func(num protocol.StreamNum) *mockGenericStream {
				newItemCounter++
				return &mockGenericStream{num: num}
			},
			maxNumStreams,
			func(f wire.Frame) { queuedControlFrames = append(queuedControlFrames, f) },
		)
	})

	It("deletes streams", func() {
		_, err := m.GetOrOpenStream(1)
		Expect(err).ToNot(HaveOccurred())
		str, err := m.AcceptStream(context.Background())
		Expect(err).ToNot(HaveOccurred())
		Expect(str.num).To(Equal(protocol.StreamNum(1)))
		Expect(m.DeleteStream(1)).To(Succeed())
		str, err = m.GetOrOpenStream(1)
		Expect(err).ToNot(HaveOccurred())
		Expect(str).To(BeNil())
	})

	It("waits until a stream is accepted before actually deleting it", func() {
		_, err := m.GetOrOpenStream(2)
		Expect(err).ToNot(HaveOccurred())
		Expect(m.DeleteStream(2)).To(Succeed())
		str, err := m.AcceptStream(context.Background())
		Expect(err).ToNot(HaveOccurred())
		Expect(str.num).To(Equal(protocol.StreamNum(1)))
		// when accepting this stream, it will get deleted, and a MAX_STREAMS frame is queued
		str, err = m.AcceptStream(context.Background())
		Expect(err).ToNot(HaveOccurred())
		Expect(str.num).To(Equal(protocol.StreamNum(2)))
	})

	It("doesn't return a stream queued for deleting from GetOrOpenStream", func() {
		str, err := m.GetOrOpenStream(1)
		Expect(err).ToNot(HaveOccurred())
		Expect(str).ToNot(BeNil())
		Expect(m.DeleteStream(1)).To(Succeed())
		str, err = m.GetOrOpenStream(1)
		Expect(err).ToNot(HaveOccurred())
		Expect(str).To(BeNil())
		// when accepting this stream, it will get deleted, and a MAX_STREAMS frame is queued
		str, err = m.AcceptStream(context.Background())
		Expect(err).ToNot(HaveOccurred())
		Expect(str).ToNot(BeNil())
	})

	It("errors when deleting a non-existing stream", func() {
		err := m.DeleteStream(1337)
		Expect(err).To(HaveOccurred())
		Expect(err.(streamError).TestError()).To(MatchError("tried to delete unknown incoming stream 1337"))
	})

	It("sends MAX_STREAMS frames when streams are deleted", func() {
		// open a bunch of streams
		_, err := m.GetOrOpenStream(5)
		Expect(err).ToNot(HaveOccurred())
		// accept all streams
		for i := 0; i < 5; i++ {
			_, err := m.AcceptStream(context.Background())
			Expect(err).ToNot(HaveOccurred())
		}
		Expect(queuedControlFrames).To(BeEmpty())
		Expect(m.DeleteStream(3)).To(Succeed())
		Expect(queuedControlFrames).To(HaveLen(1))
		msf := queuedControlFrames[0].(*wire.MaxStreamsFrame)
		Expect(msf.Type).To(BeEquivalentTo(streamType))
		Expect(msf.MaxStreamNum).To(Equal(protocol.StreamNum(maxNumStreams + 1)))
		checkFrameSerialization(msf)
		Expect(m.DeleteStream(4)).To(Succeed())
		Expect(queuedControlFrames).To(HaveLen(2))
		Expect(queuedControlFrames[1].(*wire.MaxStreamsFrame).MaxStreamNum).To(Equal(protocol.StreamNum(maxNumStreams + 2)))
		checkFrameSerialization(queuedControlFrames[1])
	})

	Context("using high stream limits", func() {
		BeforeEach(func() { maxNumStreams = uint64(protocol.MaxStreamCount) - 2 })

		It("doesn't send MAX_STREAMS frames if they would overflow 2^60 (the maximum stream count)", func() {
			// open a bunch of streams
			_, err := m.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			// accept all streams
			for i := 0; i < 5; i++ {
				_, err := m.AcceptStream(context.Background())
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(queuedControlFrames).To(BeEmpty())
			Expect(m.DeleteStream(4)).To(Succeed())
			Expect(queuedControlFrames).To(HaveLen(1))
			Expect(queuedControlFrames[0].(*wire.MaxStreamsFrame).MaxStreamNum).To(Equal(protocol.MaxStreamCount - 1))
			checkFrameSerialization(queuedControlFrames[0])
			Expect(m.DeleteStream(3)).To(Succeed())
			Expect(queuedControlFrames).To(HaveLen(2))
			Expect(queuedControlFrames[1].(*wire.MaxStreamsFrame).MaxStreamNum).To(Equal(protocol.MaxStreamCount))
			checkFrameSerialization(queuedControlFrames[1])
			// at this point, we can't increase the stream limit any further, so no more MAX_STREAMS frames will be sent
			Expect(m.DeleteStream(2)).To(Succeed())
			Expect(m.DeleteStream(1)).To(Succeed())
			Expect(queuedControlFrames).To(HaveLen(2))
		})
	})

	Context("randomized tests", func() {
		const num = 1000

		BeforeEach(func() { maxNumStreams = num })

		It("opens and accepts streams", func() {
			rand.Seed(uint64(GinkgoRandomSeed()))
			ids := make([]protocol.StreamNum, num)
			for i := 0; i < num; i++ {
				ids[i] = protocol.StreamNum(i + 1)
			}
			rand.Shuffle(len(ids), func(i, j int) { ids[i], ids[j] = ids[j], ids[i] })

			const timeout = 5 * time.Second
			done := make(chan struct{}, 2)
			go func() {
				defer GinkgoRecover()
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()
				for i := 0; i < num; i++ {
					_, err := m.AcceptStream(ctx)
					Expect(err).ToNot(HaveOccurred())
				}
				done <- struct{}{}
			}()

			go func() {
				defer GinkgoRecover()
				for i := 0; i < num; i++ {
					_, err := m.GetOrOpenStream(ids[i])
					Expect(err).ToNot(HaveOccurred())
				}
				done <- struct{}{}
			}()

			Eventually(done, timeout*3/2).Should(Receive())
			Eventually(done, timeout*3/2).Should(Receive())
		})
	})
})
