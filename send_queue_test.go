package quic

import (
	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Send Queue", func() {
	var q *sendQueue
	var c *MockConnection
	var availableChan <-chan struct{}

	BeforeEach(func() {
		c = NewMockConnection(mockCtrl)
		q, availableChan = newSendQueue(c)
		_ = availableChan
	})

	getPacket := func(b []byte) *packedPacket {
		buf := getPacketBuffer()
		buf.Slice = buf.Slice[:len(b)]
		copy(buf.Slice, b)
		return &packedPacket{
			buffer: buf,
			raw:    buf.Slice,
		}
	}

	It("sends a packet", func() {
		p := getPacket([]byte("foobar"))
		q.Send(p)

		written := make(chan struct{})
		c.EXPECT().Write(p.raw).Do(func([]byte) { close(written) })
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			q.Run()
			close(done)
		}()

		Eventually(written).Should(BeClosed())
		q.Close()
		Eventually(done).Should(BeClosed())
	})

	It("says when the send queue is full", func() {
		for i := 0; i < sendQueueCapacity; i++ {
			Expect(q.CanSend()).To(BeTrue())
			q.Send(getPacket([]byte("foobar")))
		}
		Expect(q.CanSend()).To(BeFalse())
	})

	It("notifies when the send queue frees up", func() {
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			q.Run()
		}()

		write := make(chan struct{}, 2)
		unblockWrite := make(chan struct{})
		c.EXPECT().Write(gomock.Any()).Do(func([]byte) {
			write <- struct{}{}
			<-unblockWrite
		}).Times(2)
		// send the first packet and make sure the write call blocks
		q.Send(getPacket([]byte("foobar")))
		Eventually(write).Should(HaveLen(1))
		// now completely fill up the queue
		for i := 0; i < sendQueueCapacity; i++ {
			Eventually(q.CanSend()).Should(BeTrue())
			q.Send(getPacket([]byte("foobar")))
		}
		Expect(q.CanSend()).To(BeFalse())
		Expect(availableChan).ToNot(Receive())

		// make the connection send out one packet
		unblockWrite <- struct{}{}
		Eventually(availableChan).Should(Receive())
		Expect(q.CanSend()).To(BeTrue())

		// make the go routine return
		c.EXPECT().Write(gomock.Any()).AnyTimes()
		unblockWrite <- struct{}{}
		q.Close()
		Eventually(done).Should(BeClosed())
	})

	It("panics a packet is enqueued when the queue is already full", func() {
		for i := 0; i < sendQueueCapacity; i++ {
			q.Send(getPacket([]byte("foobar")))
		}
		Expect(func() { q.Send(getPacket([]byte("foobar"))) }).To(Panic())
	})
})
