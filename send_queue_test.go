package quic

import (
	"errors"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Send Queue", func() {
	var q sender
	var c *MockSendConn

	BeforeEach(func() {
		c = NewMockSendConn(mockCtrl)
		q = newSendQueue(c)
	})

	getPacket := func(b []byte) *packetBuffer {
		buf := getPacketBuffer()
		buf.Data = buf.Data[:len(b)]
		copy(buf.Data, b)
		return buf
	}

	It("sends a packet", func() {
		p := getPacket([]byte("foobar"))
		q.Send(p)

		written := make(chan struct{})
		c.EXPECT().Write([]byte("foobar")).Do(func([]byte) { close(written) })
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

	It("panics when Send() is called although there's no space in the queue", func() {
		for i := 0; i < sendQueueCapacity; i++ {
			Expect(q.WouldBlock()).To(BeFalse())
			q.Send(getPacket([]byte("foobar")))
		}
		Expect(q.WouldBlock()).To(BeTrue())
		Expect(func() { q.Send(getPacket([]byte("raboof"))) }).To(Panic())
	})

	It("signals when sending is possible again", func() {
		Expect(q.WouldBlock()).To(BeFalse())
		q.Send(getPacket([]byte("foobar1")))
		Consistently(q.Available()).ShouldNot(Receive())

		// now start sending out packets. This should free up queue space.
		c.EXPECT().Write(gomock.Any()).MinTimes(1).MaxTimes(2)
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			q.Run()
			close(done)
		}()

		Eventually(q.Available()).Should(Receive())
		Expect(q.WouldBlock()).To(BeFalse())
		Expect(func() { q.Send(getPacket([]byte("foobar2"))) }).ToNot(Panic())

		q.Close()
		Eventually(done).Should(BeClosed())
	})

	It("does not block pending send after the queue has stopped running", func() {
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			q.Run()
			close(done)
		}()

		// the run loop exits if there is a write error
		testErr := errors.New("test error")
		c.EXPECT().Write(gomock.Any()).Return(testErr)
		q.Send(getPacket([]byte("foobar")))
		Eventually(done).Should(BeClosed())

		sent := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			q.Send(getPacket([]byte("raboof")))
			q.Send(getPacket([]byte("quux")))
			close(sent)
		}()

		Eventually(sent).Should(BeClosed())
	})

	It("blocks Close() until the packet has been sent out", func() {
		written := make(chan []byte)
		c.EXPECT().Write(gomock.Any()).Do(func(p []byte) { written <- p })
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			q.Run()
			close(done)
		}()

		q.Send(getPacket([]byte("foobar")))

		closed := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			q.Close()
			close(closed)
		}()

		Consistently(closed).ShouldNot(BeClosed())
		// now write the packet
		Expect(written).To(Receive())
		Eventually(done).Should(BeClosed())
		Eventually(closed).Should(BeClosed())
	})
})
