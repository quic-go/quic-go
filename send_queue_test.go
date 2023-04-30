package quic

import (
	"errors"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
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
		q.Send(p, 10) // make sure the packet size is passed through to the conn

		written := make(chan struct{})
		c.EXPECT().Write([]byte("foobar"), protocol.ByteCount(10)).Do(func([]byte, protocol.ByteCount) { close(written) })
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
			q.Send(getPacket([]byte("foobar")), 6)
		}
		Expect(q.WouldBlock()).To(BeTrue())
		Expect(func() { q.Send(getPacket([]byte("raboof")), 6) }).To(Panic())
	})

	It("signals when sending is possible again", func() {
		Expect(q.WouldBlock()).To(BeFalse())
		q.Send(getPacket([]byte("foobar1")), 6)
		Consistently(q.Available()).ShouldNot(Receive())

		// now start sending out packets. This should free up queue space.
		c.EXPECT().Write(gomock.Any(), gomock.Any()).MinTimes(1).MaxTimes(2)
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			q.Run()
			close(done)
		}()

		Eventually(q.Available()).Should(Receive())
		Expect(q.WouldBlock()).To(BeFalse())
		Expect(func() { q.Send(getPacket([]byte("foobar2")), 7) }).ToNot(Panic())

		q.Close()
		Eventually(done).Should(BeClosed())
	})

	It("signals when sending is possible again, when the first write succeeded", func() {
		write := make(chan struct{}, 1)
		written := make(chan struct{}, 100)
		// now start sending out packets. This should free up queue space.
		c.EXPECT().Write(gomock.Any(), gomock.Any()).DoAndReturn(func([]byte, protocol.ByteCount) error {
			written <- struct{}{}
			<-write
			return nil
		}).AnyTimes()
		// allow the first packet to be sent immediately
		write <- struct{}{}

		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			q.Run()
			close(done)
		}()

		q.Send(getPacket([]byte("foobar")), 6)
		<-written

		// now fill up the send queue
		for i := 0; i < sendQueueCapacity; i++ {
			Expect(q.WouldBlock()).To(BeFalse())
			q.Send(getPacket([]byte("foobar")), 6)
		}
		// One more packet is queued when it's picked up by Run and written to the connection.
		// In this test, it's blocked on write channel in the mocked Write call.
		<-written
		Eventually(q.WouldBlock()).Should(BeFalse())
		q.Send(getPacket([]byte("foobar")), 6)

		Expect(q.WouldBlock()).To(BeTrue())
		Consistently(q.Available()).ShouldNot(Receive())
		write <- struct{}{}
		Eventually(q.Available()).Should(Receive())

		// test shutdown
		for i := 0; i < sendQueueCapacity; i++ {
			write <- struct{}{}
		}

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
		c.EXPECT().Write(gomock.Any(), gomock.Any()).Return(testErr)
		q.Send(getPacket([]byte("foobar")), 6)
		Eventually(done).Should(BeClosed())

		sent := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			q.Send(getPacket([]byte("raboof")), 6)
			q.Send(getPacket([]byte("quux")), 4)
			close(sent)
		}()

		Eventually(sent).Should(BeClosed())
	})

	It("blocks Close() until the packet has been sent out", func() {
		written := make(chan []byte)
		c.EXPECT().Write(gomock.Any(), gomock.Any()).Do(func(p []byte, _ protocol.ByteCount) { written <- p })
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			q.Run()
			close(done)
		}()

		q.Send(getPacket([]byte("foobar")), 6)

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
