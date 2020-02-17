package quic

import (
	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Send Queue", func() {
	var q *sendQueue
	var c *MockConnection

	BeforeEach(func() {
		c = NewMockConnection(mockCtrl)
		q = newSendQueue(c)
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

	It("blocks sending when too many packets are queued", func() {
		q.Send(getPacket([]byte("foobar")))

		written := make(chan []byte, 2)
		c.EXPECT().Write(gomock.Any()).Do(func(p []byte) { written <- p }).Times(2)

		sent := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			q.Send(getPacket([]byte("raboof")))
			close(sent)
		}()

		Consistently(sent).ShouldNot(BeClosed())

		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			q.Run()
			close(done)
		}()

		Eventually(written).Should(Receive(Equal([]byte("foobar"))))
		Eventually(written).Should(Receive(Equal([]byte("raboof"))))
		q.Close()
		Eventually(done).Should(BeClosed())
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
