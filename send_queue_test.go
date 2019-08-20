package quic

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Send Queue", func() {
	var q *sendQueue
	var c *mockConnection

	BeforeEach(func() {
		c = newMockConnection()
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
		q.Send(getPacket([]byte("foobar")))

		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			q.Run()
			close(done)
		}()

		Eventually(c.written).Should(Receive(Equal([]byte("foobar"))))
		q.Close()
		Eventually(done).Should(BeClosed())
	})

	It("blocks sending when too many packets are queued", func() {
		q.Send(getPacket([]byte("foobar")))

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

		Eventually(c.written).Should(Receive(Equal([]byte("foobar"))))
		Eventually(c.written).Should(Receive(Equal([]byte("raboof"))))
		q.Close()
		Eventually(done).Should(BeClosed())
	})
})
