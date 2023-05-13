package quic

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Receive Queue", func() {
	var rq *receiveQueue

	BeforeEach(func() {
		rq = newReceiveQueue(nil)
	})

	It("receives and returns packets", func() {
		rq.Add(receivedPacket{data: []byte("foo")})
		rq.Add(receivedPacket{data: []byte("bar")})

		p, ok := rq.Pop()
		Expect(ok).To(BeTrue())
		Expect(p.data).To(Equal([]byte("foo")))
		p, ok = rq.Pop()
		Expect(ok).To(BeTrue())
		Expect(p.data).To(Equal([]byte("bar")))
		_, ok = rq.Pop()
		Expect(ok).To(BeFalse())
	})

	It("receives, returns, receives and returns packets", func() {
		// first packet
		rq.Add(receivedPacket{data: []byte("foo")})
		p, ok := rq.Pop()
		Expect(ok).To(BeTrue())
		Expect(p.data).To(Equal([]byte("foo")))
		_, ok = rq.Pop()
		Expect(ok).To(BeFalse())
		// second packet
		rq.Add(receivedPacket{data: []byte("bar")})
		p, ok = rq.Pop()
		Expect(ok).To(BeTrue())
		Expect(p.data).To(Equal([]byte("bar")))
		_, ok = rq.Pop()
		Expect(ok).To(BeFalse())
	})
})
