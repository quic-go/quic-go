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
		rq.Add(&receivedPacket{data: []byte("foo")})
		rq.Add(&receivedPacket{data: []byte("bar")})

		p := rq.Pop()
		Expect(p).ToNot(BeNil())
		Expect(p.data).To(Equal([]byte("foo")))
		p = rq.Pop()
		Expect(p).ToNot(BeNil())
		Expect(p.data).To(Equal([]byte("bar")))
		Expect(rq.Pop()).To(BeNil())
	})

	It("receives, returns, receives and returns packets", func() {
		// first packet
		rq.Add(&receivedPacket{data: []byte("foo")})
		p := rq.Pop()
		Expect(p).ToNot(BeNil())
		Expect(p.data).To(Equal([]byte("foo")))
		Expect(rq.Pop()).To(BeNil())
		// second packet
		rq.Add(&receivedPacket{data: []byte("bar")})
		p = rq.Pop()
		Expect(p).ToNot(BeNil())
		Expect(p.data).To(Equal([]byte("bar")))
		Expect(rq.Pop()).To(BeNil())
	})
})
