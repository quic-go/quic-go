package quic

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Token Cache", func() {
	var s TokenStore

	BeforeEach(func() {
		s = NewLRUTokenStore(3, 4)
	})

	mockToken := func(num int) *ClientToken {
		return &ClientToken{data: []byte(fmt.Sprintf("%d", num))}
	}

	Context("for a single origin", func() {
		const origin = "localhost"

		It("adds and gets tokens", func() {
			s.Put(origin, mockToken(1))
			s.Put(origin, mockToken(2))
			Expect(s.Pop(origin)).To(Equal(mockToken(2)))
			Expect(s.Pop(origin)).To(Equal(mockToken(1)))
			Expect(s.Pop(origin)).To(BeNil())
		})

		It("overwrites old tokens", func() {
			s.Put(origin, mockToken(1))
			s.Put(origin, mockToken(2))
			s.Put(origin, mockToken(3))
			s.Put(origin, mockToken(4))
			s.Put(origin, mockToken(5))
			Expect(s.Pop(origin)).To(Equal(mockToken(5)))
			Expect(s.Pop(origin)).To(Equal(mockToken(4)))
			Expect(s.Pop(origin)).To(Equal(mockToken(3)))
			Expect(s.Pop(origin)).To(Equal(mockToken(2)))
			Expect(s.Pop(origin)).To(BeNil())
		})

		It("continues after getting a token", func() {
			s.Put(origin, mockToken(1))
			s.Put(origin, mockToken(2))
			s.Put(origin, mockToken(3))
			Expect(s.Pop(origin)).To(Equal(mockToken(3)))
			s.Put(origin, mockToken(4))
			s.Put(origin, mockToken(5))
			Expect(s.Pop(origin)).To(Equal(mockToken(5)))
			Expect(s.Pop(origin)).To(Equal(mockToken(4)))
			Expect(s.Pop(origin)).To(Equal(mockToken(2)))
			Expect(s.Pop(origin)).To(Equal(mockToken(1)))
			Expect(s.Pop(origin)).To(BeNil())
		})
	})

	Context("for multiple origins", func() {
		It("adds and gets tokens", func() {
			s.Put("host1", mockToken(1))
			s.Put("host2", mockToken(2))
			Expect(s.Pop("host1")).To(Equal(mockToken(1)))
			Expect(s.Pop("host1")).To(BeNil())
			Expect(s.Pop("host2")).To(Equal(mockToken(2)))
			Expect(s.Pop("host2")).To(BeNil())
		})

		It("evicts old entries", func() {
			s.Put("host1", mockToken(1))
			s.Put("host2", mockToken(2))
			s.Put("host3", mockToken(3))
			s.Put("host4", mockToken(4))
			Expect(s.Pop("host1")).To(BeNil())
			Expect(s.Pop("host2")).To(Equal(mockToken(2)))
			Expect(s.Pop("host3")).To(Equal(mockToken(3)))
			Expect(s.Pop("host4")).To(Equal(mockToken(4)))
		})

		It("moves old entries to the front, when new tokens are added", func() {
			s.Put("host1", mockToken(1))
			s.Put("host2", mockToken(2))
			s.Put("host3", mockToken(3))
			s.Put("host1", mockToken(11))
			// make sure one is evicted
			s.Put("host4", mockToken(4))
			Expect(s.Pop("host2")).To(BeNil())
			Expect(s.Pop("host1")).To(Equal(mockToken(11)))
			Expect(s.Pop("host1")).To(Equal(mockToken(1)))
			Expect(s.Pop("host3")).To(Equal(mockToken(3)))
			Expect(s.Pop("host4")).To(Equal(mockToken(4)))
		})

		It("deletes hosts that are empty", func() {
			s.Put("host1", mockToken(1))
			s.Put("host2", mockToken(2))
			s.Put("host3", mockToken(3))
			Expect(s.Pop("host2")).To(Equal(mockToken(2)))
			Expect(s.Pop("host2")).To(BeNil())
			// host2 is now empty and should have been deleted, making space for host4
			s.Put("host4", mockToken(4))
			Expect(s.Pop("host1")).To(Equal(mockToken(1)))
			Expect(s.Pop("host3")).To(Equal(mockToken(3)))
			Expect(s.Pop("host4")).To(Equal(mockToken(4)))
		})
	})
})
