package utils

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Timer", func() {
	const d = 10 * time.Millisecond

	It("works", func() {
		t := NewTimer()
		t.Reset(time.Now().Add(d))
		Eventually(t.Chan()).Should(Receive())
	})

	It("works multiple times with reading", func() {
		t := NewTimer()
		for i := 0; i < 10; i++ {
			t.Reset(time.Now().Add(d))
			Eventually(t.Chan()).Should(Receive())
			t.SetRead()
		}
	})

	It("works multiple times without reading", func() {
		t := NewTimer()
		for i := 0; i < 10; i++ {
			t.Reset(time.Now().Add(d))
			time.Sleep(d * 2)
		}
		Eventually(t.Chan()).Should(Receive())
	})

	It("works when resetting without expiration", func() {
		t := NewTimer()
		for i := 0; i < 10; i++ {
			t.Reset(time.Now().Add(time.Hour))
		}
		t.Reset(time.Now().Add(d))
		Eventually(t.Chan()).Should(Receive())
	})
})
