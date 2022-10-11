package utils

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Timer", func() {
	const d = 10 * time.Millisecond

	It("doesn't fire a newly created timer", func() {
		t := NewTimer()
		Consistently(t.Chan()).ShouldNot(Receive())
	})

	It("works", func() {
		t := NewTimer()
		t.Reset(time.Now().Add(d))
		Eventually(t.Chan()).Should(Receive())
	})

	It("returns the deadline", func() {
		t := NewTimer()
		deadline := time.Now().Add(d)
		t.Reset(deadline)
		Expect(t.Deadline()).To(Equal(deadline))
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

	It("immediately fires the timer, if the deadlines has already passed", func() {
		t := NewTimer()
		t.Reset(time.Now().Add(-time.Second))
		Eventually(t.Chan()).Should(Receive())
	})

	It("doesn't set a timer if the deadline is the zero value", func() {
		t := NewTimer()
		t.Reset(time.Time{})
		Consistently(t.Chan()).ShouldNot(Receive())
	})

	It("fires the timer twice, if reset to the same deadline", func() {
		deadline := time.Now().Add(-time.Millisecond)
		t := NewTimer()
		t.Reset(deadline)
		Eventually(t.Chan()).Should(Receive())
		t.SetRead()
		t.Reset(deadline)
		Eventually(t.Chan()).Should(Receive())
	})

	It("only fires the timer once, if it is reset to the same deadline, but not read in between", func() {
		deadline := time.Now().Add(-time.Millisecond)
		t := NewTimer()
		t.Reset(deadline)
		Eventually(t.Chan()).Should(Receive())
		Consistently(t.Chan()).ShouldNot(Receive())
	})

	It("stops", func() {
		t := NewTimer()
		t.Reset(time.Now().Add(50 * time.Millisecond))
		t.Stop()
		Consistently(t.Chan()).ShouldNot(Receive())
	})
})
