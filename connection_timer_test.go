package quic

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func (t *connectionTimer) Deadline() time.Time { return t.timer.Deadline() }

var _ = Describe("Timer", func() {
	It("sets an idle timeout", func() {
		now := time.Now()
		t := newTimer()
		t.SetTimer(now.Add(time.Hour), time.Time{}, time.Time{}, time.Time{})
		Expect(t.Deadline()).To(Equal(now.Add(time.Hour)))
	})

	It("sets an ACK timer", func() {
		now := time.Now()
		t := newTimer()
		t.SetTimer(now.Add(time.Hour), now.Add(time.Minute), time.Time{}, time.Time{})
		Expect(t.Deadline()).To(Equal(now.Add(time.Minute)))
	})

	It("sets a loss timer", func() {
		now := time.Now()
		t := newTimer()
		t.SetTimer(now.Add(time.Hour), now.Add(time.Minute), now.Add(time.Second), time.Time{})
		Expect(t.Deadline()).To(Equal(now.Add(time.Second)))
	})

	It("sets a pacing timer", func() {
		now := time.Now()
		t := newTimer()
		t.SetTimer(now.Add(time.Hour), now.Add(time.Minute), now.Add(time.Second), now.Add(time.Millisecond))
		Expect(t.Deadline()).To(Equal(now.Add(time.Millisecond)))
	})

	It("doesn't reset to an earlier time", func() {
		now := time.Now()
		t := newTimer()
		t.SetTimer(now.Add(time.Hour), now.Add(time.Minute), time.Time{}, time.Time{})
		Expect(t.Deadline()).To(Equal(now.Add(time.Minute)))
		t.SetRead()

		t.SetTimer(now.Add(time.Hour), now.Add(time.Minute), time.Time{}, time.Time{})
		Expect(t.Deadline()).To(Equal(now.Add(time.Hour)))
	})

	It("allows the pacing timer to be set to send immediately", func() {
		now := time.Now()
		t := newTimer()
		t.SetTimer(now.Add(time.Hour), now.Add(time.Minute), time.Time{}, time.Time{})
		Expect(t.Deadline()).To(Equal(now.Add(time.Minute)))
		t.SetRead()

		t.SetTimer(now.Add(time.Hour), now.Add(time.Minute), time.Time{}, deadlineSendImmediately)
		Expect(t.Deadline()).To(Equal(deadlineSendImmediately))
	})
})
