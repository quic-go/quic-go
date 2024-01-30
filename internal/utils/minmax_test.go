package utils

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Min / Max", func() {
	It("returns the maximum time", func() {
		a := time.Now()
		b := a.Add(time.Second)
		Expect(MaxTime(a, b)).To(Equal(b))
		Expect(MaxTime(b, a)).To(Equal(b))
	})

	It("returns the minimum duration", func() {
		a := time.Now()
		b := a.Add(time.Second)
		Expect(MinTime(a, b)).To(Equal(a))
		Expect(MinTime(b, a)).To(Equal(a))
	})

	It("returns the minium non-zero duration", func() {
		var a time.Duration
		b := time.Second
		Expect(MinNonZeroDuration(0, 0)).To(BeZero())
		Expect(MinNonZeroDuration(a, b)).To(Equal(b))
		Expect(MinNonZeroDuration(b, a)).To(Equal(b))
		Expect(MinNonZeroDuration(time.Minute, time.Hour)).To(Equal(time.Minute))
	})
})
