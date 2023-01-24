package utils

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Min / Max", func() {
	It("returns the maximum", func() {
		Expect(Max(5, 7)).To(Equal(7))
		Expect(Max(5.5, 5.7)).To(Equal(5.7))
	})

	It("returns the minimum", func() {
		Expect(Min(5, 7)).To(Equal(5))
		Expect(Min(5.5, 5.7)).To(Equal(5.5))
	})

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

	It("returns the minium non-zero time", func() {
		a := time.Time{}
		b := time.Now()
		Expect(MinNonZeroTime(time.Time{}, time.Time{})).To(Equal(time.Time{}))
		Expect(MinNonZeroTime(a, b)).To(Equal(b))
		Expect(MinNonZeroTime(b, a)).To(Equal(b))
		Expect(MinNonZeroTime(b, b.Add(time.Second))).To(Equal(b))
		Expect(MinNonZeroTime(b.Add(time.Second), b)).To(Equal(b))
	})

	It("returns the abs time", func() {
		Expect(AbsDuration(time.Microsecond)).To(Equal(time.Microsecond))
		Expect(AbsDuration(-time.Microsecond)).To(Equal(time.Microsecond))
	})
})
