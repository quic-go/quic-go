package utils

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Min / Max", func() {
	Context("Max", func() {
		It("returns the maximum", func() {
			Expect(Max(5, 7)).To(Equal(7))
			Expect(Max(7, 5)).To(Equal(7))
		})

		It("returns the maximum uint32", func() {
			Expect(MaxUint32(5, 7)).To(Equal(uint32(7)))
			Expect(MaxUint32(7, 5)).To(Equal(uint32(7)))
		})

		It("returns the maximum uint64", func() {
			Expect(MaxUint64(5, 7)).To(Equal(uint64(7)))
			Expect(MaxUint64(7, 5)).To(Equal(uint64(7)))
		})

		It("returns the maximum int64", func() {
			Expect(MaxInt64(5, 7)).To(Equal(int64(7)))
			Expect(MaxInt64(7, 5)).To(Equal(int64(7)))
		})

		It("returns the maximum duration", func() {
			Expect(MaxDuration(time.Microsecond, time.Nanosecond)).To(Equal(time.Microsecond))
			Expect(MaxDuration(time.Nanosecond, time.Microsecond)).To(Equal(time.Microsecond))
		})

		It("returns the minimum duration", func() {
			Expect(MinDuration(time.Microsecond, time.Nanosecond)).To(Equal(time.Nanosecond))
			Expect(MinDuration(time.Nanosecond, time.Microsecond)).To(Equal(time.Nanosecond))
		})
	})

	Context("Min", func() {
		It("returns the minimum", func() {
			Expect(Min(5, 7)).To(Equal(5))
			Expect(Min(7, 5)).To(Equal(5))
		})

		It("returns the minimum int64", func() {
			Expect(MinInt64(7, 5)).To(Equal(int64(5)))
			Expect(MinInt64(5, 7)).To(Equal(int64(5)))
		})
	})

	It("returns the abs time", func() {
		Expect(AbsDuration(time.Microsecond)).To(Equal(time.Microsecond))
		Expect(AbsDuration(-time.Microsecond)).To(Equal(time.Microsecond))
	})
})
