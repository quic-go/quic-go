package utils

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Rand", func() {
	It("generates random numbers", func() {
		const (
			num = 1000
			max = 12345678
		)

		var values [num]int32
		var r Rand
		for i := 0; i < num; i++ {
			v := r.Int31n(max)
			Expect(v).To(And(
				BeNumerically(">=", 0),
				BeNumerically("<", max),
			))
			values[i] = v
		}

		var sum uint64
		for _, n := range values {
			sum += uint64(n)
		}
		Expect(float64(sum) / num).To(BeNumerically("~", max/2, max/25))
	})
})
