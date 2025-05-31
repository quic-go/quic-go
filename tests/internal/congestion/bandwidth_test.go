package congestion

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Bandwidth", func() {
	It("converts from time delta", func() {
		Expect(BandwidthFromDelta(1, time.Millisecond)).To(Equal(1000 * BytesPerSecond))
	})
})
