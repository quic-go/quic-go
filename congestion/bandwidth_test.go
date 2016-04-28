package congestion_test

import (
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Bandwidth", func() {
	It("converts from time delta", func() {
		Expect(congestion.BandwidthFromDelta(1, time.Millisecond)).To(Equal(1000 * congestion.BytesPerSecond))
	})
})
