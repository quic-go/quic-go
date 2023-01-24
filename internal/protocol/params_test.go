package protocol

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Parameters", func() {
	It("can queue more packets in the session than in the 0-RTT queue", func() {
		Expect(MaxConnUnprocessedPackets).To(BeNumerically(">", Max0RTTQueueLen))
		Expect(MaxUndecryptablePackets).To(BeNumerically(">", Max0RTTQueueLen))
	})
})
