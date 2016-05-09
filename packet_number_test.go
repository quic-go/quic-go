package quic

import (
	"fmt"
	"math"

	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// Tests taken and extended from chrome
var _ = Describe("packet number calculation", func() {
	check := func(length protocol.PacketNumberLen, expected, last uint64) {
		epoch := uint64(1) << (length * 8)
		epochMask := epoch - 1
		wirePacketNumber := expected & epochMask
		Expect(calculatePacketNumber(length, protocol.PacketNumber(last), protocol.PacketNumber(wirePacketNumber))).To(Equal(protocol.PacketNumber(expected)))
	}
	for _, length := range []protocol.PacketNumberLen{protocol.PacketNumberLen1, protocol.PacketNumberLen2, protocol.PacketNumberLen4, protocol.PacketNumberLen6} {
		Context(fmt.Sprintf("with %d bytes", length), func() {
			epoch := uint64(1) << (length * 8)
			epochMask := epoch - 1

			It("works near epoch start", func() {
				// A few quick manual sanity check
				check(length, 1, 0)
				check(length, epoch+1, epochMask)
				check(length, epoch, epochMask)

				// Cases where the last number was close to the start of the range.
				for last := uint64(0); last < 10; last++ {
					// Small numbers should not wrap (even if they're out of order).
					for j := uint64(0); j < 10; j++ {
						check(length, j, last)
					}

					// Large numbers should not wrap either (because we're near 0 already).
					for j := uint64(0); j < 10; j++ {
						check(length, epoch-1-j, last)
					}
				}
			})

			It("works near epoch end", func() {
				// Cases where the last number was close to the end of the range
				for i := uint64(0); i < 10; i++ {
					last := epoch - i

					// Small numbers should wrap.
					for j := uint64(0); j < 10; j++ {
						check(length, epoch+j, last)
					}

					// Large numbers should not (even if they're out of order).
					for j := uint64(0); j < 10; j++ {
						check(length, epoch-1-j, last)
					}
				}
			})

			// Next check where we're in a non-zero epoch to verify we handle
			// reverse wrapping, too.
			It("works near previous epoch", func() {
				prevEpoch := 1 * epoch
				curEpoch := 2 * epoch
				// Cases where the last number was close to the start of the range
				for i := uint64(0); i < 10; i++ {
					last := curEpoch + i
					// Small number should not wrap (even if they're out of order).
					for j := uint64(0); j < 10; j++ {
						check(length, curEpoch+j, last)
					}

					// But large numbers should reverse wrap.
					for j := uint64(0); j < 10; j++ {
						num := epoch - 1 - j
						check(length, prevEpoch+num, last)
					}
				}
			})

			It("works near next epoch", func() {
				curEpoch := 2 * epoch
				nextEpoch := 3 * epoch
				// Cases where the last number was close to the end of the range
				for i := uint64(0); i < 10; i++ {
					last := nextEpoch - 1 - i

					// Small numbers should wrap.
					for j := uint64(0); j < 10; j++ {
						check(length, nextEpoch+j, last)
					}

					// but large numbers should not (even if they're out of order).
					for j := uint64(0); j < 10; j++ {
						num := epoch - 1 - j
						check(length, curEpoch+num, last)
					}
				}
			})

			It("works near next max", func() {
				maxNumber := uint64(math.MaxUint64)
				maxEpoch := maxNumber & ^epochMask

				// Cases where the last number was close to the end of the range
				for i := uint64(0); i < 10; i++ {
					// Subtract 1, because the expected next packet number is 1 more than the
					// last packet number.
					last := maxNumber - i - 1

					// Small numbers should not wrap, because they have nowhere to go.
					for j := uint64(0); j < 10; j++ {
						check(length, maxEpoch+j, last)
					}

					// Large numbers should not wrap either.
					for j := uint64(0); j < 10; j++ {
						num := epoch - 1 - j
						check(length, maxEpoch+num, last)
					}
				}
			})
		})
	}
})
