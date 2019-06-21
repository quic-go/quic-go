package protocol

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// Tests taken and extended from chrome
var _ = Describe("packet number calculation", func() {
	It("InvalidPacketNumber is smaller than all valid packet numbers", func() {
		Expect(InvalidPacketNumber).To(BeNumerically("<", 0))
	})

	It("works with the example from the draft", func() {
		Expect(DecodePacketNumber(PacketNumberLen2, 0xa82f30ea, 0x9b32)).To(Equal(PacketNumber(0xa82f9b32)))
	})

	It("works with the examples from the draft", func() {
		Expect(GetPacketNumberLengthForHeader(0xac5c02, 0xabe8bc)).To(Equal(PacketNumberLen2))
		Expect(GetPacketNumberLengthForHeader(0xace8fe, 0xabe8bc)).To(Equal(PacketNumberLen3))
	})

	getEpoch := func(len PacketNumberLen) uint64 {
		if len > 4 {
			Fail("invalid packet number len")
		}
		return uint64(1) << (len * 8)
	}

	check := func(length PacketNumberLen, expected, last uint64) {
		epoch := getEpoch(length)
		epochMask := epoch - 1
		wirePacketNumber := expected & epochMask
		ExpectWithOffset(1, DecodePacketNumber(length, PacketNumber(last), PacketNumber(wirePacketNumber))).To(Equal(PacketNumber(expected)))
	}

	for _, l := range []PacketNumberLen{PacketNumberLen1, PacketNumberLen2, PacketNumberLen3, PacketNumberLen4} {
		length := l

		Context(fmt.Sprintf("with %d bytes", length), func() {
			epoch := getEpoch(length)
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

			Context("shortening a packet number for the header", func() {
				Context("shortening", func() {
					It("sends out low packet numbers as 2 byte", func() {
						length := GetPacketNumberLengthForHeader(4, 2)
						Expect(length).To(Equal(PacketNumberLen2))
					})

					It("sends out high packet numbers as 2 byte, if all ACKs are received", func() {
						length := GetPacketNumberLengthForHeader(0xdeadbeef, 0xdeadbeef-1)
						Expect(length).To(Equal(PacketNumberLen2))
					})

					It("sends out higher packet numbers as 3 bytes, if a lot of ACKs are missing", func() {
						length := GetPacketNumberLengthForHeader(40000, 2)
						Expect(length).To(Equal(PacketNumberLen3))
					})

					It("sends out higher packet numbers as 4 bytes, if a lot of ACKs are missing", func() {
						length := GetPacketNumberLengthForHeader(40000000, 2)
						Expect(length).To(Equal(PacketNumberLen4))
					})
				})

				Context("self-consistency", func() {
					It("works for small packet numbers", func() {
						for i := uint64(1); i < 10000; i++ {
							packetNumber := PacketNumber(i)
							leastUnacked := PacketNumber(1)
							length := GetPacketNumberLengthForHeader(packetNumber, leastUnacked)
							wirePacketNumber := (uint64(packetNumber) << (64 - length*8)) >> (64 - length*8)

							decodedPacketNumber := DecodePacketNumber(length, leastUnacked, PacketNumber(wirePacketNumber))
							Expect(decodedPacketNumber).To(Equal(packetNumber))
						}
					})

					It("works for small packet numbers and increasing ACKed packets", func() {
						for i := uint64(1); i < 10000; i++ {
							packetNumber := PacketNumber(i)
							leastUnacked := PacketNumber(i / 2)
							length := GetPacketNumberLengthForHeader(packetNumber, leastUnacked)
							epochMask := getEpoch(length) - 1
							wirePacketNumber := uint64(packetNumber) & epochMask

							decodedPacketNumber := DecodePacketNumber(length, leastUnacked, PacketNumber(wirePacketNumber))
							Expect(decodedPacketNumber).To(Equal(packetNumber))
						}
					})

					It("also works for larger packet numbers", func() {
						var increment uint64
						for i := uint64(1); i < getEpoch(PacketNumberLen4); i += increment {
							packetNumber := PacketNumber(i)
							leastUnacked := PacketNumber(1)
							length := GetPacketNumberLengthForHeader(packetNumber, leastUnacked)
							epochMask := getEpoch(length) - 1
							wirePacketNumber := uint64(packetNumber) & epochMask

							decodedPacketNumber := DecodePacketNumber(length, leastUnacked, PacketNumber(wirePacketNumber))
							Expect(decodedPacketNumber).To(Equal(packetNumber))

							increment = getEpoch(length) / 8
						}
					})

					It("works for packet numbers larger than 2^48", func() {
						for i := (uint64(1) << 48); i < ((uint64(1) << 63) - 1); i += (uint64(1) << 48) {
							packetNumber := PacketNumber(i)
							leastUnacked := PacketNumber(i - 1000)
							length := GetPacketNumberLengthForHeader(packetNumber, leastUnacked)
							wirePacketNumber := (uint64(packetNumber) << (64 - length*8)) >> (64 - length*8)

							decodedPacketNumber := DecodePacketNumber(length, leastUnacked, PacketNumber(wirePacketNumber))
							Expect(decodedPacketNumber).To(Equal(packetNumber))
						}
					})
				})
			})
		})
	}
})
