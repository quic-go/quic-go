package quic

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("STREAM frame sorter", func() {
	var s *frameSorter

	checkGaps := func(expectedGaps []utils.ByteInterval) {
		Expect(s.gaps.Len()).To(Equal(len(expectedGaps)))
		var i int
		for gap := s.gaps.Front(); gap != nil; gap = gap.Next() {
			Expect(gap.Value).To(Equal(expectedGaps[i]))
			i++
		}
	}

	BeforeEach(func() {
		s = newFrameSorter()
	})

	It("returns nil when empty", func() {
		_, data := s.Pop()
		Expect(data).To(BeNil())
	})

	Context("Push", func() {
		It("inserts and pops a single frame", func() {
			Expect(s.Push([]byte("foobar"), 0)).To(Succeed())
			offset, data := s.Pop()
			Expect(offset).To(BeZero())
			Expect(data).To(Equal([]byte("foobar")))
			offset, data = s.Pop()
			Expect(offset).To(Equal(protocol.ByteCount(6)))
			Expect(data).To(BeNil())
		})

		It("inserts and pops two consecutive frame", func() {
			Expect(s.Push([]byte("foo"), 0)).To(Succeed())
			Expect(s.Push([]byte("bar"), 3)).To(Succeed())
			offset, data := s.Pop()
			Expect(offset).To(BeZero())
			Expect(data).To(Equal([]byte("foo")))
			offset, data = s.Pop()
			Expect(offset).To(Equal(protocol.ByteCount(3)))
			Expect(data).To(Equal([]byte("bar")))
			offset, data = s.Pop()
			Expect(offset).To(Equal(protocol.ByteCount(6)))
			Expect(data).To(BeNil())
		})

		It("ignores empty frames", func() {
			Expect(s.Push(nil, 0)).To(Succeed())
			_, data := s.Pop()
			Expect(data).To(BeNil())
		})

		It("says if has more data", func() {
			Expect(s.HasMoreData()).To(BeFalse())
			Expect(s.Push([]byte("foo"), 0)).To(Succeed())
			Expect(s.HasMoreData()).To(BeTrue())
			_, data := s.Pop()
			Expect(data).To(Equal([]byte("foo")))
			Expect(s.HasMoreData()).To(BeFalse())
		})

		Context("Gap handling", func() {
			It("finds the first gap", func() {
				Expect(s.Push([]byte("foobar"), 10)).To(Succeed())
				checkGaps([]utils.ByteInterval{
					{Start: 0, End: 10},
					{Start: 16, End: protocol.MaxByteCount},
				})
			})

			It("correctly sets the first gap for a frame with offset 0", func() {
				Expect(s.Push([]byte("foobar"), 0)).To(Succeed())
				checkGaps([]utils.ByteInterval{
					{Start: 6, End: protocol.MaxByteCount},
				})
			})

			It("finds the two gaps", func() {
				Expect(s.Push([]byte("foobar"), 10)).To(Succeed())
				Expect(s.Push([]byte("foobar"), 20)).To(Succeed())
				checkGaps([]utils.ByteInterval{
					{Start: 0, End: 10},
					{Start: 16, End: 20},
					{Start: 26, End: protocol.MaxByteCount},
				})
			})

			It("finds the two gaps in reverse order", func() {
				Expect(s.Push([]byte("foobar"), 20)).To(Succeed())
				Expect(s.Push([]byte("foobar"), 10)).To(Succeed())
				checkGaps([]utils.ByteInterval{
					{Start: 0, End: 10},
					{Start: 16, End: 20},
					{Start: 26, End: protocol.MaxByteCount},
				})
			})

			It("shrinks a gap when it is partially filled", func() {
				Expect(s.Push([]byte("test"), 10)).To(Succeed())
				Expect(s.Push([]byte("foobar"), 4)).To(Succeed())
				checkGaps([]utils.ByteInterval{
					{Start: 0, End: 4},
					{Start: 14, End: protocol.MaxByteCount},
				})
			})

			It("deletes a gap at the beginning, when it is filled", func() {
				Expect(s.Push([]byte("test"), 6)).To(Succeed())
				Expect(s.Push([]byte("foobar"), 0)).To(Succeed())
				checkGaps([]utils.ByteInterval{
					{Start: 10, End: protocol.MaxByteCount},
				})
			})

			It("deletes a gap in the middle, when it is filled", func() {
				Expect(s.Push([]byte("test"), 0)).To(Succeed())
				Expect(s.Push([]byte("test2"), 10)).To(Succeed())
				Expect(s.Push([]byte("foobar"), 4)).To(Succeed())
				Expect(s.queue).To(HaveLen(3))
				checkGaps([]utils.ByteInterval{
					{Start: 15, End: protocol.MaxByteCount},
				})
			})

			It("splits a gap into two", func() {
				Expect(s.Push([]byte("test"), 100)).To(Succeed())
				Expect(s.Push([]byte("foobar"), 50)).To(Succeed())
				Expect(s.queue).To(HaveLen(2))
				checkGaps([]utils.ByteInterval{
					{Start: 0, End: 50},
					{Start: 56, End: 100},
					{Start: 104, End: protocol.MaxByteCount},
				})
			})

			Context("Overlapping Stream Data detection", func() {
				// create gaps: 0-5, 10-15, 20-25, 30-inf
				BeforeEach(func() {
					Expect(s.Push([]byte("12345"), 5)).To(Succeed())
					Expect(s.Push([]byte("12345"), 15)).To(Succeed())
					Expect(s.Push([]byte("12345"), 25)).To(Succeed())
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 5},
						{Start: 10, End: 15},
						{Start: 20, End: 25},
						{Start: 30, End: protocol.MaxByteCount},
					})
				})

				It("cuts a frame with offset 0 that overlaps at the end", func() {
					Expect(s.Push([]byte("foobar"), 0)).To(Succeed())
					Expect(s.queue).To(HaveKey(protocol.ByteCount(0)))
					Expect(s.queue[0]).To(Equal([]byte("fooba")))
					Expect(s.queue[0]).To(HaveCap(5))
					checkGaps([]utils.ByteInterval{
						{Start: 10, End: 15},
						{Start: 20, End: 25},
						{Start: 30, End: protocol.MaxByteCount},
					})
				})

				It("cuts a frame that overlaps at the end", func() {
					// 4 to 7
					Expect(s.Push([]byte("foo"), 4)).To(Succeed())
					Expect(s.queue).To(HaveKey(protocol.ByteCount(4)))
					Expect(s.queue[4]).To(Equal([]byte("f")))
					Expect(s.queue[4]).To(HaveCap(1))
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 4},
						{Start: 10, End: 15},
						{Start: 20, End: 25},
						{Start: 30, End: protocol.MaxByteCount},
					})
				})

				It("cuts a frame that completely fills a gap, but overlaps at the end", func() {
					// 10 to 16
					Expect(s.Push([]byte("foobar"), 10)).To(Succeed())
					Expect(s.queue).To(HaveKey(protocol.ByteCount(10)))
					Expect(s.queue[10]).To(Equal([]byte("fooba")))
					Expect(s.queue[10]).To(HaveCap(5))
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 5},
						{Start: 20, End: 25},
						{Start: 30, End: protocol.MaxByteCount},
					})
				})

				It("cuts a frame that overlaps at the beginning", func() {
					// 8 to 14
					Expect(s.Push([]byte("foobar"), 8)).To(Succeed())
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(8)))
					Expect(s.queue).To(HaveKey(protocol.ByteCount(10)))
					Expect(s.queue[10]).To(Equal([]byte("obar")))
					Expect(s.queue[10]).To(HaveCap(4))
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 5},
						{Start: 14, End: 15},
						{Start: 20, End: 25},
						{Start: 30, End: protocol.MaxByteCount},
					})
				})

				It("processes a frame that overlaps at the beginning and at the end, starting in a gap", func() {
					// 2 to 12
					Expect(s.Push([]byte("1234567890"), 2)).To(Succeed())
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(5)))
					Expect(s.queue).To(HaveKey(protocol.ByteCount(2)))
					Expect(s.queue[2]).To(Equal([]byte("1234567890")))
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 2},
						{Start: 12, End: 15},
						{Start: 20, End: 25},
						{Start: 30, End: protocol.MaxByteCount},
					})
				})

				It("processes a frame that overlaps at the beginning and at the end, starting in a gap, ending in data", func() {
					// 2 to 17
					Expect(s.Push([]byte("123456789012345"), 2)).To(Succeed())
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(5)))
					Expect(s.queue).To(HaveKey(protocol.ByteCount(2)))
					Expect(s.queue[2]).To(Equal([]byte("1234567890123")))
					Expect(s.queue[2]).To(HaveCap(13))
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 2},
						{Start: 20, End: 25},
						{Start: 30, End: protocol.MaxByteCount},
					})
				})

				It("processes a frame that overlaps at the beginning and at the end, starting in a gap, ending in data", func() {
					// 5 to 22
					Expect(s.Push([]byte("12345678901234567"), 5)).To(Succeed())
					Expect(s.queue).To(HaveKey(protocol.ByteCount(5)))
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(15)))
					Expect(s.queue[10]).To(Equal([]byte("678901234567")))
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 5},
						{Start: 22, End: 25},
						{Start: 30, End: protocol.MaxByteCount},
					})
				})

				It("processes a frame that closes multiple gaps", func() {
					// 2 to 27
					Expect(s.Push(bytes.Repeat([]byte{'e'}, 25), 2)).To(Succeed())
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(5)))
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(15)))
					Expect(s.queue).To(HaveKey(protocol.ByteCount(25)))
					Expect(s.queue).To(HaveKey(protocol.ByteCount(2)))
					Expect(s.queue[2]).To(Equal(bytes.Repeat([]byte{'e'}, 23)))
					Expect(s.queue[2]).To(HaveCap(23))
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 2},
						{Start: 30, End: protocol.MaxByteCount},
					})
				})

				It("processes a frame that closes multiple gaps", func() {
					// 5 to 27
					Expect(s.Push(bytes.Repeat([]byte{'d'}, 22), 5)).To(Succeed())
					Expect(s.queue).To(HaveKey(protocol.ByteCount(5)))
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(15)))
					Expect(s.queue).To(HaveKey(protocol.ByteCount(25)))
					Expect(s.queue).To(HaveKey(protocol.ByteCount(10)))
					Expect(s.queue[10]).To(Equal(bytes.Repeat([]byte{'d'}, 15)))
					Expect(s.queue[10]).To(HaveCap(15))
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 5},
						{Start: 30, End: protocol.MaxByteCount},
					})
				})

				It("processes a frame that covers multiple gaps and ends at the end of a gap", func() {
					data := bytes.Repeat([]byte{'e'}, 14)
					// 1 to 15
					Expect(s.Push(data, 1)).To(Succeed())
					Expect(s.queue).To(HaveKey(protocol.ByteCount(1)))
					Expect(s.queue).To(HaveKey(protocol.ByteCount(15)))
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(5)))
					Expect(s.queue[1]).To(Equal(data))
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 1},
						{Start: 20, End: 25},
						{Start: 30, End: protocol.MaxByteCount},
					})
				})

				It("processes a frame that closes all gaps (except for the last one)", func() {
					data := bytes.Repeat([]byte{'f'}, 32)
					// 0 to 32
					Expect(s.Push(data, 0)).To(Succeed())
					Expect(s.queue).To(HaveLen(1))
					Expect(s.queue).To(HaveKey(protocol.ByteCount(0)))
					Expect(s.queue[0]).To(Equal(data))
					checkGaps([]utils.ByteInterval{
						{Start: 32, End: protocol.MaxByteCount},
					})
				})

				It("cuts a frame that overlaps at the beginning and at the end, starting in data already received", func() {
					// 8 to 17
					Expect(s.Push([]byte("123456789"), 8)).To(Succeed())
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(8)))
					Expect(s.queue).To(HaveKey(protocol.ByteCount(10)))
					Expect(s.queue[10]).To(Equal([]byte("34567")))
					Expect(s.queue[10]).To(HaveCap(5))
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 5},
						{Start: 20, End: 25},
						{Start: 30, End: protocol.MaxByteCount},
					})
				})

				It("cuts a frame that completely covers two gaps", func() {
					// 10 to 20
					Expect(s.Push([]byte("1234567890"), 10)).To(Succeed())
					Expect(s.queue).To(HaveKey(protocol.ByteCount(10)))
					Expect(s.queue[10]).To(Equal([]byte("12345")))
					Expect(s.queue[10]).To(HaveCap(5))
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 5},
						{Start: 20, End: 25},
						{Start: 30, End: protocol.MaxByteCount},
					})
				})
			})

			Context("duplicate data", func() {
				expectedGaps := []utils.ByteInterval{
					{Start: 5, End: 10},
					{Start: 15, End: protocol.MaxByteCount},
				}

				BeforeEach(func() {
					// create gaps: 5-10, 15-inf
					Expect(s.Push([]byte("12345"), 0)).To(Succeed())
					Expect(s.Push([]byte("12345"), 10)).To(Succeed())
					checkGaps(expectedGaps)
				})

				AfterEach(func() {
					// check that the gaps were not modified
					checkGaps(expectedGaps)
				})

				It("does not modify data when receiving a duplicate", func() {
					err := s.push([]byte("fffff"), 0)
					Expect(err).To(MatchError(errDuplicateStreamData))
					Expect(s.queue[0]).ToNot(Equal([]byte("fffff")))
				})

				It("detects a duplicate frame that is smaller than the original, starting at the beginning", func() {
					// 10 to 12
					err := s.push([]byte("12"), 10)
					Expect(err).To(MatchError(errDuplicateStreamData))
					Expect(s.queue[10]).To(HaveLen(5))
				})

				It("detects a duplicate frame that is smaller than the original, somewhere in the middle", func() {
					// 1 to 4
					err := s.push([]byte("123"), 1)
					Expect(err).To(MatchError(errDuplicateStreamData))
					Expect(s.queue[0]).To(HaveLen(5))
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(1)))
				})

				It("detects a duplicate frame that is smaller than the original, somewhere in the middle in the last block", func() {
					// 11 to 14
					err := s.push([]byte("123"), 11)
					Expect(err).To(MatchError(errDuplicateStreamData))
					Expect(s.queue[10]).To(HaveLen(5))
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(11)))
				})

				It("detects a duplicate frame that is smaller than the original, with aligned end in the last block", func() {
					// 11 to 15
					err := s.push([]byte("1234"), 1)
					Expect(err).To(MatchError(errDuplicateStreamData))
					Expect(s.queue[10]).To(HaveLen(5))
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(11)))
				})

				It("detects a duplicate frame that is smaller than the original, with aligned end", func() {
					// 3 to 5
					err := s.push([]byte("12"), 3)
					Expect(err).To(MatchError(errDuplicateStreamData))
					Expect(s.queue[0]).To(HaveLen(5))
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(3)))
				})
			})

			Context("DoS protection", func() {
				It("errors when too many gaps are created", func() {
					for i := 0; i < protocol.MaxStreamFrameSorterGaps; i++ {
						Expect(s.Push([]byte("foobar"), protocol.ByteCount(i*7))).To(Succeed())
					}
					Expect(s.gaps.Len()).To(Equal(protocol.MaxStreamFrameSorterGaps))
					err := s.Push([]byte("foobar"), protocol.ByteCount(protocol.MaxStreamFrameSorterGaps*7)+100)
					Expect(err).To(MatchError("Too many gaps in received data"))
				})
			})
		})
	})
})
