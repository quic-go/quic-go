package quic

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("frame sorter", func() {
	var s *frameSorter

	checkGaps := func(expectedGaps []utils.ByteInterval) {
		ExpectWithOffset(1, s.gaps.Len()).To(Equal(len(expectedGaps)))
		var i int
		for gap := s.gaps.Front(); gap != nil; gap = gap.Next() {
			ExpectWithOffset(1, gap.Value).To(Equal(expectedGaps[i]))
			i++
		}
	}

	getCallback := func() (func(), *bool) {
		var called bool
		return func() { called = true }, &called
	}

	checkCallback := func(cb func(), called *bool) {
		ExpectWithOffset(1, cb).ToNot(BeNil())
		ExpectWithOffset(1, *called).To(BeFalse())
		cb()
		ExpectWithOffset(1, *called).To(BeTrue())
	}

	BeforeEach(func() {
		s = newFrameSorter()
		_ = checkGaps
	})

	It("returns nil when empty", func() {
		_, data, doneCb := s.Pop()
		Expect(data).To(BeNil())
		Expect(doneCb).To(BeNil())
	})

	Context("Push", func() {
		It("inserts and pops a single frame", func() {
			cb, called := getCallback()
			Expect(s.Push([]byte("foobar"), 0, cb)).To(Succeed())
			offset, data, doneCb := s.Pop()
			Expect(offset).To(BeZero())
			Expect(data).To(Equal([]byte("foobar")))
			checkCallback(doneCb, called)
			offset, data, doneCb = s.Pop()
			Expect(offset).To(Equal(protocol.ByteCount(6)))
			Expect(data).To(BeNil())
			Expect(doneCb).To(BeNil())
		})

		It("inserts and pops two consecutive frame", func() {
			cb1, called1 := getCallback()
			cb2, called2 := getCallback()
			Expect(s.Push([]byte("bar"), 3, cb2)).To(Succeed())
			Expect(s.Push([]byte("foo"), 0, cb1)).To(Succeed())
			offset, data, doneCb := s.Pop()
			Expect(offset).To(BeZero())
			Expect(data).To(Equal([]byte("foo")))
			checkCallback(doneCb, called1)
			offset, data, doneCb = s.Pop()
			Expect(offset).To(Equal(protocol.ByteCount(3)))
			Expect(data).To(Equal([]byte("bar")))
			checkCallback(doneCb, called2)
			offset, data, doneCb = s.Pop()
			Expect(offset).To(Equal(protocol.ByteCount(6)))
			Expect(data).To(BeNil())
			Expect(doneCb).To(BeNil())
		})

		It("ignores empty frames", func() {
			Expect(s.Push(nil, 0, nil)).To(Succeed())
			_, data, doneCb := s.Pop()
			Expect(data).To(BeNil())
			Expect(doneCb).To(BeNil())
		})

		It("says if has more data", func() {
			Expect(s.HasMoreData()).To(BeFalse())
			Expect(s.Push([]byte("foo"), 0, nil)).To(Succeed())
			Expect(s.HasMoreData()).To(BeTrue())
			_, data, _ := s.Pop()
			Expect(data).To(Equal([]byte("foo")))
			Expect(s.HasMoreData()).To(BeFalse())
		})

		Context("Gap handling", func() {
			It("finds the first gap", func() {
				Expect(s.Push([]byte("foobar"), 10, nil)).To(Succeed())
				checkGaps([]utils.ByteInterval{
					{Start: 0, End: 10},
					{Start: 16, End: protocol.MaxByteCount},
				})
			})

			It("correctly sets the first gap for a frame with offset 0", func() {
				Expect(s.Push([]byte("foobar"), 0, nil)).To(Succeed())
				checkGaps([]utils.ByteInterval{
					{Start: 6, End: protocol.MaxByteCount},
				})
			})

			It("finds the two gaps", func() {
				Expect(s.Push([]byte("foobar"), 10, nil)).To(Succeed())
				Expect(s.Push([]byte("foobar"), 20, nil)).To(Succeed())
				checkGaps([]utils.ByteInterval{
					{Start: 0, End: 10},
					{Start: 16, End: 20},
					{Start: 26, End: protocol.MaxByteCount},
				})
			})

			It("finds the two gaps in reverse order", func() {
				Expect(s.Push([]byte("foobar"), 20, nil)).To(Succeed())
				Expect(s.Push([]byte("foobar"), 10, nil)).To(Succeed())
				checkGaps([]utils.ByteInterval{
					{Start: 0, End: 10},
					{Start: 16, End: 20},
					{Start: 26, End: protocol.MaxByteCount},
				})
			})

			It("shrinks a gap when it is partially filled", func() {
				Expect(s.Push([]byte("test"), 10, nil)).To(Succeed())
				Expect(s.Push([]byte("foobar"), 4, nil)).To(Succeed())
				checkGaps([]utils.ByteInterval{
					{Start: 0, End: 4},
					{Start: 14, End: protocol.MaxByteCount},
				})
			})

			It("deletes a gap at the beginning, when it is filled", func() {
				Expect(s.Push([]byte("test"), 6, nil)).To(Succeed())
				Expect(s.Push([]byte("foobar"), 0, nil)).To(Succeed())
				checkGaps([]utils.ByteInterval{
					{Start: 10, End: protocol.MaxByteCount},
				})
			})

			It("deletes a gap in the middle, when it is filled", func() {
				Expect(s.Push([]byte("test"), 0, nil)).To(Succeed())
				Expect(s.Push([]byte("test2"), 10, nil)).To(Succeed())
				Expect(s.Push([]byte("foobar"), 4, nil)).To(Succeed())
				Expect(s.queue).To(HaveLen(3))
				checkGaps([]utils.ByteInterval{
					{Start: 15, End: protocol.MaxByteCount},
				})
			})

			It("splits a gap into two", func() {
				Expect(s.Push([]byte("test"), 100, nil)).To(Succeed())
				Expect(s.Push([]byte("foobar"), 50, nil)).To(Succeed())
				Expect(s.queue).To(HaveLen(2))
				checkGaps([]utils.ByteInterval{
					{Start: 0, End: 50},
					{Start: 56, End: 100},
					{Start: 104, End: protocol.MaxByteCount},
				})
			})

			Context("Overlapping Stream Data detection", func() {
				var initialCb1, initialCb2, initialCb3 func()
				var initialCb1Called, initialCb2Called, initialCb3Called *bool

				// create gaps: 0-500, 1000-1500, 2000-2500, 3000-inf
				BeforeEach(func() {
					// make sure frames are not cut when we overlap a little bit
					Expect(protocol.MinStreamFrameBufferSize).To(BeNumerically("<", 500/2))
					initialCb1, initialCb1Called = getCallback()
					initialCb2, initialCb2Called = getCallback()
					initialCb3, initialCb3Called = getCallback()
					Expect(s.Push(bytes.Repeat([]byte{1}, 500), 500, initialCb1)).To(Succeed())
					Expect(s.Push(bytes.Repeat([]byte{2}, 500), 1500, initialCb2)).To(Succeed())
					Expect(s.Push(bytes.Repeat([]byte{3}, 500), 2500, initialCb3)).To(Succeed())
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 500},
						{Start: 1000, End: 1500},
						{Start: 2000, End: 2500},
						{Start: 3000, End: protocol.MaxByteCount},
					})
				})

				It("cuts a frame with offset 0 that overlaps at the end", func() {
					cb, called := getCallback()
					// 0 - 505
					Expect(s.Push(bytes.Repeat([]byte{9}, 505), 0, cb)).To(Succeed())
					Expect(s.queue).To(HaveKey(protocol.ByteCount(0)))
					Expect(s.queue[0].Data).To(Equal(bytes.Repeat([]byte{9}, 500))) // 0 to 500
					checkGaps([]utils.ByteInterval{
						{Start: 1000, End: 1500},
						{Start: 2000, End: 2500},
						{Start: 3000, End: protocol.MaxByteCount},
					})
					checkCallback(cb, called)
					checkCallback(initialCb1, initialCb1Called)
					checkCallback(initialCb2, initialCb2Called)
					checkCallback(initialCb3, initialCb3Called)
				})

				It("cuts a frame that overlaps at the end", func() {
					cb, called := getCallback()
					// 100 to 600
					Expect(s.Push(bytes.Repeat([]byte{9}, 500), 100, cb)).To(Succeed())
					Expect(s.queue).To(HaveKey(protocol.ByteCount(100)))
					Expect(s.queue[100].Data).To(Equal(bytes.Repeat([]byte{9}, 400))) // 100 to 500
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 100},
						{Start: 1000, End: 1500},
						{Start: 2000, End: 2500},
						{Start: 3000, End: protocol.MaxByteCount},
					})
					checkCallback(cb, called)
					checkCallback(initialCb1, initialCb1Called)
					checkCallback(initialCb2, initialCb2Called)
					checkCallback(initialCb3, initialCb3Called)
				})

				It("cuts a frame that completely fills a gap, but overlaps at the end", func() {
					// 1000 to 1600
					cb, called := getCallback()
					Expect(s.Push(bytes.Repeat([]byte{9}, 600), 1000, cb)).To(Succeed())
					Expect(s.queue).To(HaveKey(protocol.ByteCount(1000)))
					Expect(s.queue[1000].Data).To(Equal(bytes.Repeat([]byte{9}, 500))) // 1000 to 15000
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 500},
						{Start: 2000, End: 2500},
						{Start: 3000, End: protocol.MaxByteCount},
					})
					checkCallback(cb, called)
					checkCallback(initialCb1, initialCb1Called)
					checkCallback(initialCb2, initialCb2Called)
					checkCallback(initialCb3, initialCb3Called)
				})

				It("cuts a frame that overlaps at the beginning", func() {
					cb, called := getCallback()
					// 900 to 1400
					Expect(s.Push(bytes.Repeat([]byte{9}, 500), 900, cb)).To(Succeed())
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(900)))
					Expect(s.queue).To(HaveKey(protocol.ByteCount(1000)))
					Expect(s.queue[1000].Data).To(Equal(bytes.Repeat([]byte{9}, 400))) // 1000 to 1400
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 500},
						{Start: 1400, End: 1500},
						{Start: 2000, End: 2500},
						{Start: 3000, End: protocol.MaxByteCount},
					})
					checkCallback(cb, called)
					checkCallback(initialCb1, initialCb1Called)
					checkCallback(initialCb2, initialCb2Called)
					checkCallback(initialCb3, initialCb3Called)
				})

				It("processes a frame that overlaps at the beginning and at the end, starting in a gap", func() {
					cb, called := getCallback()
					// 300 to 1100
					Expect(s.Push(bytes.Repeat([]byte{9}, 800), 300, cb)).To(Succeed())
					Expect(s.queue).To(HaveKey(protocol.ByteCount(300)))
					Expect(s.queue[300].Data).To(Equal(bytes.Repeat([]byte{9}, 800))) // 300 to 1100
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 300},
						{Start: 1100, End: 1500},
						{Start: 2000, End: 2500},
						{Start: 3000, End: protocol.MaxByteCount},
					})
					checkCallback(cb, called)
					// initial1 spanned from 500 - 1000, and should have been deleted
					Expect(*initialCb1Called).To(BeTrue())
					checkCallback(initialCb2, initialCb2Called)
					checkCallback(initialCb3, initialCb3Called)
				})

				It("processes a frame that overlaps at the beginning and at the end, starting in a gap, ending in data", func() {
					cb, called := getCallback()
					// 400 to 1600
					Expect(s.Push(bytes.Repeat([]byte{9}, 1200), 400, cb)).To(Succeed())
					Expect(s.queue).To(HaveKey(protocol.ByteCount(400)))
					Expect(s.queue).To(HaveKey(protocol.ByteCount(1500)))
					Expect(s.queue[400].Data).To(Equal(bytes.Repeat([]byte{9}, 1100))) // 400 to 1500
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 400},
						{Start: 2000, End: 2500},
						{Start: 3000, End: protocol.MaxByteCount},
					})
					checkCallback(cb, called)
					// initial1 spans from 500 - 1000, and should have been deleted
					Expect(*initialCb1Called).To(BeTrue())
					checkCallback(initialCb2, initialCb2Called)
					checkCallback(initialCb3, initialCb3Called)
				})

				It("processes a frame that overlaps at the beginning and at the end, starting in a gap, ending in data", func() {
					cb, called := getCallback()
					// 500 to 2100
					Expect(s.Push(bytes.Repeat([]byte{9}, 1600), 500, cb)).To(Succeed())
					Expect(s.queue).To(HaveKey(protocol.ByteCount(500)))
					Expect(s.queue[500].Data).To(Equal(bytes.Repeat([]byte{9}, 1600))) // 500 to 2100
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(1000)))
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(1500)))
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 500},
						{Start: 2100, End: 2500},
						{Start: 3000, End: protocol.MaxByteCount},
					})
					checkCallback(cb, called)
					// initial1 spans from 500 - 1000, and should have been deleted
					Expect(*initialCb1Called).To(BeTrue())
					// initial2 spans from 1500 - 2000, and should have been deleted
					Expect(*initialCb2Called).To(BeTrue())
					checkCallback(initialCb3, initialCb3Called)
				})

				It("processes a frame that closes multiple gaps, beginning in a gap", func() {
					cb, called := getCallback()
					// 400 to 3100
					Expect(s.Push(bytes.Repeat([]byte{9}, 2700), 400, cb)).To(Succeed())
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(500)))
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(1500)))
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(2500)))
					Expect(s.queue).To(HaveKey(protocol.ByteCount(400)))
					Expect(s.queue[400].Data).To(Equal(bytes.Repeat([]byte{9}, 2700))) // 400 to 3100
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 400},
						{Start: 3100, End: protocol.MaxByteCount},
					})
					checkCallback(cb, called)
					// initial1 spans from 500 - 1000, and should have been deleted
					Expect(*initialCb1Called).To(BeTrue())
					// initial2 spans from 1500 - 2000, and should have been deleted
					Expect(*initialCb2Called).To(BeTrue())
					// initial3 spans from 2500 - 3100, and should have been deleted
					Expect(*initialCb3Called).To(BeTrue())
				})

				It("processes a frame that closes multiple gaps, beginning at the end of a gap", func() {
					cb, called := getCallback()
					// 500 to 2600
					Expect(s.Push(bytes.Repeat([]byte{9}, 2100), 500, cb)).To(Succeed())
					Expect(s.queue).To(HaveKey(protocol.ByteCount(500)))
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(1000)))
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(1500)))
					Expect(s.queue).To(HaveKey(protocol.ByteCount(2500)))
					Expect(s.queue[500].Data).To(Equal(bytes.Repeat([]byte{9}, 2000))) // 500 to 2500
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 500},
						{Start: 3000, End: protocol.MaxByteCount},
					})
					checkCallback(cb, called)
					// initial1 spans from 500 - 1000, and should have been deleted
					Expect(*initialCb1Called).To(BeTrue())
					// initial2 spans from 1500 - 2000, and should have been deleted
					Expect(*initialCb2Called).To(BeTrue())
					checkCallback(initialCb3, initialCb3Called)
				})

				It("processes a frame that covers multiple gaps and ends at the end of a gap", func() {
					cb, called := getCallback()
					// 100 to 1500
					Expect(s.Push(bytes.Repeat([]byte{9}, 1400), 100, cb)).To(Succeed())
					Expect(s.queue).To(HaveKey(protocol.ByteCount(100)))
					Expect(s.queue).To(HaveKey(protocol.ByteCount(1500)))
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(500)))
					Expect(s.queue[100].Data).To(Equal(bytes.Repeat([]byte{9}, 1400))) // 100 to 1500
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 100},
						{Start: 2000, End: 2500},
						{Start: 3000, End: protocol.MaxByteCount},
					})
					checkCallback(cb, called)
					// initial1 spans from 500 - 1000, and should have been deleted
					Expect(*initialCb1Called).To(BeTrue())
					checkCallback(initialCb2, initialCb2Called)
					checkCallback(initialCb3, initialCb3Called)
				})

				It("processes a frame that closes all gaps (except for the last one)", func() {
					cb, called := getCallback()
					// 0 to 3100
					Expect(s.Push(bytes.Repeat([]byte{9}, 3100), 0, cb)).To(Succeed())
					Expect(s.queue).To(HaveLen(1))
					Expect(s.queue).To(HaveKey(protocol.ByteCount(0)))
					Expect(s.queue[0].Data).To(Equal(bytes.Repeat([]byte{9}, 3100))) // 0 to 3100
					checkGaps([]utils.ByteInterval{
						{Start: 3100, End: protocol.MaxByteCount},
					})
					checkCallback(cb, called)
					// initial1 spans from 500 - 1000, and should have been deleted
					Expect(*initialCb1Called).To(BeTrue())
					Expect(*initialCb2Called).To(BeTrue())
					Expect(*initialCb3Called).To(BeTrue())
				})
			})

			Context("duplicate data", func() {
				var initialCb1, initialCb2 func()
				var initialCb1Called, initialCb2Called *bool

				BeforeEach(func() {
					// make sure frames are not cut when we overlap a little bit
					Expect(protocol.MinStreamFrameBufferSize).To(BeNumerically("<", 500/2))
					initialCb1, initialCb1Called = getCallback()
					initialCb2, initialCb2Called = getCallback()
					// create gaps: 500 - 1000, 1500 - inf
					Expect(s.Push(bytes.Repeat([]byte{1}, 500), 0, initialCb1)).To(Succeed())
					Expect(s.Push(bytes.Repeat([]byte{2}, 500), 1000, initialCb1)).To(Succeed())
					checkGaps([]utils.ByteInterval{
						{Start: 500, End: 1000},
						{Start: 1500, End: protocol.MaxByteCount},
					})
				})

				AfterEach(func() {
					// check that the gaps were not modified
					checkGaps([]utils.ByteInterval{
						{Start: 500, End: 1000},
						{Start: 1500, End: protocol.MaxByteCount},
					})
				})

				It("does not modify data when receiving a duplicate", func() {
					cb, called := getCallback()
					// 0 to 500
					Expect(s.Push(bytes.Repeat([]byte{9}, 500), 0, cb)).To(Succeed())
					Expect(s.queue).To(HaveKey(protocol.ByteCount(0)))
					Expect(s.queue[0].Data).ToNot(Equal(bytes.Repeat([]byte{9}, 500)))
					Expect(*called).To(BeTrue())
					checkCallback(initialCb1, initialCb1Called)
					checkCallback(initialCb2, initialCb2Called)
				})

				It("detects a duplicate frame that is smaller than the original, starting at the beginning", func() {
					cb, called := getCallback()
					// 1000 to 1200
					Expect(s.Push(bytes.Repeat([]byte{9}, 200), 1000, cb)).To(Succeed())
					Expect(s.queue).To(HaveKey(protocol.ByteCount(1000)))
					Expect(s.queue[1000].Data).ToNot(Equal(bytes.Repeat([]byte{9}, 200)))
					Expect(*called).To(BeTrue())
					checkCallback(initialCb1, initialCb1Called)
					checkCallback(initialCb2, initialCb2Called)
				})

				It("detects a duplicate frame that is smaller than the original, somewhere in the middle", func() {
					cb, called := getCallback()
					// 100 to 400
					Expect(s.Push(bytes.Repeat([]byte{9}, 300), 100, cb)).To(Succeed())
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(100)))
					Expect(s.queue[0].Data).To(Equal(bytes.Repeat([]byte{1}, 500)))
					Expect(*called).To(BeTrue())
					checkCallback(initialCb1, initialCb1Called)
					checkCallback(initialCb2, initialCb2Called)
				})

				It("detects a duplicate frame that is smaller than the original, somewhere in the middle in the last block", func() {
					cb, called := getCallback()
					// 1100 to 1400
					Expect(s.Push(bytes.Repeat([]byte{9}, 300), 1100, cb)).To(Succeed())
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(1100)))
					Expect(s.queue[1000].Data).To(Equal(bytes.Repeat([]byte{2}, 500)))
					Expect(*called).To(BeTrue())
					checkCallback(initialCb1, initialCb1Called)
					checkCallback(initialCb2, initialCb2Called)
				})

				It("detects a duplicate frame that is smaller than the original, somewhere in the middle in the last block", func() {
					cb, called := getCallback()
					// 1100 to 1500
					Expect(s.Push(bytes.Repeat([]byte{9}, 400), 1100, cb)).To(Succeed())
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(1100)))
					Expect(s.queue[1000].Data).To(Equal(bytes.Repeat([]byte{2}, 500)))
					Expect(*called).To(BeTrue())
					checkCallback(initialCb1, initialCb1Called)
					checkCallback(initialCb2, initialCb2Called)
				})

				It("detects a duplicate frame that is smaller than the original, with aligned end", func() {
					cb, called := getCallback()
					// 300 to 500
					Expect(s.Push(bytes.Repeat([]byte{9}, 200), 300, cb)).To(Succeed())
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(300)))
					Expect(s.queue[0].Data).To(Equal(bytes.Repeat([]byte{1}, 500)))
					Expect(*called).To(BeTrue())
					checkCallback(initialCb1, initialCb1Called)
					checkCallback(initialCb2, initialCb2Called)
				})
			})

			Context("cutting short frames", func() {
				var initialCb1, initialCb2 func()
				var initialCb1Called, initialCb2Called *bool

				// create gaps: 0-5, 10-15, 2000-inf
				BeforeEach(func() {
					// make sure frames are not cut when we overlap a little bit
					Expect(protocol.MinStreamFrameBufferSize).To(BeNumerically(">", 10))
					initialCb1, initialCb1Called = getCallback()
					initialCb2, initialCb2Called = getCallback()
					Expect(s.Push(bytes.Repeat([]byte{1}, 5), 5, initialCb1)).To(Succeed())
					Expect(s.Push(bytes.Repeat([]byte{2}, 5), 15, initialCb2)).To(Succeed())
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 5},
						{Start: 10, End: 15},
						{Start: 20, End: protocol.MaxByteCount},
					})
				})

				It("cuts a frame that overlaps with received data at the beginning", func() {
					cb, called := getCallback()
					// 9 to 12
					Expect(s.Push(bytes.Repeat([]byte{9}, 3), 9, cb)).To(Succeed())
					Expect(s.queue).ToNot(HaveKey(protocol.ByteCount(9)))
					Expect(s.queue).To(HaveKey(protocol.ByteCount(10)))
					Expect(s.queue[10].Data).To(Equal(bytes.Repeat([]byte{9}, 2))) // 10 to 12
					Expect(s.queue[10].Data).To(HaveCap(2))
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 5},
						{Start: 12, End: 15},
						{Start: 20, End: protocol.MaxByteCount},
					})
					Expect(*called).To(BeTrue())
					checkCallback(initialCb1, initialCb1Called)
					checkCallback(initialCb2, initialCb2Called)
				})

				It("cuts a frame that overlaps with received data at the end", func() {
					cb, called := getCallback()
					// 12 to 19
					Expect(s.Push(bytes.Repeat([]byte{9}, 7), 12, cb)).To(Succeed())
					Expect(s.queue).To(HaveKey(protocol.ByteCount(12)))
					Expect(s.queue[12].Data).To(Equal(bytes.Repeat([]byte{9}, 3))) // 12 to 15
					Expect(s.queue[12].Data).To(HaveCap(3))
					checkGaps([]utils.ByteInterval{
						{Start: 0, End: 5},
						{Start: 10, End: 12},
						{Start: 20, End: protocol.MaxByteCount},
					})
					Expect(*called).To(BeTrue())
					checkCallback(initialCb1, initialCb1Called)
					checkCallback(initialCb2, initialCb2Called)
				})
			})

			Context("DoS protection", func() {
				It("errors when too many gaps are created", func() {
					for i := 0; i < protocol.MaxStreamFrameSorterGaps; i++ {
						Expect(s.Push([]byte("foobar"), protocol.ByteCount(i*7), nil)).To(Succeed())
					}
					Expect(s.gaps.Len()).To(Equal(protocol.MaxStreamFrameSorterGaps))
					err := s.Push([]byte("foobar"), protocol.ByteCount(protocol.MaxStreamFrameSorterGaps*7)+100, nil)
					Expect(err).To(MatchError("too many gaps in received data"))
				})
			})
		})
	})
})
