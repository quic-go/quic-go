package quic

import (
	"bytes"
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("frame sorter", func() {
	var s *frameSorter

	checkGaps := func(expectedGaps []byteInterval) {
		if s.gaps.Len() != len(expectedGaps) {
			fmt.Println("Gaps:")
			for gap := s.gaps.Front(); gap != nil; gap = gap.Next() {
				fmt.Printf("\t%d - %d\n", gap.Value.Start, gap.Value.End)
			}
			ExpectWithOffset(1, s.gaps.Len()).To(Equal(len(expectedGaps)))
		}
		var i int
		for gap := s.gaps.Front(); gap != nil; gap = gap.Next() {
			ExpectWithOffset(1, gap.Value).To(Equal(expectedGaps[i]))
			i++
		}
	}

	type callbackTracker struct {
		called *bool
		cb     func()
	}

	getCallback := func() (func(), callbackTracker) {
		var called bool
		cb := func() {
			if called {
				panic("double free")
			}
			called = true
		}
		return cb, callbackTracker{
			cb:     cb,
			called: &called,
		}
	}

	checkCallbackCalled := func(t callbackTracker) {
		ExpectWithOffset(1, *t.called).To(BeTrue())
	}

	checkCallbackNotCalled := func(t callbackTracker) {
		ExpectWithOffset(1, *t.called).To(BeFalse())
		t.cb()
		ExpectWithOffset(1, *t.called).To(BeTrue())
	}

	BeforeEach(func() {
		s = newFrameSorter()
	})

	It("returns nil when empty", func() {
		_, data, doneCb := s.Pop()
		Expect(data).To(BeNil())
		Expect(doneCb).To(BeNil())
	})

	It("inserts and pops a single frame", func() {
		cb, t := getCallback()
		Expect(s.Push([]byte("foobar"), 0, cb)).To(Succeed())
		offset, data, doneCb := s.Pop()
		Expect(offset).To(BeZero())
		Expect(data).To(Equal([]byte("foobar")))
		Expect(doneCb).ToNot(BeNil())
		checkCallbackNotCalled(t)
		offset, data, doneCb = s.Pop()
		Expect(offset).To(Equal(protocol.ByteCount(6)))
		Expect(data).To(BeNil())
		Expect(doneCb).To(BeNil())
	})

	It("inserts and pops two consecutive frame", func() {
		cb1, t1 := getCallback()
		cb2, t2 := getCallback()
		Expect(s.Push([]byte("bar"), 3, cb2)).To(Succeed())
		Expect(s.Push([]byte("foo"), 0, cb1)).To(Succeed())
		offset, data, doneCb := s.Pop()
		Expect(offset).To(BeZero())
		Expect(data).To(Equal([]byte("foo")))
		Expect(doneCb).ToNot(BeNil())
		doneCb()
		checkCallbackCalled(t1)
		offset, data, doneCb = s.Pop()
		Expect(offset).To(Equal(protocol.ByteCount(3)))
		Expect(data).To(Equal([]byte("bar")))
		Expect(doneCb).ToNot(BeNil())
		doneCb()
		checkCallbackCalled(t2)
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
		var dataCounter uint8

		BeforeEach(func() {
			dataCounter = 0
		})

		checkQueue := func(m map[protocol.ByteCount][]byte) {
			ExpectWithOffset(1, s.queue).To(HaveLen(len(m)))
			for offset, data := range m {
				ExpectWithOffset(1, s.queue).To(HaveKey(offset))
				ExpectWithOffset(1, s.queue[offset].Data).To(Equal(data))
			}
		}

		getData := func(l protocol.ByteCount) []byte {
			dataCounter++
			return bytes.Repeat([]byte{dataCounter}, int(l))
		}

		// ---xxx--------------
		//       ++++++
		// =>
		// ---xxx++++++--------
		It("case 1", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(5)
			cb2, t2 := getCallback()
			Expect(s.Push(f1, 3, cb1)).To(Succeed()) // 3 - 6
			Expect(s.Push(f2, 6, cb2)).To(Succeed()) // 6 - 11
			checkQueue(map[protocol.ByteCount][]byte{
				3: f1,
				6: f2,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 11, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackNotCalled(t2)
		})

		// ---xxx-----------------
		//          +++++++
		// =>
		// ---xxx---+++++++--------
		It("case 2", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(5)
			cb2, t2 := getCallback()
			Expect(s.Push(f1, 3, cb1)).To(Succeed())  // 3 - 6
			Expect(s.Push(f2, 10, cb2)).To(Succeed()) // 10 -15
			checkQueue(map[protocol.ByteCount][]byte{
				3:  f1,
				10: f2,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 6, End: 10},
				{Start: 15, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackNotCalled(t2)
		})

		// ---xxx----xxxxxx-------
		//       ++++
		// =>
		// ---xxx++++xxxxx--------
		It("case 3", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(4)
			cb2, t2 := getCallback()
			f3 := getData(5)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3, cb1)).To(Succeed())  // 3 - 6
			Expect(s.Push(f3, 10, cb2)).To(Succeed()) // 10 - 15
			Expect(s.Push(f2, 6, cb3)).To(Succeed())  // 6 - 10
			checkQueue(map[protocol.ByteCount][]byte{
				3:  f1,
				6:  f2,
				10: f3,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 15, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackNotCalled(t2)
			checkCallbackNotCalled(t3)
		})

		// ----xxxx-------
		//       ++++
		// =>
		// ----xxxx++-----
		It("case 4", func() {
			f1 := getData(4)
			cb1, t1 := getCallback()
			f2 := getData(4)
			cb2, t2 := getCallback()
			Expect(s.Push(f1, 3, cb1)).To(Succeed()) // 3 - 7
			Expect(s.Push(f2, 5, cb2)).To(Succeed()) // 5 - 9
			checkQueue(map[protocol.ByteCount][]byte{
				3: f1,
				7: f2[2:],
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 9, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackCalled(t2)
		})

		It("case 4, for long frames", func() {
			mult := protocol.ByteCount(math.Ceil(float64(protocol.MinStreamFrameSize) / 2))
			f1 := getData(4 * mult)
			cb1, t1 := getCallback()
			f2 := getData(4 * mult)
			cb2, t2 := getCallback()
			Expect(s.Push(f1, 3*mult, cb1)).To(Succeed()) // 3 - 7
			Expect(s.Push(f2, 5*mult, cb2)).To(Succeed()) // 5 - 9
			checkQueue(map[protocol.ByteCount][]byte{
				3 * mult: f1,
				7 * mult: f2[2*mult:],
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3 * mult},
				{Start: 9 * mult, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackNotCalled(t2)
		})

		// xxxx-------
		//    ++++
		// =>
		// xxxx+++-----
		It("case 5", func() {
			f1 := getData(4)
			cb1, t1 := getCallback()
			f2 := getData(4)
			cb2, t2 := getCallback()
			Expect(s.Push(f1, 0, cb1)).To(Succeed()) // 0 - 4
			Expect(s.Push(f2, 3, cb2)).To(Succeed()) // 3 - 7
			checkQueue(map[protocol.ByteCount][]byte{
				0: f1,
				4: f2[1:],
			})
			checkGaps([]byteInterval{
				{Start: 7, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackCalled(t2)
		})

		It("case 5, for long frames", func() {
			mult := protocol.ByteCount(math.Ceil(float64(protocol.MinStreamFrameSize) / 2))
			f1 := getData(4 * mult)
			cb1, t1 := getCallback()
			f2 := getData(4 * mult)
			cb2, t2 := getCallback()
			Expect(s.Push(f1, 0, cb1)).To(Succeed())      // 0 - 4
			Expect(s.Push(f2, 3*mult, cb2)).To(Succeed()) // 3 - 7
			checkQueue(map[protocol.ByteCount][]byte{
				0:        f1,
				4 * mult: f2[mult:],
			})
			checkGaps([]byteInterval{
				{Start: 7 * mult, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackNotCalled(t2)
		})

		// ----xxxx-------
		//   ++++
		// =>
		// --++xxxx-------
		It("case 6", func() {
			f1 := getData(4)
			cb1, t1 := getCallback()
			f2 := getData(4)
			cb2, t2 := getCallback()
			Expect(s.Push(f1, 5, cb1)).To(Succeed()) // 5 - 9
			Expect(s.Push(f2, 3, cb2)).To(Succeed()) // 3 - 7
			checkQueue(map[protocol.ByteCount][]byte{
				3: f2[:2],
				5: f1,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 9, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackCalled(t2)
		})

		It("case 6, for long frames", func() {
			mult := protocol.ByteCount(math.Ceil(float64(protocol.MinStreamFrameSize) / 2))
			f1 := getData(4 * mult)
			cb1, t1 := getCallback()
			f2 := getData(4 * mult)
			cb2, t2 := getCallback()
			Expect(s.Push(f1, 5*mult, cb1)).To(Succeed()) // 5 - 9
			Expect(s.Push(f2, 3*mult, cb2)).To(Succeed()) // 3 - 7
			checkQueue(map[protocol.ByteCount][]byte{
				3 * mult: f2[:2*mult],
				5 * mult: f1,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3 * mult},
				{Start: 9 * mult, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackNotCalled(t2)
		})

		// ---xxx----xxxxxx-------
		//       ++
		// =>
		// ---xxx++--xxxxx--------
		It("case 7", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(2)
			cb2, t2 := getCallback()
			f3 := getData(5)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3, cb1)).To(Succeed())  // 3 - 6
			Expect(s.Push(f3, 10, cb2)).To(Succeed()) // 10 - 15
			Expect(s.Push(f2, 6, cb3)).To(Succeed())  // 6 - 8
			checkQueue(map[protocol.ByteCount][]byte{
				3:  f1,
				6:  f2,
				10: f3,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 8, End: 10},
				{Start: 15, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackNotCalled(t2)
			checkCallbackNotCalled(t3)
		})

		// ---xxx---------xxxxxx--
		//          ++
		// =>
		// ---xxx---++----xxxxx--
		It("case 8", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(2)
			cb2, t2 := getCallback()
			f3 := getData(5)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3, cb1)).To(Succeed())  // 3 - 6
			Expect(s.Push(f3, 15, cb2)).To(Succeed()) // 15 - 20
			Expect(s.Push(f2, 10, cb3)).To(Succeed()) // 10 - 12
			checkQueue(map[protocol.ByteCount][]byte{
				3:  f1,
				10: f2,
				15: f3,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 6, End: 10},
				{Start: 12, End: 15},
				{Start: 20, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackNotCalled(t2)
			checkCallbackNotCalled(t3)
		})

		// ---xxx----xxxxxx-------
		//         ++
		// =>
		// ---xxx--++xxxxx--------
		It("case 9", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(2)
			cb2, t2 := getCallback()
			cb3, t3 := getCallback()
			f3 := getData(5)
			Expect(s.Push(f1, 3, cb1)).To(Succeed())  // 3 - 6
			Expect(s.Push(f3, 10, cb2)).To(Succeed()) // 10 - 15
			Expect(s.Push(f2, 8, cb3)).To(Succeed())  // 8 - 10
			checkQueue(map[protocol.ByteCount][]byte{
				3:  f1,
				8:  f2,
				10: f3,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 6, End: 8},
				{Start: 15, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackNotCalled(t2)
			checkCallbackNotCalled(t3)
		})

		// ---xxx----=====-------
		//      +++++++
		// =>
		// ---xxx++++=====--------
		It("case 10", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(5)
			cb2, t2 := getCallback()
			f3 := getData(6)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3, cb1)).To(Succeed())  // 3 - 6
			Expect(s.Push(f2, 10, cb2)).To(Succeed()) // 10 - 15
			Expect(s.Push(f3, 5, cb3)).To(Succeed())  // 5 - 11
			checkQueue(map[protocol.ByteCount][]byte{
				3:  f1,
				6:  f3[1:5],
				10: f2,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 15, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackNotCalled(t2)
			checkCallbackCalled(t3)
		})

		It("case 10, for long frames", func() {
			mult := protocol.ByteCount(math.Ceil(float64(protocol.MinStreamFrameSize) / 4))
			f1 := getData(3 * mult)
			cb1, t1 := getCallback()
			f2 := getData(5 * mult)
			cb2, t2 := getCallback()
			f3 := getData(6 * mult)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3*mult, cb1)).To(Succeed())  // 3 - 6
			Expect(s.Push(f2, 10*mult, cb2)).To(Succeed()) // 10 - 15
			Expect(s.Push(f3, 5*mult, cb3)).To(Succeed())  // 5 - 11
			checkQueue(map[protocol.ByteCount][]byte{
				3 * mult:  f1,
				6 * mult:  f3[mult : 5*mult],
				10 * mult: f2,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3 * mult},
				{Start: 15 * mult, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackNotCalled(t2)
			checkCallbackNotCalled(t3)
		})

		// ---xxxx----=====-------
		//      ++++++
		// =>
		// ---xxx++++=====--------
		It("case 11", func() {
			f1 := getData(4)
			cb1, t1 := getCallback()
			f2 := getData(5)
			cb2, t2 := getCallback()
			f3 := getData(5)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3, cb1)).To(Succeed())  // 3 - 7
			Expect(s.Push(f2, 10, cb2)).To(Succeed()) // 10 - 15
			Expect(s.Push(f3, 5, cb3)).To(Succeed())  // 5 - 10
			checkQueue(map[protocol.ByteCount][]byte{
				3:  f1,
				7:  f3[2:],
				10: f2,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 15, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackNotCalled(t2)
			checkCallbackCalled(t3)
		})

		// ---xxxx----=====-------
		//      ++++++
		// =>
		// ---xxx++++=====--------
		It("case 11, for long frames", func() {
			mult := protocol.ByteCount(math.Ceil(float64(protocol.MinStreamFrameSize) / 3))
			f1 := getData(4 * mult)
			cb1, t1 := getCallback()
			f2 := getData(5 * mult)
			cb2, t2 := getCallback()
			f3 := getData(5 * mult)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3*mult, cb1)).To(Succeed())  // 3 - 7
			Expect(s.Push(f2, 10*mult, cb2)).To(Succeed()) // 10 - 15
			Expect(s.Push(f3, 5*mult, cb3)).To(Succeed())  // 5 - 10
			checkQueue(map[protocol.ByteCount][]byte{
				3 * mult:  f1,
				7 * mult:  f3[2*mult:],
				10 * mult: f2,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3 * mult},
				{Start: 15 * mult, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackNotCalled(t2)
			checkCallbackNotCalled(t3)
		})

		// ----xxxx-------
		//     +++++++
		// =>
		// ----+++++++-----
		It("case 12", func() {
			f1 := getData(4)
			cb1, t1 := getCallback()
			f2 := getData(7)
			cb2, t2 := getCallback()
			Expect(s.Push(f1, 3, cb1)).To(Succeed()) // 3 - 7
			Expect(s.Push(f2, 3, cb2)).To(Succeed()) // 3 - 10
			checkQueue(map[protocol.ByteCount][]byte{
				3: f2,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 10, End: protocol.MaxByteCount},
			})
			checkCallbackCalled(t1)
			checkCallbackNotCalled(t2)
		})

		// ----xxx===-------
		//     +++++++
		// =>
		// ----+++++++-----
		It("case 13", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(3)
			cb2, t2 := getCallback()
			f3 := getData(7)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3, cb1)).To(Succeed()) // 3 - 6
			Expect(s.Push(f2, 6, cb2)).To(Succeed()) // 6 - 9
			Expect(s.Push(f3, 3, cb3)).To(Succeed()) // 3 - 10
			checkQueue(map[protocol.ByteCount][]byte{
				3: f3,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 10, End: protocol.MaxByteCount},
			})
			checkCallbackCalled(t1)
			checkCallbackCalled(t2)
			checkCallbackNotCalled(t3)
		})

		// ----xxx====-------
		//     +++++
		// =>
		// ----+++====-----
		It("case 14", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(4)
			cb2, t2 := getCallback()
			f3 := getData(5)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3, cb1)).To(Succeed()) // 3 - 6
			Expect(s.Push(f2, 6, cb2)).To(Succeed()) // 6 - 10
			Expect(s.Push(f3, 3, cb3)).To(Succeed()) // 3 - 8
			checkQueue(map[protocol.ByteCount][]byte{
				3: f3[:3],
				6: f2,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 10, End: protocol.MaxByteCount},
			})
			checkCallbackCalled(t1)
			checkCallbackNotCalled(t2)
			checkCallbackCalled(t3)
		})

		It("case 14, for long frames", func() {
			mult := protocol.ByteCount(math.Ceil(float64(protocol.MinStreamFrameSize) / 3))
			f1 := getData(3 * mult)
			cb1, t1 := getCallback()
			f2 := getData(4 * mult)
			cb2, t2 := getCallback()
			f3 := getData(5 * mult)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3*mult, cb1)).To(Succeed()) // 3 - 6
			Expect(s.Push(f2, 6*mult, cb2)).To(Succeed()) // 6 - 10
			Expect(s.Push(f3, 3*mult, cb3)).To(Succeed()) // 3 - 8
			checkQueue(map[protocol.ByteCount][]byte{
				3 * mult: f3[:3*mult],
				6 * mult: f2,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3 * mult},
				{Start: 10 * mult, End: protocol.MaxByteCount},
			})
			checkCallbackCalled(t1)
			checkCallbackNotCalled(t2)
			checkCallbackNotCalled(t3)
		})

		// ----xxx===-------
		//     ++++++
		// =>
		// ----++++++-----
		It("case 15", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(3)
			cb2, t2 := getCallback()
			f3 := getData(6)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3, cb1)).To(Succeed()) // 3 - 6
			Expect(s.Push(f2, 6, cb2)).To(Succeed()) // 6 - 9
			Expect(s.Push(f3, 3, cb3)).To(Succeed()) // 3 - 9
			checkQueue(map[protocol.ByteCount][]byte{
				3: f3,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 9, End: protocol.MaxByteCount},
			})
			checkCallbackCalled(t1)
			checkCallbackCalled(t2)
			checkCallbackNotCalled(t3)
		})

		// ---xxxx-------
		//    ++++
		// =>
		// ---xxxx-----
		It("case 16", func() {
			f1 := getData(4)
			cb1, t1 := getCallback()
			f2 := getData(4)
			cb2, t2 := getCallback()
			Expect(s.Push(f1, 5, cb1)).To(Succeed()) // 5 - 9
			Expect(s.Push(f2, 5, cb2)).To(Succeed()) // 5 - 9
			checkQueue(map[protocol.ByteCount][]byte{
				5: f1,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 5},
				{Start: 9, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackCalled(t2)
		})

		// ----xxx===-------
		//     +++
		// =>
		// ----xxx===-----
		It("case 17", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(3)
			cb2, t2 := getCallback()
			f3 := getData(3)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3, cb1)).To(Succeed()) // 3 - 6
			Expect(s.Push(f2, 6, cb2)).To(Succeed()) // 6 - 9
			Expect(s.Push(f3, 3, cb3)).To(Succeed()) // 3 - 6
			checkQueue(map[protocol.ByteCount][]byte{
				3: f1,
				6: f2,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 9, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackNotCalled(t2)
			checkCallbackCalled(t3)
		})

		// ---xxxx-------
		//    ++
		// =>
		// ---xxxx-----
		It("case 18", func() {
			f1 := getData(4)
			cb1, t1 := getCallback()
			f2 := getData(2)
			cb2, t2 := getCallback()
			Expect(s.Push(f1, 5, cb1)).To(Succeed()) // 5 - 9
			Expect(s.Push(f2, 5, cb2)).To(Succeed()) // 5 - 7
			checkQueue(map[protocol.ByteCount][]byte{
				5: f1,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 5},
				{Start: 9, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackCalled(t2)
		})

		// ---xxxxx------
		//     ++
		// =>
		// ---xxxxx----
		It("case 19", func() {
			f1 := getData(5)
			cb1, t1 := getCallback()
			f2 := getData(2)
			cb2, t2 := getCallback()
			Expect(s.Push(f1, 5, cb1)).To(Succeed()) // 5 - 10
			checkQueue(map[protocol.ByteCount][]byte{
				5: f1,
			})
			Expect(s.Push(f2, 6, cb2)).To(Succeed()) // 6 - 8
			checkQueue(map[protocol.ByteCount][]byte{
				5: f1,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 5},
				{Start: 10, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackCalled(t2)
		})

		// xxxxx------
		//  ++
		// =>
		// xxxxx------
		It("case 20", func() {
			f1 := getData(10)
			cb1, t1 := getCallback()
			f2 := getData(4)
			cb2, t2 := getCallback()
			Expect(s.Push(f1, 0, cb1)).To(Succeed()) // 0 - 10
			Expect(s.Push(f2, 5, cb2)).To(Succeed()) // 5 - 9
			checkQueue(map[protocol.ByteCount][]byte{
				0: f1,
			})
			checkGaps([]byteInterval{
				{Start: 10, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackCalled(t2)
		})

		// ---xxxxx---
		//      +++
		// =>
		// ---xxxxx---
		It("case 21", func() {
			f1 := getData(5)
			cb1, t1 := getCallback()
			f2 := getData(3)
			cb2, t2 := getCallback()
			Expect(s.Push(f1, 5, cb1)).To(Succeed()) // 5 - 10
			Expect(s.Push(f2, 7, cb2)).To(Succeed()) // 7 - 10
			checkGaps([]byteInterval{
				{Start: 0, End: 5},
				{Start: 10, End: protocol.MaxByteCount},
			})
			checkQueue(map[protocol.ByteCount][]byte{
				5: f1,
			})
			checkCallbackNotCalled(t1)
			checkCallbackCalled(t2)
		})

		// ----xxx------
		//   +++++
		// =>
		// --+++++----
		It("case 22", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(5)
			cb2, t2 := getCallback()
			Expect(s.Push(f1, 5, cb1)).To(Succeed()) // 5 - 8
			Expect(s.Push(f2, 3, cb2)).To(Succeed()) // 3 - 8
			checkQueue(map[protocol.ByteCount][]byte{
				3: f2,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 8, End: protocol.MaxByteCount},
			})
			checkCallbackCalled(t1)
			checkCallbackNotCalled(t2)
		})

		// ----xxx===------
		//   ++++++++
		// =>
		// --++++++++----
		It("case 23", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(3)
			cb2, t2 := getCallback()
			f3 := getData(8)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 5, cb1)).To(Succeed()) // 5 - 8
			Expect(s.Push(f2, 8, cb2)).To(Succeed()) // 8 - 11
			Expect(s.Push(f3, 3, cb3)).To(Succeed()) // 3 - 11
			checkQueue(map[protocol.ByteCount][]byte{
				3: f3,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 11, End: protocol.MaxByteCount},
			})
			checkCallbackCalled(t1)
			checkCallbackCalled(t2)
			checkCallbackNotCalled(t3)
		})

		// --xxx---===---
		//      ++++++
		// =>
		// --xxx++++++----
		It("case 24", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(3)
			cb2, t2 := getCallback()
			f3 := getData(6)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3, cb1)).To(Succeed()) // 3 - 6
			Expect(s.Push(f2, 9, cb2)).To(Succeed()) // 9 - 12
			Expect(s.Push(f3, 6, cb3)).To(Succeed()) // 6 - 12
			checkQueue(map[protocol.ByteCount][]byte{
				3: f1,
				6: f3,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 12, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackCalled(t2)
			checkCallbackNotCalled(t3)
		})

		// --xxx---===---###
		//      +++++++++
		// =>
		// --xxx+++++++++###
		It("case 25", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(3)
			cb2, t2 := getCallback()
			f3 := getData(3)
			cb3, t3 := getCallback()
			f4 := getData(9)
			cb4, t4 := getCallback()
			Expect(s.Push(f1, 3, cb1)).To(Succeed())  // 3 - 6
			Expect(s.Push(f2, 9, cb2)).To(Succeed())  // 9 - 12
			Expect(s.Push(f3, 15, cb3)).To(Succeed()) // 15 - 18
			Expect(s.Push(f4, 6, cb4)).To(Succeed())  // 6 - 15
			checkQueue(map[protocol.ByteCount][]byte{
				3:  f1,
				6:  f4,
				15: f3,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 18, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackCalled(t2)
			checkCallbackNotCalled(t3)
			checkCallbackNotCalled(t4)
		})

		// ----xxx------
		//   +++++++
		// =>
		// --+++++++---
		It("case 26", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(10)
			cb2, t2 := getCallback()
			Expect(s.Push(f1, 5, cb1)).To(Succeed()) // 5 - 8
			Expect(s.Push(f2, 3, cb2)).To(Succeed()) // 3 - 13
			checkQueue(map[protocol.ByteCount][]byte{
				3: f2,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 13, End: protocol.MaxByteCount},
			})
			checkCallbackCalled(t1)
			checkCallbackNotCalled(t2)
		})

		// ---xxx====---
		//   ++++
		// =>
		// --+xxx====---
		It("case 27", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(4)
			cb2, t2 := getCallback()
			f3 := getData(4)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3, cb1)).To(Succeed()) // 3 - 6
			Expect(s.Push(f2, 6, cb2)).To(Succeed()) // 6 - 10
			Expect(s.Push(f3, 2, cb3)).To(Succeed()) // 2 - 6
			checkQueue(map[protocol.ByteCount][]byte{
				2: f3[:1],
				3: f1,
				6: f2,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 2},
				{Start: 10, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackNotCalled(t2)
			checkCallbackCalled(t3)
		})

		It("case 27, for long frames", func() {
			const mult = protocol.MinStreamFrameSize
			f1 := getData(3 * mult)
			cb1, t1 := getCallback()
			f2 := getData(4 * mult)
			cb2, t2 := getCallback()
			f3 := getData(4 * mult)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3*mult, cb1)).To(Succeed()) // 3 - 6
			Expect(s.Push(f2, 6*mult, cb2)).To(Succeed()) // 6 - 10
			Expect(s.Push(f3, 2*mult, cb3)).To(Succeed()) // 2 - 6
			checkQueue(map[protocol.ByteCount][]byte{
				2 * mult: f3[:mult],
				3 * mult: f1,
				6 * mult: f2,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 2 * mult},
				{Start: 10 * mult, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackNotCalled(t2)
			checkCallbackNotCalled(t3)
		})

		// ---xxx====---
		//   ++++++
		// =>
		// --+xxx====---
		It("case 28", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(4)
			cb2, t2 := getCallback()
			f3 := getData(6)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3, cb1)).To(Succeed()) // 3 - 6
			Expect(s.Push(f2, 6, cb2)).To(Succeed()) // 6 - 10
			Expect(s.Push(f3, 2, cb3)).To(Succeed()) // 2 - 8
			checkQueue(map[protocol.ByteCount][]byte{
				2: f3[:1],
				3: f1,
				6: f2,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 2},
				{Start: 10, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackNotCalled(t2)
			checkCallbackCalled(t3)
		})

		It("case 28, for long frames", func() {
			const mult = protocol.MinStreamFrameSize
			f1 := getData(3 * mult)
			cb1, t1 := getCallback()
			f2 := getData(4 * mult)
			cb2, t2 := getCallback()
			f3 := getData(6 * mult)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3*mult, cb1)).To(Succeed()) // 3 - 6
			Expect(s.Push(f2, 6*mult, cb2)).To(Succeed()) // 6 - 10
			Expect(s.Push(f3, 2*mult, cb3)).To(Succeed()) // 2 - 8
			checkQueue(map[protocol.ByteCount][]byte{
				2 * mult: f3[:mult],
				3 * mult: f1,
				6 * mult: f2,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 2 * mult},
				{Start: 10 * mult, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackNotCalled(t2)
			checkCallbackNotCalled(t3)
		})

		// ---xxx===-----
		//       +++++
		// =>
		// ---xxx+++++---
		It("case 29", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(3)
			cb2, t2 := getCallback()
			f3 := getData(5)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3, cb1)).To(Succeed()) // 3 - 6
			Expect(s.Push(f2, 6, cb2)).To(Succeed()) // 6 - 9
			Expect(s.Push(f3, 6, cb3)).To(Succeed()) // 6 - 11
			checkQueue(map[protocol.ByteCount][]byte{
				3: f1,
				6: f3,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 11, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackCalled(t2)
			checkCallbackNotCalled(t3)
		})

		// ---xxx===----
		//      ++++++
		// =>
		// ---xxx===++--
		It("case 30", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(3)
			cb2, t2 := getCallback()
			f3 := getData(6)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3, cb1)).To(Succeed()) // 3 - 6
			Expect(s.Push(f2, 6, cb2)).To(Succeed()) // 6 - 9
			Expect(s.Push(f3, 5, cb3)).To(Succeed()) // 5 - 11
			checkQueue(map[protocol.ByteCount][]byte{
				3: f1,
				6: f2,
				9: f3[4:],
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 11, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackNotCalled(t2)
			checkCallbackCalled(t3)
		})

		It("case 30, for long frames", func() {
			mult := protocol.ByteCount(math.Ceil(float64(protocol.MinStreamFrameSize) / 2))
			f1 := getData(3 * mult)
			cb1, t1 := getCallback()
			f2 := getData(3 * mult)
			cb2, t2 := getCallback()
			f3 := getData(6 * mult)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3*mult, cb1)).To(Succeed()) // 3 - 6
			Expect(s.Push(f2, 6*mult, cb2)).To(Succeed()) // 6 - 9
			Expect(s.Push(f3, 5*mult, cb3)).To(Succeed()) // 5 - 11
			checkQueue(map[protocol.ByteCount][]byte{
				3 * mult: f1,
				6 * mult: f2,
				9 * mult: f3[4*mult:],
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3 * mult},
				{Start: 11 * mult, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackNotCalled(t2)
			checkCallbackNotCalled(t3)
		})

		// ---xxx---===-----
		//     ++++++++++
		// =>
		// ---xxx++++++++---
		It("case 31", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(3)
			cb2, t2 := getCallback()
			f3 := getData(10)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3, cb1)).To(Succeed()) // 3 - 6
			Expect(s.Push(f2, 9, cb2)).To(Succeed()) // 9 - 12
			Expect(s.Push(f3, 5, cb3)).To(Succeed()) // 5 - 15
			checkQueue(map[protocol.ByteCount][]byte{
				3: f1,
				6: f3[1:],
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 15, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackCalled(t2)
			checkCallbackCalled(t3)
		})

		It("case 31, for long frames", func() {
			mult := protocol.ByteCount(math.Ceil(float64(protocol.MinStreamFrameSize) / 9))
			f1 := getData(3 * mult)
			cb1, t1 := getCallback()
			f2 := getData(3 * mult)
			cb2, t2 := getCallback()
			f3 := getData(10 * mult)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3*mult, cb1)).To(Succeed()) // 3 - 6
			Expect(s.Push(f2, 9*mult, cb2)).To(Succeed()) // 9 - 12
			Expect(s.Push(f3, 5*mult, cb3)).To(Succeed()) // 5 - 15
			checkQueue(map[protocol.ByteCount][]byte{
				3 * mult: f1,
				6 * mult: f3[mult:],
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3 * mult},
				{Start: 15 * mult, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackCalled(t2)
			checkCallbackNotCalled(t3)
		})

		// ---xxx---===-----
		//    +++++++++
		// =>
		// ---+++++++++---
		It("case 32", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(3)
			cb2, t2 := getCallback()
			f3 := getData(9)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3, cb1)).To(Succeed()) // 3 - 6
			Expect(s.Push(f2, 9, cb2)).To(Succeed()) // 9 - 12
			Expect(s.Push(f3, 3, cb3)).To(Succeed()) // 3 - 12
			checkQueue(map[protocol.ByteCount][]byte{
				3: f3,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 12, End: protocol.MaxByteCount},
			})
			checkCallbackCalled(t1)
			checkCallbackCalled(t2)
			checkCallbackNotCalled(t3)
		})

		// ---xxx---===###-----
		//     ++++++++++++
		// =>
		// ---xxx++++++++++---
		It("case 33", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(3)
			cb2, t2 := getCallback()
			f3 := getData(3)
			cb3, t3 := getCallback()
			f4 := getData(12)
			cb4, t4 := getCallback()
			Expect(s.Push(f1, 3, cb1)).To(Succeed()) // 3 - 6
			Expect(s.Push(f2, 9, cb2)).To(Succeed()) // 9 - 12
			Expect(s.Push(f3, 9, cb3)).To(Succeed()) // 12 - 15
			Expect(s.Push(f4, 5, cb4)).To(Succeed()) // 5 - 17
			checkQueue(map[protocol.ByteCount][]byte{
				3: f1,
				6: f4[1:],
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 17, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackCalled(t2)
			checkCallbackCalled(t3)
			checkCallbackCalled(t4)
		})

		It("case 33, for long frames", func() {
			mult := protocol.ByteCount(math.Ceil(float64(protocol.MinStreamFrameSize) / 11))
			f1 := getData(3 * mult)
			cb1, t1 := getCallback()
			f2 := getData(3 * mult)
			cb2, t2 := getCallback()
			f3 := getData(3 * mult)
			cb3, t3 := getCallback()
			f4 := getData(12 * mult)
			cb4, t4 := getCallback()
			Expect(s.Push(f1, 3*mult, cb1)).To(Succeed()) // 3 - 6
			Expect(s.Push(f2, 9*mult, cb2)).To(Succeed()) // 9 - 12
			Expect(s.Push(f3, 9*mult, cb3)).To(Succeed()) // 12 - 15
			Expect(s.Push(f4, 5*mult, cb4)).To(Succeed()) // 5 - 17
			checkQueue(map[protocol.ByteCount][]byte{
				3 * mult: f1,
				6 * mult: f4[mult:],
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 3 * mult},
				{Start: 17 * mult, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackCalled(t2)
			checkCallbackCalled(t3)
			checkCallbackNotCalled(t4)
		})

		// ---xxx===---###
		//       ++++++
		// =>
		// ---xxx++++++###
		It("case 34", func() {
			f1 := getData(5)
			cb1, t1 := getCallback()
			f2 := getData(5)
			cb2, t2 := getCallback()
			f3 := getData(10)
			cb3, t3 := getCallback()
			f4 := getData(5)
			cb4, t4 := getCallback()
			Expect(s.Push(f1, 5, cb1)).To(Succeed())  // 5 - 10
			Expect(s.Push(f2, 10, cb2)).To(Succeed()) // 10 - 15
			Expect(s.Push(f4, 20, cb3)).To(Succeed()) // 20 - 25
			Expect(s.Push(f3, 10, cb4)).To(Succeed()) // 10 - 20
			checkQueue(map[protocol.ByteCount][]byte{
				5:  f1,
				10: f3,
				20: f4,
			})
			checkGaps([]byteInterval{
				{Start: 0, End: 5},
				{Start: 25, End: protocol.MaxByteCount},
			})
			checkCallbackNotCalled(t1)
			checkCallbackCalled(t2)
			checkCallbackNotCalled(t3)
			checkCallbackNotCalled(t4)
		})

		// ---xxx---####---
		//    ++++++++
		// =>
		// ---++++++####---
		It("case 35", func() {
			f1 := getData(3)
			cb1, t1 := getCallback()
			f2 := getData(4)
			cb2, t2 := getCallback()
			f3 := getData(8)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3, cb1)).To(Succeed()) // 3 - 6
			Expect(s.Push(f2, 9, cb2)).To(Succeed()) // 9 - 13
			Expect(s.Push(f3, 3, cb3)).To(Succeed()) // 3 - 11
			checkGaps([]byteInterval{
				{Start: 0, End: 3},
				{Start: 13, End: protocol.MaxByteCount},
			})
			checkQueue(map[protocol.ByteCount][]byte{
				3: f3[:6],
				9: f2,
			})
			checkCallbackCalled(t1)
			checkCallbackNotCalled(t2)
			checkCallbackCalled(t3)
		})

		It("case 35, for long frames", func() {
			mult := protocol.ByteCount(math.Ceil(float64(protocol.MinStreamFrameSize) / 6))
			f1 := getData(3 * mult)
			cb1, t1 := getCallback()
			f2 := getData(4 * mult)
			cb2, t2 := getCallback()
			f3 := getData(8 * mult)
			cb3, t3 := getCallback()
			Expect(s.Push(f1, 3*mult, cb1)).To(Succeed()) // 3 - 6
			Expect(s.Push(f2, 9*mult, cb2)).To(Succeed()) // 9 - 13
			Expect(s.Push(f3, 3*mult, cb3)).To(Succeed()) // 3 - 11
			checkGaps([]byteInterval{
				{Start: 0, End: 3 * mult},
				{Start: 13 * mult, End: protocol.MaxByteCount},
			})
			checkQueue(map[protocol.ByteCount][]byte{
				3 * mult: f3[:6*mult],
				9 * mult: f2,
			})
			checkCallbackCalled(t1)
			checkCallbackNotCalled(t2)
			checkCallbackNotCalled(t3)
		})

		Context("receiving data after reads", func() {
			It("ignores duplicate frames", func() {
				Expect(s.Push([]byte("foobar"), 0, nil)).To(Succeed())
				offset, data, _ := s.Pop()
				Expect(offset).To(BeZero())
				Expect(data).To(Equal([]byte("foobar")))
				// now receive the duplicate
				Expect(s.Push([]byte("foobar"), 0, nil)).To(Succeed())
				Expect(s.queue).To(BeEmpty())
				checkGaps([]byteInterval{
					{Start: 6, End: protocol.MaxByteCount},
				})
			})

			It("ignores parts of frames that have already been read", func() {
				Expect(s.Push([]byte("foo"), 0, nil)).To(Succeed())
				offset, data, _ := s.Pop()
				Expect(offset).To(BeZero())
				Expect(data).To(Equal([]byte("foo")))
				// now receive the duplicate
				Expect(s.Push([]byte("foobar"), 0, nil)).To(Succeed())
				offset, data, _ = s.Pop()
				Expect(offset).To(Equal(protocol.ByteCount(3)))
				Expect(data).To(Equal([]byte("bar")))
				Expect(s.queue).To(BeEmpty())
				checkGaps([]byteInterval{
					{Start: 6, End: protocol.MaxByteCount},
				})
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

	Context("stress testing", func() {
		type frame struct {
			offset protocol.ByteCount
			data   []byte
		}

		for _, lf := range []bool{true, false} {
			longFrames := lf

			const num = 1000

			name := "short"
			if longFrames {
				name = "long"
			}

			Context(fmt.Sprintf("using %s frames", name), func() {
				var data []byte
				var dataLen protocol.ByteCount
				var callbacks []callbackTracker

				BeforeEach(func() {
					seed := time.Now().UnixNano()
					fmt.Fprintf(GinkgoWriter, "Seed: %d\n", seed)
					rand.Seed(seed)

					callbacks = nil
					dataLen = 25
					if longFrames {
						dataLen = 2 * protocol.MinStreamFrameSize
					}

					data = make([]byte, num*dataLen)
					for i := 0; i < num; i++ {
						for j := protocol.ByteCount(0); j < dataLen; j++ {
							data[protocol.ByteCount(i)*dataLen+j] = uint8(i)
						}
					}
				})

				getRandomFrames := func() []frame {
					frames := make([]frame, num)
					for i := protocol.ByteCount(0); i < num; i++ {
						b := make([]byte, dataLen)
						Expect(copy(b, data[i*dataLen:])).To(BeEquivalentTo(dataLen))
						frames[i] = frame{
							offset: i * dataLen,
							data:   b,
						}
					}
					rand.Shuffle(len(frames), func(i, j int) { frames[i], frames[j] = frames[j], frames[i] })
					return frames
				}

				getData := func() []byte {
					var data []byte
					for {
						offset, b, cb := s.Pop()
						if b == nil {
							break
						}
						Expect(offset).To(BeEquivalentTo(len(data)))
						data = append(data, b...)
						if cb != nil {
							cb()
						}
					}
					return data
				}

				// push pushes data to the frame sorter
				// It creates a new callback and adds the
				push := func(data []byte, offset protocol.ByteCount) {
					cb, t := getCallback()
					ExpectWithOffset(1, s.Push(data, offset, cb)).To(Succeed())
					callbacks = append(callbacks, t)
				}

				checkCallbacks := func() {
					ExpectWithOffset(1, callbacks).ToNot(BeEmpty())
					for _, t := range callbacks {
						checkCallbackCalled(t)
					}
				}

				It("inserting frames in a random order", func() {
					frames := getRandomFrames()

					for _, f := range frames {
						push(f.data, f.offset)
					}
					checkGaps([]byteInterval{{Start: num * dataLen, End: protocol.MaxByteCount}})

					Expect(getData()).To(Equal(data))
					Expect(s.queue).To(BeEmpty())
					checkCallbacks()
				})

				It("inserting frames in a random order, with some duplicates", func() {
					frames := getRandomFrames()

					for _, f := range frames {
						push(f.data, f.offset)
						if rand.Intn(10) < 5 {
							df := frames[rand.Intn(len(frames))]
							push(df.data, df.offset)
						}
					}
					checkGaps([]byteInterval{{Start: num * dataLen, End: protocol.MaxByteCount}})

					Expect(getData()).To(Equal(data))
					Expect(s.queue).To(BeEmpty())
					checkCallbacks()
				})

				It("inserting frames in a random order, with randomly cut retransmissions", func() {
					frames := getRandomFrames()

					for _, f := range frames {
						push(f.data, f.offset)
						if rand.Intn(10) < 5 {
							length := protocol.ByteCount(1 + rand.Intn(int(4*dataLen)))
							if length >= num*dataLen {
								length = num*dataLen - 1
							}
							b := make([]byte, length)
							offset := protocol.ByteCount(rand.Intn(int(num*dataLen - length)))
							Expect(copy(b, data[offset:offset+length])).To(BeEquivalentTo(length))
							push(b, offset)
						}
					}
					checkGaps([]byteInterval{{Start: num * dataLen, End: protocol.MaxByteCount}})

					Expect(getData()).To(Equal(data))
					Expect(s.queue).To(BeEmpty())
					checkCallbacks()
				})
			})
		}
	})
})
