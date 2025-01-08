package quic

import (
	"fmt"
	"math"
	"testing"

	"golang.org/x/exp/rand"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

type callbackTracker struct {
	called *bool
	cb     func()
}

func (t *callbackTracker) WasCalled() bool { return *t.called }

func getFrameSorterTestCallback(t *testing.T) (func(), callbackTracker) {
	var called bool
	cb := func() {
		if called {
			t.Fatal("double free")
		}
		called = true
	}
	return cb, callbackTracker{
		cb:     cb,
		called: &called,
	}
}

func TestFrameSorterSimpleCases(t *testing.T) {
	s := newFrameSorter()
	_, data, doneCb := s.Pop()
	require.Nil(t, data)
	require.Nil(t, doneCb)

	// empty frames are ignored
	require.NoError(t, s.Push(nil, 0, nil))
	_, data, doneCb = s.Pop()
	require.Nil(t, data)
	require.Nil(t, doneCb)

	cb1, t1 := getFrameSorterTestCallback(t)
	cb2, t2 := getFrameSorterTestCallback(t)
	require.NoError(t, s.Push([]byte("bar"), 3, cb2))
	require.True(t, s.HasMoreData())
	require.NoError(t, s.Push([]byte("foo"), 0, cb1))

	offset, data, doneCb := s.Pop()
	require.Equal(t, []byte("foo"), data)
	require.Zero(t, offset)
	require.NotNil(t, doneCb)
	doneCb()
	require.True(t, t1.WasCalled())
	require.False(t, t2.WasCalled())
	require.True(t, s.HasMoreData())

	offset, data, doneCb = s.Pop()
	require.Equal(t, []byte("bar"), data)
	require.Equal(t, protocol.ByteCount(3), offset)
	require.NotNil(t, doneCb)
	doneCb()
	require.True(t, t2.WasCalled())
	require.False(t, s.HasMoreData())

	// now receive a duplicate
	cb3, t3 := getFrameSorterTestCallback(t)
	require.NoError(t, s.Push([]byte("foo"), 0, cb3))
	require.False(t, s.HasMoreData())
	require.True(t, t3.WasCalled())

	// now receive a later frame that overlaps with the ones we already consumed
	cb4, _ := getFrameSorterTestCallback(t)
	require.NoError(t, s.Push([]byte("barbaz"), 3, cb4))
	require.True(t, s.HasMoreData())

	offset, data, _ = s.Pop()
	require.Equal(t, protocol.ByteCount(6), offset)
	require.Equal(t, []byte("baz"), data)
	require.False(t, s.HasMoreData())
}

// Usually, it's not a good idea to test the implementation details.
// However, we need to make sure that the frame sorter handles gaps correctly,
// in particular when overlapping stream data is received.
// This also includes returning buffers that are no longer needed.
func TestFrameSorterGapHandling(t *testing.T) {
	getData := func(l protocol.ByteCount) []byte {
		b := make([]byte, l)
		rand.Read(b)
		return b
	}

	checkQueue := func(t *testing.T, s *frameSorter, m map[protocol.ByteCount][]byte) {
		require.Equal(t, len(m), len(s.queue))
		for offset, data := range m {
			require.Contains(t, s.queue, offset)
			require.Equal(t, data, s.queue[offset].Data)
		}
	}

	checkGaps := func(t *testing.T, s *frameSorter, expectedGaps []byteInterval) {
		if s.gaps.Len() != len(expectedGaps) {
			fmt.Println("Gaps:")
			for gap := s.gaps.Front(); gap != nil; gap = gap.Next() {
				fmt.Printf("\t%d - %d\n", gap.Value.Start, gap.Value.End)
			}
			require.Equal(t, len(expectedGaps), s.gaps.Len())
		}
		var i int
		for gap := s.gaps.Front(); gap != nil; gap = gap.Next() {
			require.Equal(t, expectedGaps[i], gap.Value)
			i++
		}
	}

	// ---xxx--------------
	//       ++++++
	// =>
	// ---xxx++++++--------
	t.Run("case 1", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(5)
		cb2, t2 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1)) // 3 - 6
		require.NoError(t, s.Push(f2, 6, cb2)) // 6 - 11
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3: f1,
			6: f2,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 11, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
	})

	// ---xxx-----------------
	//          +++++++
	// =>
	// ---xxx---+++++++--------
	t.Run("case 2", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(5)
		cb2, t2 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1))  // 3 - 6
		require.NoError(t, s.Push(f2, 10, cb2)) // 10 -15
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3:  f1,
			10: f2,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 6, End: 10},
			{Start: 15, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
	})

	// ---xxx----xxxxxx-------
	//       ++++
	// =>
	// ---xxx++++xxxxx--------
	t.Run("case 3", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(4)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(5)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1))  // 3 - 6
		require.NoError(t, s.Push(f3, 10, cb2)) // 10 - 15
		require.NoError(t, s.Push(f2, 6, cb3))  // 6 - 10
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3:  f1,
			6:  f2,
			10: f3,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 15, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
		require.False(t, t3.WasCalled())
	})

	// ----xxxx-------
	//       ++++
	// =>
	// ----xxxx++-----
	t.Run("case 4", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(4)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(4)
		cb2, t2 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1)) // 3 - 7
		require.NoError(t, s.Push(f2, 5, cb2)) // 5 - 9
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3: f1,
			7: f2[2:],
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 9, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.True(t, t2.WasCalled())
	})

	t.Run("case 4, for long frames", func(t *testing.T) {
		s := newFrameSorter()
		mult := protocol.ByteCount(math.Ceil(float64(protocol.MinStreamFrameSize) / 2))
		f1 := getData(4 * mult)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(4 * mult)
		cb2, t2 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3*mult, cb1)) // 3 - 7
		require.NoError(t, s.Push(f2, 5*mult, cb2)) // 5 - 9
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3 * mult: f1,
			7 * mult: f2[2*mult:],
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3 * mult},
			{Start: 9 * mult, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
	})

	// xxxx-------
	//    ++++
	// =>
	// xxxx+++-----
	t.Run("case 5", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(4)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(4)
		cb2, t2 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 0, cb1)) // 0 - 4
		require.NoError(t, s.Push(f2, 3, cb2)) // 3 - 7
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			0: f1,
			4: f2[1:],
		})
		checkGaps(t, s, []byteInterval{
			{Start: 7, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.True(t, t2.WasCalled())
	})

	t.Run("case 5, for long frames", func(t *testing.T) {
		s := newFrameSorter()
		mult := protocol.ByteCount(math.Ceil(float64(protocol.MinStreamFrameSize) / 2))
		f1 := getData(4 * mult)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(4 * mult)
		cb2, t2 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 0, cb1))      // 0 - 4
		require.NoError(t, s.Push(f2, 3*mult, cb2)) // 3 - 7
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			0:        f1,
			4 * mult: f2[mult:],
		})
		checkGaps(t, s, []byteInterval{
			{Start: 7 * mult, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
	})

	// ----xxxx-------
	//   ++++
	// =>
	// --++xxxx-------
	t.Run("case 6", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(4)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(4)
		cb2, t2 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 5, cb1)) // 5 - 9
		require.NoError(t, s.Push(f2, 3, cb2)) // 3 - 7
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3: f2[:2],
			5: f1,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 9, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.True(t, t2.WasCalled())
	})

	t.Run("case 6, for long frames", func(t *testing.T) {
		s := newFrameSorter()
		mult := protocol.ByteCount(math.Ceil(float64(protocol.MinStreamFrameSize) / 2))
		f1 := getData(4 * mult)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(4 * mult)
		cb2, t2 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 5*mult, cb1)) // 5 - 9
		require.NoError(t, s.Push(f2, 3*mult, cb2)) // 3 - 7
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3 * mult: f2[:2*mult],
			5 * mult: f1,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3 * mult},
			{Start: 9 * mult, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
	})

	// ---xxx----xxxxxx-------
	//       ++
	// =>
	// ---xxx++--xxxxx--------
	t.Run("case 7", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(2)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(5)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1))  // 3 - 6
		require.NoError(t, s.Push(f3, 10, cb2)) // 10 - 15
		require.NoError(t, s.Push(f2, 6, cb3))  // 6 - 8
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3:  f1,
			6:  f2,
			10: f3,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 8, End: 10},
			{Start: 15, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
		require.False(t, t3.WasCalled())
	})

	// ---xxx---------xxxxxx--
	//          ++
	// =>
	// ---xxx---++----xxxxx--
	t.Run("case 8", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(2)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(5)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1))  // 3 - 6
		require.NoError(t, s.Push(f3, 15, cb2)) // 15 - 20
		require.NoError(t, s.Push(f2, 10, cb3)) // 10 - 12
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3:  f1,
			10: f2,
			15: f3,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 6, End: 10},
			{Start: 12, End: 15},
			{Start: 20, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
		require.False(t, t3.WasCalled())
	})

	// ---xxx----xxxxxx-------
	//         ++
	// =>
	// ---xxx--++xxxxx--------
	t.Run("case 9", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(2)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(5)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1))  // 3 - 6
		require.NoError(t, s.Push(f3, 10, cb2)) // 10 - 15
		require.NoError(t, s.Push(f2, 8, cb3))  // 8 - 10
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3:  f1,
			8:  f2,
			10: f3,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 6, End: 8},
			{Start: 15, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
		require.False(t, t3.WasCalled())
	})

	// ---xxx----=====-------
	//      +++++++
	// =>
	// ---xxx++++=====--------
	t.Run("case 10", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(5)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(6)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1))  // 3 - 6
		require.NoError(t, s.Push(f2, 10, cb2)) // 10 - 15
		require.NoError(t, s.Push(f3, 5, cb3))  // 5 - 11
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3:  f1,
			6:  f3[1:5],
			10: f2,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 15, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
		require.True(t, t3.WasCalled())
	})

	t.Run("case 10, for long frames", func(t *testing.T) {
		s := newFrameSorter()
		mult := protocol.ByteCount(math.Ceil(float64(protocol.MinStreamFrameSize) / 4))
		f1 := getData(3 * mult)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(5 * mult)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(6 * mult)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3*mult, cb1))  // 3 - 6
		require.NoError(t, s.Push(f2, 10*mult, cb2)) // 10 - 15
		require.NoError(t, s.Push(f3, 5*mult, cb3))  // 5 - 11
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3 * mult:  f1,
			6 * mult:  f3[mult : 5*mult],
			10 * mult: f2,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3 * mult},
			{Start: 15 * mult, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
		require.False(t, t3.WasCalled())
	})

	// ---xxxx----=====-------
	//      ++++++
	// =>
	// ---xxx++++=====--------
	t.Run("case 11", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(4)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(5)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(5)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1))  // 3 - 7
		require.NoError(t, s.Push(f2, 10, cb2)) // 10 - 15
		require.NoError(t, s.Push(f3, 5, cb3))  // 5 - 10
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3:  f1,
			7:  f3[2:],
			10: f2,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 15, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
		require.True(t, t3.WasCalled())
	})

	// ---xxxx----=====-------
	//      ++++++
	// =>
	// ---xxx++++=====--------
	t.Run("case 11, for long frames", func(t *testing.T) {
		s := newFrameSorter()
		mult := protocol.ByteCount(math.Ceil(float64(protocol.MinStreamFrameSize) / 3))
		f1 := getData(4 * mult)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(5 * mult)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(5 * mult)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3*mult, cb1))  // 3 - 7
		require.NoError(t, s.Push(f2, 10*mult, cb2)) // 10 - 15
		require.NoError(t, s.Push(f3, 5*mult, cb3))  // 5 - 10
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3 * mult:  f1,
			7 * mult:  f3[2*mult:],
			10 * mult: f2,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3 * mult},
			{Start: 15 * mult, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
		require.False(t, t3.WasCalled())
	})

	// ----xxxx-------
	//     +++++++
	// =>
	// ----+++++++-----
	t.Run("case 12", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(4)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(7)
		cb2, t2 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1)) // 3 - 7
		require.NoError(t, s.Push(f2, 3, cb2)) // 3 - 10
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3: f2,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 10, End: protocol.MaxByteCount},
		})
		require.True(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
	})

	// ----xxx===-------
	//     +++++++
	// =>
	// ----+++++++-----
	t.Run("case 13", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(3)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(7)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1)) // 3 - 6
		require.NoError(t, s.Push(f2, 6, cb2)) // 6 - 9
		require.NoError(t, s.Push(f3, 3, cb3)) // 3 - 10
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3: f3,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 10, End: protocol.MaxByteCount},
		})
		require.True(t, t1.WasCalled())
		require.True(t, t2.WasCalled())
		require.False(t, t3.WasCalled())
	})

	// ----xxx====-------
	//     +++++
	// =>
	// ----+++====-----
	t.Run("case 14", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(4)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(5)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1)) // 3 - 6
		require.NoError(t, s.Push(f2, 6, cb2)) // 6 - 10
		require.NoError(t, s.Push(f3, 3, cb3)) // 3 - 8
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3: f3[:3],
			6: f2,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 10, End: protocol.MaxByteCount},
		})
		require.True(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
		require.True(t, t3.WasCalled())
	})

	t.Run("case 14, for long frames", func(t *testing.T) {
		s := newFrameSorter()
		mult := protocol.ByteCount(math.Ceil(float64(protocol.MinStreamFrameSize) / 3))
		f1 := getData(3 * mult)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(4 * mult)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(5 * mult)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3*mult, cb1)) // 3 - 6
		require.NoError(t, s.Push(f2, 6*mult, cb2)) // 6 - 10
		require.NoError(t, s.Push(f3, 3*mult, cb3)) // 3 - 8
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3 * mult: f3[:3*mult],
			6 * mult: f2,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3 * mult},
			{Start: 10 * mult, End: protocol.MaxByteCount},
		})
		require.True(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
		require.False(t, t3.WasCalled())
	})

	// ----xxx===-------
	//     ++++++
	// =>
	// ----++++++-----
	t.Run("case 15", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(3)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(6)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1)) // 3 - 6
		require.NoError(t, s.Push(f2, 6, cb2)) // 6 - 9
		require.NoError(t, s.Push(f3, 3, cb3)) // 3 - 9
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3: f3,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 9, End: protocol.MaxByteCount},
		})
		require.True(t, t1.WasCalled())
		require.True(t, t2.WasCalled())
		require.False(t, t3.WasCalled())
	})

	// ---xxxx-------
	//    ++++
	// =>
	// ---xxxx-----
	t.Run("case 16", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(4)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(4)
		cb2, t2 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 5, cb1)) // 5 - 9
		require.NoError(t, s.Push(f2, 5, cb2)) // 5 - 9
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			5: f1,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 5},
			{Start: 9, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.True(t, t2.WasCalled())
	})

	// ----xxx===-------
	//     +++
	// =>
	// ----xxx===-----
	t.Run("case 17", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(3)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(3)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1)) // 3 - 6
		require.NoError(t, s.Push(f2, 6, cb2)) // 6 - 9
		require.NoError(t, s.Push(f3, 3, cb3)) // 3 - 6
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3: f1,
			6: f2,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 9, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
		require.True(t, t3.WasCalled())
	})

	// ---xxxx-------
	//    ++
	// =>
	// ---xxxx-----
	t.Run("case 18", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(4)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(2)
		cb2, t2 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 5, cb1)) // 5 - 9
		require.NoError(t, s.Push(f2, 5, cb2)) // 5 - 7
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			5: f1,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 5},
			{Start: 9, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.True(t, t2.WasCalled())
	})

	// ---xxxxx------
	//     ++
	// =>
	// ---xxxxx----
	t.Run("case 19", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(5)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(2)
		cb2, t2 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 5, cb1)) // 5 - 10
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			5: f1,
		})
		require.NoError(t, s.Push(f2, 6, cb2)) // 6 - 8
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			5: f1,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 5},
			{Start: 10, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.True(t, t2.WasCalled())
	})

	// xxxxx------
	//  ++
	// =>
	// xxxxx------
	t.Run("case 20", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(10)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(4)
		cb2, t2 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 0, cb1)) // 0 - 10
		require.NoError(t, s.Push(f2, 5, cb2)) // 5 - 9
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			0: f1,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 10, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.True(t, t2.WasCalled())
	})
	// ---xxxxx---
	//      +++
	// =>
	// ---xxxxx---
	t.Run("case 21", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(5)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(3)
		cb2, t2 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 5, cb1)) // 5 - 10
		require.NoError(t, s.Push(f2, 7, cb2)) // 7 - 10
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 5},
			{Start: 10, End: protocol.MaxByteCount},
		})
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			5: f1,
		})
		require.False(t, t1.WasCalled())
		require.True(t, t2.WasCalled())
	})

	// ----xxx------
	//   +++++
	// =>
	// --+++++----
	t.Run("case 22", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(5)
		cb2, t2 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 5, cb1)) // 5 - 8
		require.NoError(t, s.Push(f2, 3, cb2)) // 3 - 8
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3: f2,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 8, End: protocol.MaxByteCount},
		})
		require.True(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
	})

	// ----xxx===------
	//   ++++++++
	// =>
	// --++++++++----
	t.Run("case 23", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(3)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(8)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 5, cb1)) // 5 - 8
		require.NoError(t, s.Push(f2, 8, cb2)) // 8 - 11
		require.NoError(t, s.Push(f3, 3, cb3)) // 3 - 11
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3: f3,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 11, End: protocol.MaxByteCount},
		})
		require.True(t, t1.WasCalled())
		require.True(t, t2.WasCalled())
		require.False(t, t3.WasCalled())
	})

	// --xxx---===---
	//      ++++++
	// =>
	// --xxx++++++----
	t.Run("case 24", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(3)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(6)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1)) // 3 - 6
		require.NoError(t, s.Push(f2, 9, cb2)) // 9 - 12
		require.NoError(t, s.Push(f3, 6, cb3)) // 6 - 12
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3: f1,
			6: f3,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 12, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.True(t, t2.WasCalled())
		require.False(t, t3.WasCalled())
	})

	// --xxx---===---###
	//      +++++++++
	// =>
	// --xxx+++++++++###
	t.Run("case 25", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(3)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(3)
		cb3, t3 := getFrameSorterTestCallback(t)
		f4 := getData(9)
		cb4, t4 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1))  // 3 - 6
		require.NoError(t, s.Push(f2, 9, cb2))  // 9 - 12
		require.NoError(t, s.Push(f3, 15, cb3)) // 15 - 18
		require.NoError(t, s.Push(f4, 6, cb4))  // 6 - 15
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3:  f1,
			6:  f4,
			15: f3,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 18, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.True(t, t2.WasCalled())
		require.False(t, t3.WasCalled())
		require.False(t, t4.WasCalled())
	})

	// ----xxx------
	//   +++++++
	// =>
	// --+++++++---
	t.Run("case 26", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(10)
		cb2, t2 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 5, cb1)) // 5 - 8
		require.NoError(t, s.Push(f2, 3, cb2)) // 3 - 13
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3: f2,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 13, End: protocol.MaxByteCount},
		})
		require.True(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
	})

	// ---xxx====---
	//   ++++
	// =>
	// --+xxx====---
	t.Run("case 27", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(4)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(4)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1)) // 3 - 6
		require.NoError(t, s.Push(f2, 6, cb2)) // 6 - 10
		require.NoError(t, s.Push(f3, 2, cb3)) // 2 - 6
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			2: f3[:1],
			3: f1,
			6: f2,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 2},
			{Start: 10, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
		require.True(t, t3.WasCalled())
	})

	t.Run("case 27, for long frames", func(t *testing.T) {
		s := newFrameSorter()
		const mult = protocol.MinStreamFrameSize
		f1 := getData(3 * mult)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(4 * mult)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(4 * mult)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3*mult, cb1)) // 3 - 6
		require.NoError(t, s.Push(f2, 6*mult, cb2)) // 6 - 10
		require.NoError(t, s.Push(f3, 2*mult, cb3)) // 2 - 6
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			2 * mult: f3[:mult],
			3 * mult: f1,
			6 * mult: f2,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 2 * mult},
			{Start: 10 * mult, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
		require.False(t, t3.WasCalled())
	})

	// ---xxx====---
	//   ++++++
	// =>
	// --+xxx====---
	t.Run("case 28", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(4)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(6)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1)) // 3 - 6
		require.NoError(t, s.Push(f2, 6, cb2)) // 6 - 10
		require.NoError(t, s.Push(f3, 2, cb3)) // 2 - 8
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			2: f3[:1],
			3: f1,
			6: f2,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 2},
			{Start: 10, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
		require.True(t, t3.WasCalled())
	})

	t.Run("case 28, for long frames", func(t *testing.T) {
		s := newFrameSorter()
		const mult = protocol.MinStreamFrameSize
		f1 := getData(3 * mult)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(4 * mult)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(6 * mult)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3*mult, cb1)) // 3 - 6
		require.NoError(t, s.Push(f2, 6*mult, cb2)) // 6 - 10
		require.NoError(t, s.Push(f3, 2*mult, cb3)) // 2 - 8
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			2 * mult: f3[:mult],
			3 * mult: f1,
			6 * mult: f2,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 2 * mult},
			{Start: 10 * mult, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
		require.False(t, t3.WasCalled())
	})

	// ---xxx===-----
	//       +++++
	// =>
	// ---xxx+++++---
	t.Run("case 29", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(3)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(5)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1)) // 3 - 6
		require.NoError(t, s.Push(f2, 6, cb2)) // 6 - 9
		require.NoError(t, s.Push(f3, 6, cb3)) // 6 - 11
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3: f1,
			6: f3,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 11, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.True(t, t2.WasCalled())
		require.False(t, t3.WasCalled())
	})

	// ---xxx===----
	//      ++++++
	// =>
	// ---xxx===++--
	t.Run("case 30", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(3)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(6)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1)) // 3 - 6
		require.NoError(t, s.Push(f2, 6, cb2)) // 6 - 9
		require.NoError(t, s.Push(f3, 5, cb3)) // 5 - 11
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3: f1,
			6: f2,
			9: f3[4:],
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 11, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
		require.True(t, t3.WasCalled())
	})

	t.Run("case 30, for long frames", func(t *testing.T) {
		s := newFrameSorter()
		mult := protocol.ByteCount(math.Ceil(float64(protocol.MinStreamFrameSize) / 2))
		f1 := getData(3 * mult)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(3 * mult)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(6 * mult)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3*mult, cb1)) // 3 - 6
		require.NoError(t, s.Push(f2, 6*mult, cb2)) // 6 - 9
		require.NoError(t, s.Push(f3, 5*mult, cb3)) // 5 - 11
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3 * mult: f1,
			6 * mult: f2,
			9 * mult: f3[4*mult:],
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3 * mult},
			{Start: 11 * mult, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
		require.False(t, t3.WasCalled())
	})

	// ---xxx---===-----
	//     ++++++++++
	// =>
	// ---xxx++++++++---
	t.Run("case 31", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(3)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(10)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1)) // 3 - 6
		require.NoError(t, s.Push(f2, 9, cb2)) // 9 - 12
		require.NoError(t, s.Push(f3, 5, cb3)) // 5 - 15
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3: f1,
			6: f3[1:],
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 15, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.True(t, t2.WasCalled())
		require.True(t, t3.WasCalled())
	})

	t.Run("case 31, for long frames", func(t *testing.T) {
		s := newFrameSorter()
		mult := protocol.ByteCount(math.Ceil(float64(protocol.MinStreamFrameSize) / 9))
		f1 := getData(3 * mult)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(3 * mult)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(10 * mult)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3*mult, cb1)) // 3 - 6
		require.NoError(t, s.Push(f2, 9*mult, cb2)) // 9 - 12
		require.NoError(t, s.Push(f3, 5*mult, cb3)) // 5 - 15
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3 * mult: f1,
			6 * mult: f3[mult:],
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3 * mult},
			{Start: 15 * mult, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.True(t, t2.WasCalled())
		require.False(t, t3.WasCalled())
	})

	// ---xxx---===-----
	//    +++++++++
	// =>
	// ---+++++++++---
	t.Run("case 32", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(3)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(9)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1)) // 3 - 6
		require.NoError(t, s.Push(f2, 9, cb2)) // 9 - 12
		require.NoError(t, s.Push(f3, 3, cb3)) // 3 - 12
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3: f3,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 12, End: protocol.MaxByteCount},
		})
		require.True(t, t1.WasCalled())
		require.True(t, t2.WasCalled())
		require.False(t, t3.WasCalled())
	})

	// ---xxx---===###-----
	//     ++++++++++++
	// =>
	// ---xxx++++++++++---
	t.Run("case 33", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(3)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(3)
		cb3, t3 := getFrameSorterTestCallback(t)
		f4 := getData(12)
		cb4, t4 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1)) // 3 - 6
		require.NoError(t, s.Push(f2, 9, cb2)) // 9 - 12
		require.NoError(t, s.Push(f3, 9, cb3)) // 12 - 15
		require.NoError(t, s.Push(f4, 5, cb4)) // 5 - 17
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3: f1,
			6: f4[1:],
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 17, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.True(t, t2.WasCalled())
		require.True(t, t3.WasCalled())
		require.True(t, t4.WasCalled())
	})

	t.Run("case 33, for long frames", func(t *testing.T) {
		s := newFrameSorter()
		mult := protocol.ByteCount(math.Ceil(float64(protocol.MinStreamFrameSize) / 11))
		f1 := getData(3 * mult)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(3 * mult)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(3 * mult)
		cb3, t3 := getFrameSorterTestCallback(t)
		f4 := getData(12 * mult)
		cb4, t4 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3*mult, cb1)) // 3 - 6
		require.NoError(t, s.Push(f2, 9*mult, cb2)) // 9 - 12
		require.NoError(t, s.Push(f3, 9*mult, cb3)) // 12 - 15
		require.NoError(t, s.Push(f4, 5*mult, cb4)) // 5 - 17
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3 * mult: f1,
			6 * mult: f4[mult:],
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3 * mult},
			{Start: 17 * mult, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.True(t, t2.WasCalled())
		require.True(t, t3.WasCalled())
		require.False(t, t4.WasCalled())
	})

	// ---xxx===---###
	//       ++++++
	// =>
	// ---xxx++++++###
	t.Run("case 34", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(5)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(5)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(10)
		cb3, t3 := getFrameSorterTestCallback(t)
		f4 := getData(5)
		cb4, t4 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 5, cb1))  // 5 - 10
		require.NoError(t, s.Push(f2, 10, cb2)) // 10 - 15
		require.NoError(t, s.Push(f4, 20, cb3)) // 20 - 25
		require.NoError(t, s.Push(f3, 10, cb4)) // 10 - 20
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			5:  f1,
			10: f3,
			20: f4,
		})
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 5},
			{Start: 25, End: protocol.MaxByteCount},
		})
		require.False(t, t1.WasCalled())
		require.True(t, t2.WasCalled())
		require.False(t, t3.WasCalled())
		require.False(t, t4.WasCalled())
	})

	// ---xxx---####---
	//    ++++++++
	// =>
	// ---++++++####---
	t.Run("case 35", func(t *testing.T) {
		s := newFrameSorter()
		f1 := getData(3)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(4)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(8)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3, cb1)) // 3 - 6
		require.NoError(t, s.Push(f2, 9, cb2)) // 9 - 13
		require.NoError(t, s.Push(f3, 3, cb3)) // 3 - 11
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3},
			{Start: 13, End: protocol.MaxByteCount},
		})
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3: f3[:6],
			9: f2,
		})
		require.True(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
		require.True(t, t3.WasCalled())
	})

	t.Run("case 35, for long frames", func(t *testing.T) {
		s := newFrameSorter()
		mult := protocol.ByteCount(math.Ceil(float64(protocol.MinStreamFrameSize) / 6))
		f1 := getData(3 * mult)
		cb1, t1 := getFrameSorterTestCallback(t)
		f2 := getData(4 * mult)
		cb2, t2 := getFrameSorterTestCallback(t)
		f3 := getData(8 * mult)
		cb3, t3 := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f1, 3*mult, cb1)) // 3 - 6
		require.NoError(t, s.Push(f2, 9*mult, cb2)) // 9 - 13
		require.NoError(t, s.Push(f3, 3*mult, cb3)) // 3 - 11
		checkGaps(t, s, []byteInterval{
			{Start: 0, End: 3 * mult},
			{Start: 13 * mult, End: protocol.MaxByteCount},
		})
		checkQueue(t, s, map[protocol.ByteCount][]byte{
			3 * mult: f3[:6*mult],
			9 * mult: f2,
		})
		require.True(t, t1.WasCalled())
		require.False(t, t2.WasCalled())
		require.False(t, t3.WasCalled())
	})
}

func TestFrameSorterTooManyGaps(t *testing.T) {
	s := newFrameSorter()
	for i := 0; i < protocol.MaxStreamFrameSorterGaps; i++ {
		require.NoError(t, s.Push([]byte("foobar"), protocol.ByteCount(i*7), nil))
	}
	require.Equal(t, protocol.MaxStreamFrameSorterGaps, s.gaps.Len())
	err := s.Push([]byte("foobar"), protocol.ByteCount(protocol.MaxStreamFrameSorterGaps*7)+100, nil)
	require.EqualError(t, err, "too many gaps in received data")
}

func TestFrameSorterRandomized(t *testing.T) {
	t.Run("short", func(t *testing.T) {
		testFrameSorterRandomized(t, 25, false, false)
	})
	t.Run("long", func(t *testing.T) {
		testFrameSorterRandomized(t, 2*protocol.MinStreamFrameSize, false, false)
	})
	t.Run("short, with duplicates", func(t *testing.T) {
		testFrameSorterRandomized(t, 25, true, false)
	})
	t.Run("long, with duplicates", func(t *testing.T) {
		testFrameSorterRandomized(t, 2*protocol.MinStreamFrameSize, true, false)
	})
	t.Run("short, with overlaps", func(t *testing.T) {
		testFrameSorterRandomized(t, 25, false, true)
	})
	t.Run("long, with overlaps", func(t *testing.T) {
		testFrameSorterRandomized(t, 2*protocol.MinStreamFrameSize, false, true)
	})
}

func testFrameSorterRandomized(t *testing.T, dataLen protocol.ByteCount, injectDuplicates, injectOverlaps bool) {
	type frame struct {
		offset protocol.ByteCount
		data   []byte
	}

	const num = 1000

	data := make([]byte, num*int(dataLen))
	rand.Read(data)

	frames := make([]frame, num)
	for i := 0; i < num; i++ {
		b := make([]byte, dataLen)
		offset := i * int(dataLen)
		copy(b, data[offset:offset+int(dataLen)])
		frames[i] = frame{
			offset: protocol.ByteCount(i) * dataLen,
			data:   b,
		}
	}
	rand.Shuffle(len(frames), func(i, j int) { frames[i], frames[j] = frames[j], frames[i] })

	s := newFrameSorter()

	var callbacks []callbackTracker
	for _, f := range frames {
		cb, tr := getFrameSorterTestCallback(t)
		require.NoError(t, s.Push(f.data, f.offset, cb))
		callbacks = append(callbacks, tr)
	}
	if injectDuplicates {
		for i := 0; i < num/10; i++ {
			cb, tr := getFrameSorterTestCallback(t)
			df := frames[rand.Intn(len(frames))]
			require.NoError(t, s.Push(df.data, df.offset, cb))
			callbacks = append(callbacks, tr)
		}
	}
	if injectOverlaps {
		finalOffset := num * dataLen
		for i := 0; i < num/3; i++ {
			cb, tr := getFrameSorterTestCallback(t)
			startOffset := protocol.ByteCount(rand.Intn(int(finalOffset)))
			endOffset := startOffset + protocol.ByteCount(rand.Intn(int(finalOffset-startOffset)))
			require.NoError(t, s.Push(data[startOffset:endOffset], startOffset, cb))
			callbacks = append(callbacks, tr)
		}
	}
	require.Equal(t, 1, s.gaps.Len())
	require.Equal(t, byteInterval{Start: num * dataLen, End: protocol.MaxByteCount}, s.gaps.Front().Value)

	// read all data
	var read []byte
	for {
		offset, b, cb := s.Pop()
		if b == nil {
			break
		}
		require.Equal(t, offset, protocol.ByteCount(len(read)))
		read = append(read, b...)
		if cb != nil {
			cb()
		}
	}

	require.Equal(t, data, read)
	require.False(t, s.HasMoreData())
	for _, cb := range callbacks {
		require.True(t, cb.WasCalled())
	}
}
