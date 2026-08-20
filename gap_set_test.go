package quic

import (
	"fmt"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestGapSetFindIncludesTouchingIntervals(t *testing.T) {
	for _, count := range []int{3, 17} {
		t.Run(fmt.Sprintf("%d gaps", count), func(t *testing.T) {
			var set gapSet
			for index := range count {
				start := protocol.ByteCount(index * 20)
				set.InsertAt(set.Len(), byteInterval{Start: start, End: start + 10})
			}

			start, end, startsInGap, endsInGap, ok := set.Find(10, protocol.ByteCount((count-1)*20))
			require.True(t, ok)
			require.Equal(t, 0, start)
			require.Equal(t, count-1, end)
			require.True(t, startsInGap)
			require.True(t, endsInGap)
			_, _, _, _, ok = set.Find(11, 19)
			require.False(t, ok)
		})
	}
}

func TestGapSetPreservesOrderAcrossPromotionAndMutation(t *testing.T) {
	var set gapSet
	const count = 257
	for index := range count {
		start := protocol.ByteCount(index * 10)
		set.InsertAt(set.Len(), byteInterval{Start: start, End: start + 5})
	}

	set.UpdateAt(129, byteInterval{Start: 1291, End: 1295})
	for index := count - 1; index >= 0; index-- {
		if index%7 == 2 {
			set.DeleteAt(index)
		}
	}

	values := set.values()
	require.Len(t, values, set.Len())
	for index := 1; index < len(values); index++ {
		require.Less(t, values[index-1].End, values[index].Start)
	}
	require.Equal(t, values[0], set.First())
	require.Contains(t, values, byteInterval{Start: 1291, End: 1295})
}

func TestGapSetReusesLargeStorageAfterDemotion(t *testing.T) {
	var set gapSet
	for index := range gapInlineCapacity + 1 {
		start := protocol.ByteCount(index * 10)
		set.InsertAt(set.Len(), byteInterval{Start: start, End: start + 5})
	}
	capacity := cap(set.large)
	set.DeleteAt(set.Len() - 1)
	require.Len(t, set.large, 0)

	set.InsertAt(set.Len(), byteInterval{Start: 100, End: 105})
	require.Equal(t, capacity, cap(set.large))
}
