package utils

import (
	"math"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRandomNumbers(t *testing.T) {
	const num = 1000

	var r Rand
	require.Panics(t, func() { r.Uint32N(0) })
	for _, max := range []uint32{1, 256, 12345678, 1<<31 + 1, math.MaxUint32} {
		t.Run(strconv.FormatUint(uint64(max), 10), func(t *testing.T) {
			var values [num]uint32
			for i := range num {
				v := r.Uint32N(max)
				require.Less(t, v, max)
				values[i] = v
			}

			var sum uint64
			for _, n := range values {
				sum += uint64(n)
			}
			average := float64(sum) / num
			expectedAverage := (float64(max) - 1) / 2
			tolerance := float64(max) / 25
			require.InDelta(t, expectedAverage, average, tolerance)
		})
	}
}
