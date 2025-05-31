package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRandomNumbers(t *testing.T) {
	const (
		num = 1000
		max = 12345678
	)

	var values [num]int32
	var r Rand
	for i := 0; i < num; i++ {
		v := r.Int31n(max)
		require.GreaterOrEqual(t, v, int32(0))
		require.Less(t, v, int32(max))
		values[i] = v
	}

	var sum uint64
	for _, n := range values {
		sum += uint64(n)
	}
	average := float64(sum) / num
	expectedAverage := float64(max) / 2
	tolerance := float64(max) / 25
	require.InDelta(t, expectedAverage, average, tolerance)
}
