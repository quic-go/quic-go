package utils

import "time"

// Max returns the maximum of two Ints
func Max(a, b int) int {
	if a < b {
		return b
	}
	return a
}

// MaxUint32 returns the maximum of two uint32
func MaxUint32(a, b uint32) uint32 {
	if a < b {
		return b
	}
	return a
}

// MaxUint64 returns the maximum of two uint64
func MaxUint64(a, b uint64) uint64 {
	if a < b {
		return b
	}
	return a
}

// Min returns the minimum of two Ints
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// MinInt64 returns the minimum of two int64
func MinInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// MaxInt64 returns the minimum of two int64
func MaxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// MaxDuration returns the max duration
func MaxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func MinDuration(a, b time.Duration) time.Duration {
	if a > b {
		return b
	}
	return a
}

// AbsDuration returns the absolute value of a time duration
func AbsDuration(d time.Duration) time.Duration {
	if d >= 0 {
		return d
	}
	return -d
}
