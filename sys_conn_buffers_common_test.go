package quic

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// failAtomicKernel models kernels like OpenBSD and Darwin: setting a buffer
// size above the cap fails outright, leaving the previous value in place.
type failAtomicKernel struct {
	cap  int
	size int
}

func (k *failAtomicKernel) set(n int) error {
	if n > k.cap {
		return errors.New("no buffer space available")
	}
	k.size = n
	return nil
}

func (k *failAtomicKernel) inspect() (int, error) { return k.size, nil }

// clampingKernel models Linux: setting always succeeds, but the value is
// silently clamped to the cap.
type clampingKernel struct {
	cap  int
	size int
}

func (k *clampingKernel) set(n int) error {
	k.size = min(n, k.cap)
	return nil
}

func (k *clampingKernel) inspect() (int, error) { return k.size, nil }

func TestLargestBufferSizeFailAtomicKernel(t *testing.T) {
	// OpenBSD 7.9: default 41600, SB_MAX caps buffers at exactly 2 MiB,
	// larger requests fail with ENOBUFS. quic-go desires 7 MiB.
	k := &failAtomicKernel{cap: 2 << 20, size: 41600}
	got, err := largestBufferSize(41600, 7<<20, k.set, k.inspect)
	require.NoError(t, err)
	require.Equal(t, 2<<20, got)
	require.Equal(t, 2<<20, k.size, "socket should be left at the discovered size")
}

func TestLargestBufferSizeClampingKernel(t *testing.T) {
	// Linux with a low rmem_max: sets succeed but silently clamp, so the
	// search must rely on reading the value back, not on the set error.
	k := &clampingKernel{cap: 416 << 10, size: 208 << 10}
	got, err := largestBufferSize(208<<10, 7<<20, k.set, k.inspect)
	require.NoError(t, err)
	require.Equal(t, 416<<10, got)
	require.Equal(t, 416<<10, k.size)
}

func TestLargestBufferSizeNothingToGain(t *testing.T) {
	k := &failAtomicKernel{cap: 2 << 20, size: 2 << 20}
	got, err := largestBufferSize(2<<20, 2<<20, k.set, k.inspect)
	require.NoError(t, err)
	require.Equal(t, 2<<20, got)
	got, err = largestBufferSize(3<<20, 2<<20, k.set, k.inspect)
	require.NoError(t, err)
	require.Equal(t, 3<<20, got, "desired below current should return current untouched")
}

func TestLargestBufferSizeInspectFailure(t *testing.T) {
	// If inspection fails after a set may have changed the socket, the
	// probed size is unverifiable and the error must be propagated.
	k := &failAtomicKernel{cap: 2 << 20, size: 41600}
	inspectErr := errors.New("not supported")
	_, err := largestBufferSize(41600, 7<<20, k.set, func() (int, error) { return 0, inspectErr })
	require.ErrorIs(t, err, inspectErr)
}
