package quic

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func mockToken(num int) *ClientToken { return &ClientToken{data: []byte(fmt.Sprintf("%d", num))} }

func TestTokenStoreSingleOrigin(t *testing.T) {
	const origin = "localhost"

	s := NewLRUTokenStore(1, 3)
	s.Put(origin, mockToken(1))
	s.Put(origin, mockToken(2))
	require.Equal(t, mockToken(2), s.Pop(origin))
	require.Equal(t, mockToken(1), s.Pop(origin))
	require.Nil(t, s.Pop(origin))

	// now add more tokens than the cache size
	s.Put(origin, mockToken(1))
	s.Put(origin, mockToken(2))
	s.Put(origin, mockToken(3))
	require.Equal(t, mockToken(3), s.Pop(origin))
	s.Put(origin, mockToken(4))
	s.Put(origin, mockToken(5))
	require.Equal(t, mockToken(5), s.Pop(origin))
	require.Equal(t, mockToken(4), s.Pop(origin))
	require.Equal(t, mockToken(2), s.Pop(origin))
	require.Nil(t, s.Pop(origin))
}

func TestTokenStoreMultipleOrigins(t *testing.T) {
	s := NewLRUTokenStore(3, 4)

	s.Put("host1", mockToken(1))
	s.Put("host2", mockToken(2))
	s.Put("host3", mockToken(3))
	s.Put("host4", mockToken(4))
	require.Nil(t, s.Pop("host1"))
	require.Equal(t, mockToken(2), s.Pop("host2"))
	require.Equal(t, mockToken(3), s.Pop("host3"))
	require.Equal(t, mockToken(4), s.Pop("host4"))
}

func TestTokenStoreUpdates(t *testing.T) {
	s := NewLRUTokenStore(3, 4)
	s.Put("host1", mockToken(1))
	s.Put("host2", mockToken(2))
	s.Put("host3", mockToken(3))
	s.Put("host1", mockToken(11))
	// make sure one is evicted
	s.Put("host4", mockToken(4))
	require.Nil(t, s.Pop("host2"))
	require.Equal(t, mockToken(11), s.Pop("host1"))
	require.Equal(t, mockToken(1), s.Pop("host1"))
	require.Equal(t, mockToken(3), s.Pop("host3"))
	require.Equal(t, mockToken(4), s.Pop("host4"))
}

func TestTokenStoreEviction(t *testing.T) {
	s := NewLRUTokenStore(3, 4)

	s.Put("host1", mockToken(1))
	s.Put("host2", mockToken(2))
	s.Put("host3", mockToken(3))
	require.Equal(t, mockToken(2), s.Pop("host2"))
	require.Nil(t, s.Pop("host2"))
	// host2 is now empty and should have been deleted, making space for host4
	s.Put("host4", mockToken(4))
	require.Equal(t, mockToken(1), s.Pop("host1"))
	require.Equal(t, mockToken(3), s.Pop("host3"))
	require.Equal(t, mockToken(4), s.Pop("host4"))
}
