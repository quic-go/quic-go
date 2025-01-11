package quic

import (
	"crypto/rand"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestStatelessResetter(t *testing.T) {
	t.Run("no key", func(t *testing.T) {
		r1 := newStatelessResetter(nil)
		r2 := newStatelessResetter(nil)
		for i := 0; i < 100; i++ {
			b := make([]byte, 15)
			rand.Read(b)
			connID := protocol.ParseConnectionID(b)
			t1 := r1.GetStatelessResetToken(connID)
			t2 := r2.GetStatelessResetToken(connID)
			require.NotZero(t, t1)
			require.NotZero(t, t2)
			require.NotEqual(t, t1, t2)
		}
	})

	t.Run("with key", func(t *testing.T) {
		var key StatelessResetKey
		rand.Read(key[:])
		m := newStatelessResetter(&key)
		b := make([]byte, 8)
		rand.Read(b)
		connID := protocol.ParseConnectionID(b)
		token := m.GetStatelessResetToken(connID)
		require.NotZero(t, token)
		require.Equal(t, token, m.GetStatelessResetToken(connID))
		// generate a new connection ID
		rand.Read(b)
		connID2 := protocol.ParseConnectionID(b)
		require.NotEqual(t, token, m.GetStatelessResetToken(connID2))
	})
}
