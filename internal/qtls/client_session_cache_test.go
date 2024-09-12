package qtls

import (
	"crypto/tls"
	"fmt"
	"net"
	"testing"

	"github.com/quic-go/quic-go/internal/testdata"
	"github.com/stretchr/testify/require"
)

func TestClientSessionCacheAddAndRestoreData(t *testing.T) {
	ln, err := tls.Listen("tcp4", "localhost:0", testdata.GetTLSConfig())
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)

		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, err = conn.Read(make([]byte, 10))
			require.NoError(t, err)
			_, err = conn.Write([]byte("foobar"))
			require.NoError(t, err)
		}
	}()

	restored := make(chan []byte, 1)
	clientConf := &tls.Config{
		RootCAs: testdata.GetRootCA(),
		ClientSessionCache: &clientSessionCache{
			wrapped: tls.NewLRUClientSessionCache(10),
			getData: func(bool) []byte { return []byte("session") },
			setData: func(data []byte, earlyData bool) bool {
				require.False(t, earlyData) // running on top of TCP, we can only test non-0-RTT here
				restored <- data
				return true
			},
		},
	}
	conn, err := tls.Dial(
		"tcp4",
		fmt.Sprintf("localhost:%d", ln.Addr().(*net.TCPAddr).Port),
		clientConf,
	)
	require.NoError(t, err)
	_, err = conn.Write([]byte("foobar"))
	require.NoError(t, err)
	require.False(t, conn.ConnectionState().DidResume)
	require.Len(t, restored, 0)
	_, err = conn.Read(make([]byte, 10))
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	// make sure the cache can deal with nonsensical inputs
	clientConf.ClientSessionCache.Put("foo", nil)
	clientConf.ClientSessionCache.Put("bar", &tls.ClientSessionState{})

	conn, err = tls.Dial(
		"tcp4",
		fmt.Sprintf("localhost:%d", ln.Addr().(*net.TCPAddr).Port),
		clientConf,
	)
	require.NoError(t, err)
	_, err = conn.Write([]byte("foobar"))
	require.NoError(t, err)
	require.True(t, conn.ConnectionState().DidResume)
	var restoredData []byte
	select {
	case restoredData = <-restored:
	default:
		t.Fatal("no data restored")
	}
	require.Equal(t, []byte("session"), restoredData)
	require.NoError(t, conn.Close())

	require.NoError(t, ln.Close())
	<-done
}
