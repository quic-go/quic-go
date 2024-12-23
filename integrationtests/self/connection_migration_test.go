package self_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/stretchr/testify/require"
)

func TestConnectionMigration(t *testing.T) {
	ln, err := quic.ListenAddr("localhost:0", tlsConfig, getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	tr1 := &quic.Transport{
		Conn: newUPDConnLocalhost(t),
	}
	defer tr1.Close()
	tr2 := &quic.Transport{
		Conn: newUPDConnLocalhost(t),
	}
	defer tr2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	tlsConf := tlsClientConfig
	f, err := os.Create("/Users/marten/src/go/src/github.com/quic-go/quic-go/keylog.txt")
	require.NoError(t, err)
	defer f.Close()
	tlsConf.KeyLogWriter = f
	conn, err := tr1.Dial(ctx, ln.Addr(), tlsConf, getQuicConfig(nil))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	sconn, err := ln.Accept(ctx)
	require.NoError(t, err)
	defer sconn.CloseWithError(0, "")
	require.Equal(t, sconn.RemoteAddr(), tr1.Conn.LocalAddr())

	path, err := conn.AddPath(tr2)
	require.NoError(t, err)
	err = path.Probe(ctx)
	require.NoError(t, err)
}
