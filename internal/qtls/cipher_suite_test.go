package qtls

import (
	"fmt"
	"github.com/Noooste/utls"
	"net"
	"testing"

	"github.com/Noooste/uquic-go/internal/testdata"

	"github.com/stretchr/testify/require"
)

func TestCipherSuiteSelection(t *testing.T) {
	t.Run("TLS_AES_128_GCM_SHA256", func(t *testing.T) { testCipherSuiteSelection(t, tls.TLS_AES_128_GCM_SHA256) })
	t.Run("TLS_CHACHA20_POLY1305_SHA256", func(t *testing.T) { testCipherSuiteSelection(t, tls.TLS_CHACHA20_POLY1305_SHA256) })
	t.Run("TLS_AES_256_GCM_SHA384", func(t *testing.T) { testCipherSuiteSelection(t, tls.TLS_AES_256_GCM_SHA384) })
}

func testCipherSuiteSelection(t *testing.T, cs uint16) {
	reset := SetCipherSuite(cs)
	defer reset()

	ln, err := tls.Listen("tcp4", "localhost:0", testdata.GetTLSConfig())
	require.NoError(t, err)
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		require.NoError(t, err)
		_, err = conn.Read(make([]byte, 10))
		require.NoError(t, err)
		require.Equal(t, cs, conn.(*tls.Conn).ConnectionState().CipherSuite)
	}()

	conn, err := tls.Dial(
		"tcp4",
		fmt.Sprintf("localhost:%d", ln.Addr().(*net.TCPAddr).Port),
		&tls.Config{RootCAs: testdata.GetRootCA()},
	)
	require.NoError(t, err)
	_, err = conn.Write([]byte("foobar"))
	require.NoError(t, err)
	require.Equal(t, cs, conn.ConnectionState().CipherSuite)
	require.NoError(t, conn.Close())
	<-done
}
