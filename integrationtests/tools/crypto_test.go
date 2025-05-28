package tools

import (
	"crypto/x509"
	"github.com/Noooste/utls"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

type countingConn struct {
	net.Conn
	BytesReceived int
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.BytesReceived += n
	return n, err
}

func TestGenerateTLSConfig(t *testing.T) {
	ca, caPriv, err := GenerateCA()
	require.NoError(t, err)
	certPool := x509.NewCertPool()
	certPool.AddCert(ca)
	clientConf := &tls.Config{
		ServerName: "localhost",
		RootCAs:    certPool,
	}

	t.Run("short chain", func(t *testing.T) {
		leaf, leafPriv, err := GenerateLeafCert(ca, caPriv)
		require.NoError(t, err)

		serverConf := &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{leaf.Raw},
				PrivateKey:  leafPriv,
			}},
		}

		bytesReceived := testGenerateTLSConfig(t, serverConf, clientConf)
		t.Logf("bytes received: %d", bytesReceived)
		require.Less(t, bytesReceived, 2000)
	})

	t.Run("long chain", func(t *testing.T) {
		serverConf, err := GenerateTLSConfigWithLongCertChain(ca, caPriv)
		require.NoError(t, err)

		bytesReceived := testGenerateTLSConfig(t, serverConf, clientConf)
		t.Logf("bytes received: %d", bytesReceived)
		require.Greater(t, bytesReceived, 5000)
	})
}

func testGenerateTLSConfig(t *testing.T, serverConf, clientConf *tls.Config) int {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverConf)
	require.NoError(t, err)
	defer ln.Close()

	type result struct {
		err error
		msg string
	}

	resultChan := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			resultChan <- result{err: err}
			return
		}
		defer conn.Close()
		msg, err := io.ReadAll(conn)
		resultChan <- result{err: err, msg: string(msg)}
	}()

	tcpConn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer tcpConn.Close()
	countingConn := &countingConn{Conn: tcpConn}

	tlsConn := tls.Client(countingConn, clientConf)
	require.NoError(t, tlsConn.Handshake())

	_, err = tlsConn.Write([]byte("foobar"))
	require.NoError(t, err)
	require.NoError(t, tlsConn.Close())

	res := <-resultChan
	require.NoError(t, res.err)
	require.Equal(t, "foobar", res.msg)

	return countingConn.BytesReceived
}
