package quic

import (
	"context"
	"crypto/rand"
	"github.com/Noooste/utls"
	"io"
	mrand "math/rand/v2"
	"testing"

	"github.com/Noooste/uquic-go/internal/testdata"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func checkClientHello(t testing.TB, clientHello []byte) {
	t.Helper()

	conn := tls.QUICServer(&tls.QUICConfig{
		TLSConfig: testdata.GetTLSConfig(),
	})
	require.NoError(t, conn.Start(context.Background()))
	defer conn.Close()
	require.NoError(t, conn.HandleData(tls.QUICEncryptionLevelInitial, clientHello))
}

func getClientHello(t testing.TB, serverName string) []byte {
	t.Helper()

	c := tls.QUICClient(&tls.QUICConfig{
		TLSConfig: &tls.Config{
			ServerName:         serverName,
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: serverName == "",
			// disable post-quantum curves
			CurvePreferences: []tls.CurveID{tls.CurveP256},
		},
	})
	b := make([]byte, mrand.IntN(200))
	rand.Read(b)
	c.SetTransportParameters(b)
	require.NoError(t, c.Start(context.Background()))

	ev := c.NextEvent()
	require.Equal(t, tls.QUICWriteData, ev.Kind)
	checkClientHello(t, ev.Data)
	return ev.Data
}

func TestFindSNI(t *testing.T) {
	t.Run("without SNI", func(t *testing.T) {
		testFindSNI(t, "")
	})
	t.Run("without subdomain", func(t *testing.T) {
		testFindSNI(t, "quic-go.net")
	})
	t.Run("with subdomain", func(t *testing.T) {
		testFindSNI(t, "sub.do.ma.in.quic-go.net")
	})
}

func testFindSNI(t *testing.T, serverName string) {
	clientHello := getClientHello(t, serverName)
	sniPos, sniLen, echPos, err := findSNIAndECH(clientHello)
	require.NoError(t, err)
	assert.Equal(t, -1, echPos)
	if serverName == "" {
		require.Equal(t, -1, sniPos)
		return
	}
	assert.Equal(t, len(serverName), sniLen)
	require.NotEqual(t, -1, sniPos)
	require.Equal(t, serverName, string(clientHello[sniPos:sniPos+sniLen]))

	// incomplete ClientHellos result in an io.ErrUnexpectedEOF
	for i := range clientHello {
		_, _, _, err := findSNIAndECH(clientHello[:i])
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	}
}
