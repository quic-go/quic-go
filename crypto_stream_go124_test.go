//go:build go1.24

package quic

import (
	"fmt"
	mrand "math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/Noooste/uquic-go/internal/protocol"
	"github.com/Noooste/uquic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func randomDomainName(length int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		if i > 0 && i < length-1 && mrand.IntN(5) == 0 && b[i-1] != '.' {
			b[i] = '.'
		} else {
			b[i] = alphabet[mrand.IntN(len(alphabet))]
		}
	}
	return string(b)
}

func TestInitialCryptoStreamClientRandomizedSizes(t *testing.T) {
	skipIfDisableScramblingEnvSet(t)

	for i := range 100 {
		t.Run(fmt.Sprintf("run %d", i), func(t *testing.T) {
			var serverName string
			if mrand.Int()%4 > 0 {
				serverName = randomDomainName(6 + mrand.IntN(20))
			}
			var clientHello []byte
			if serverName == "" || !strings.Contains(serverName, ".") || mrand.Int()%2 == 0 {
				t.Logf("using a ClientHello without ECH, hostname: %q", serverName)
				clientHello = getClientHello(t, serverName)
			} else {
				t.Logf("using a ClientHello with ECH, hostname: %q", serverName)
				clientHello = getClientHelloWithECH(t, serverName)
			}
			testInitialCryptoStreamClientRandomizedSizes(t, clientHello, serverName)
		})
	}
}

func testInitialCryptoStreamClientRandomizedSizes(t *testing.T, clientHello []byte, expectedServerName string) {
	str := newInitialCryptoStream(true)

	b := slices.Clone(clientHello)
	for len(b) > 0 {
		n := min(len(b), mrand.IntN(2*len(b)))
		_, err := str.Write(b[:n])
		require.NoError(t, err)
		b = b[n:]
	}

	require.True(t, str.HasData())
	_, err := str.Write([]byte("foobar"))
	require.NoError(t, err)

	segments := make(map[protocol.ByteCount][]byte)

	var frames []*wire.CryptoFrame
	for str.HasData() {
		// fmt.Println("popping a frame")
		var maxSize protocol.ByteCount
		if mrand.Int()%4 == 0 {
			maxSize = protocol.ByteCount(mrand.IntN(512) + 1)
		} else {
			maxSize = protocol.ByteCount(mrand.IntN(32) + 1)
		}
		f := str.PopCryptoFrame(maxSize)
		if f == nil {
			continue
		}
		frames = append(frames, f)
		require.LessOrEqual(t, f.Length(protocol.Version1), maxSize)
	}
	t.Logf("received %d frames", len(frames))

	for _, f := range frames {
		t.Logf("offset %d: %d bytes", f.Offset, len(f.Data))
		if expectedServerName != "" {
			require.NotContainsf(t, string(f.Data), expectedServerName, "frame at offset %d contains the server name", f.Offset)
		}
		segments[f.Offset] = f.Data
	}

	reassembled := reassembleCryptoData(t, segments)
	require.Equal(t, append(clientHello, []byte("foobar")...), reassembled)
	if expectedServerName != "" {
		require.Contains(t, string(reassembled), expectedServerName)
	}
}
