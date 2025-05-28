package handshake

import (
	"encoding/hex"
	"github.com/Noooste/utls"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func splitHexString(t *testing.T, s string) (slice []byte) {
	t.Helper()
	for _, ss := range strings.Split(s, " ") {
		if ss[0:2] == "0x" {
			ss = ss[2:]
		}
		d, err := hex.DecodeString(ss)
		require.NoError(t, err)
		slice = append(slice, d...)
	}
	return
}

func TestSplitHexString(t *testing.T) {
	require.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, splitHexString(t, "0xdeadbeef"))
	require.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, splitHexString(t, "deadbeef"))
	require.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, splitHexString(t, "dead beef"))
}

var cipherSuites = []*cipherSuite{
	getCipherSuite(tls.TLS_AES_128_GCM_SHA256),
	getCipherSuite(tls.TLS_AES_256_GCM_SHA384),
	getCipherSuite(tls.TLS_CHACHA20_POLY1305_SHA256),
}
