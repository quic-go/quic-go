package handshake

import (
	"encoding/binary"
	"testing"

	"github.com/Noooste/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestRetryIntegrityTagCalculation(t *testing.T) {
	connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	fooTag := GetRetryIntegrityTag([]byte("foo"), connID, protocol.Version1)
	barTag := GetRetryIntegrityTag([]byte("bar"), connID, protocol.Version1)
	require.NotNil(t, fooTag)
	require.NotNil(t, barTag)
	require.NotEqual(t, *fooTag, *barTag)
}

func TestRetryIntegrityTagWithDifferentConnectionIDs(t *testing.T) {
	connID1 := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	connID2 := protocol.ParseConnectionID([]byte{4, 3, 2, 1})
	t1 := GetRetryIntegrityTag([]byte("foobar"), connID1, protocol.Version1)
	t2 := GetRetryIntegrityTag([]byte("foobar"), connID2, protocol.Version1)
	require.NotEqual(t, *t1, *t2)
}

func TestRetryIntegrityTagWithTestVectors(t *testing.T) {
	tests := []struct {
		name    string
		version protocol.Version
		data    []byte
	}{
		{
			name:    "v1",
			version: protocol.Version1,
			data:    splitHexString(t, "ff000000010008f067a5502a4262b574 6f6b656e04a265ba2eff4d829058fb3f 0f2496ba"),
		},
		{
			name:    "v2",
			version: protocol.Version2,
			data:    splitHexString(t, "cf6b3343cf0008f067a5502a4262b574 6f6b656ec8646ce8bfe33952d9555436 65dcc7b6"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := binary.BigEndian.Uint32(tt.data[1:5])
			require.Equal(t, tt.version, protocol.Version(v))
			connID := protocol.ParseConnectionID(splitHexString(t, "0x8394c8f03e515708"))
			tag := GetRetryIntegrityTag(tt.data[:len(tt.data)-16], connID, tt.version)
			require.Equal(t, tt.data[len(tt.data)-16:], tag[:])
		})
	}
}
