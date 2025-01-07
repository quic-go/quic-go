package quic

import (
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func TestCryptoStreamManager(t *testing.T) {
	t.Run("Initial", func(t *testing.T) {
		testCryptoStreamManager(t, protocol.EncryptionInitial)
	})
	t.Run("Handshake", func(t *testing.T) {
		testCryptoStreamManager(t, protocol.EncryptionHandshake)
	})
	t.Run("1-RTT", func(t *testing.T) {
		testCryptoStreamManager(t, protocol.Encryption1RTT)
	})
}

func testCryptoStreamManager(t *testing.T, encLevel protocol.EncryptionLevel) {
	initialStream := newCryptoStream()
	handshakeStream := newCryptoStream()
	oneRTTStream := newCryptoStream()
	csm := newCryptoStreamManager(initialStream, handshakeStream, oneRTTStream)

	require.NoError(t, csm.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("foo")}, encLevel))
	require.NoError(t, csm.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("bar"), Offset: 3}, encLevel))
	var data []byte
	for {
		b := csm.GetCryptoData(encLevel)
		if len(b) == 0 {
			break
		}
		data = append(data, b...)
	}
	require.Equal(t, []byte("foobar"), data)
}

func TestCryptoStreamManagerInvalidEncryptionLevel(t *testing.T) {
	csm := newCryptoStreamManager(nil, nil, nil)
	require.ErrorContains(t,
		csm.HandleCryptoFrame(&wire.CryptoFrame{}, protocol.Encryption0RTT),
		"received CRYPTO frame with unexpected encryption level",
	)
}

func TestCryptoStreamManagerDropEncryptionLevel(t *testing.T) {
	t.Run("Initial", func(t *testing.T) {
		testCryptoStreamManagerDropEncryptionLevel(t, protocol.EncryptionInitial)
	})
	t.Run("Handshake", func(t *testing.T) {
		testCryptoStreamManagerDropEncryptionLevel(t, protocol.EncryptionHandshake)
	})
}

func testCryptoStreamManagerDropEncryptionLevel(t *testing.T, encLevel protocol.EncryptionLevel) {
	initialStream := newCryptoStream()
	handshakeStream := newCryptoStream()
	oneRTTStream := newCryptoStream()
	csm := newCryptoStreamManager(initialStream, handshakeStream, oneRTTStream)

	require.NoError(t, csm.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("foo")}, encLevel))
	require.ErrorContains(t, csm.Drop(encLevel), "encryption level changed, but crypto stream has more data to read")

	require.Equal(t, []byte("foo"), csm.GetCryptoData(encLevel))
	require.NoError(t, csm.Drop(encLevel))
}

func TestCryptoStreamManagerPostHandshake(t *testing.T) {
	initialStream := newCryptoStream()
	handshakeStream := newCryptoStream()
	oneRTTStream := newCryptoStream()
	csm := newCryptoStreamManager(initialStream, handshakeStream, oneRTTStream)

	_, err := oneRTTStream.Write([]byte("foo"))
	require.NoError(t, err)
	_, err = oneRTTStream.Write([]byte("bar"))
	require.NoError(t, err)
	require.Equal(t,
		&wire.CryptoFrame{Data: []byte("foobar")},
		csm.GetPostHandshakeData(protocol.ByteCount(10)),
	)
}
