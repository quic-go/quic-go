//go:build go1.24

package handshake

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"io"
	mrand "math/rand/v2"
	"testing"

	"golang.org/x/crypto/cryptobyte"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindSNIWithECH(t *testing.T) {
	// various constants from the standard library's (internal) hpke package
	const (
		DHKEM_X25519_HKDF_SHA256 = 0x20
		KDF_HKDF_SHA256          = 1
		AEAD_AES_128_GCM         = 1
	)
	const serverName = "public.example"

	marshalECHConfig := func(id uint8, pubKey []byte, publicName string, maxNameLen uint8) []byte {
		builder := cryptobyte.NewBuilder(nil)
		builder.AddUint16(extTypeECH)
		builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddUint8(id)
			builder.AddUint16(DHKEM_X25519_HKDF_SHA256)
			builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) { builder.AddBytes(pubKey) })
			builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
				builder.AddUint16(KDF_HKDF_SHA256)
				builder.AddUint16(AEAD_AES_128_GCM)
			})
			builder.AddUint8(maxNameLen)
			builder.AddUint8LengthPrefixed(func(builder *cryptobyte.Builder) {
				builder.AddBytes([]byte(publicName))
			})
			builder.AddUint16(0) // extensions
		})

		return builder.BytesOrPanic()
	}

	echKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	echConfig := marshalECHConfig(42, echKey.PublicKey().Bytes(), serverName, 32)

	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) { builder.AddBytes(echConfig) })

	c := tls.QUICClient(&tls.QUICConfig{
		TLSConfig: &tls.Config{
			ServerName:                     serverName,
			MinVersion:                     tls.VersionTLS13,
			EncryptedClientHelloConfigList: builder.BytesOrPanic(),
		},
	})
	b := make([]byte, mrand.IntN(200))
	rand.Read(b)
	c.SetTransportParameters(b)
	require.NoError(t, c.Start(context.Background()))

	ev := c.NextEvent()
	require.Equal(t, tls.QUICWriteData, ev.Kind)
	clientHello := ev.Data
	sniPos, sniLen, echPos, err := FindSNIAndECH(clientHello)
	require.NoError(t, err)
	require.NotEqual(t, -1, echPos)
	require.Equal(t, uint16(extTypeECH), binary.BigEndian.Uint16(clientHello[echPos:echPos+2]))
	assert.Equal(t, len(serverName), sniLen)
	require.NotEqual(t, -1, sniPos)
	require.Equal(t, serverName, string(clientHello[sniPos:sniPos+sniLen]))

	for i := range clientHello {
		_, _, _, err := FindSNIAndECH(clientHello[:i])
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	}
}
