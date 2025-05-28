//go:build go1.24

package quic

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"github.com/Noooste/utls"
	"io"
	mrand "math/rand/v2"
	"testing"

	"golang.org/x/crypto/cryptobyte"

	"github.com/Noooste/quic-go/internal/protocol"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getClientHelloWithECH(t testing.TB, serverName string) []byte {
	t.Helper()

	// various constants from the standard library's (internal) hpke package
	const (
		DHKEM_X25519_HKDF_SHA256 = 0x20
		KDF_HKDF_SHA256          = 1
		AEAD_AES_128_GCM         = 1
	)

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
			InsecureSkipVerify:             serverName == "",
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

// shuffleClientHelloExtensions takes a TLS 1.3 ClientHello message (without the record layer)
// and returns a new ClientHello with its extensions shuffled. Returns nil if the input is invalid.
func shuffleClientHelloExtensions(t testing.TB, clientHello []byte) []byte {
	t.Helper()

	// Basic validation: ensure minimum length and correct handshake type (0x01 for ClientHello)
	if len(clientHello) < 4 || clientHello[0] != 0x01 {
		t.Fatalf("not a ClientHello")
	}

	// Extract the 3-byte length (24-bit integer) and validate total length
	length := uint32(clientHello[1])<<16 | uint32(clientHello[2])<<8 | uint32(clientHello[3])
	require.Equal(t, 4+int(length), len(clientHello))

	// Body is everything after type and length
	body := clientHello[4 : 4+length]
	var pos int
	// Parse fixed and variable-length fields to reach extensions
	require.Greater(t, len(body), pos+2) // protocol version: 2 bytes
	pos += 2
	require.Greater(t, len(body), pos+32) // random: 32 bytes
	pos += 32
	require.Greater(t, len(body), pos+1) // session ID length: 1 byte
	sessionIDLen := int(body[pos])
	pos += 1
	require.Greater(t, len(body), pos+sessionIDLen) // session ID data
	pos += sessionIDLen
	require.Greater(t, len(body), pos+2) // cipher suites length: 2 bytes
	cipherSuitesLen := int(body[pos])<<8 | int(body[pos+1])
	pos += 2
	require.Greater(t, len(body), pos+cipherSuitesLen) // cipher suites data
	pos += cipherSuitesLen
	require.Greater(t, len(body), pos+1) // compression methods length: 1 byte
	compressionMethodsLen := int(body[pos])
	pos += 1
	require.Greater(t, len(body), pos+compressionMethodsLen) // compression methods data
	pos += compressionMethodsLen

	// Extensions: 2 bytes total length + data (may be absent)
	if pos+2 > len(body) {
		// No extensions present; return original
		return clientHello
	}
	extensionsLen := int(body[pos])<<8 | int(body[pos+1])
	pos += 2
	require.Equal(t, pos+extensionsLen, len(body)) // extensions length doesn't match remaining data
	extensionsData := body[pos : pos+extensionsLen]

	// parse extensions into a slice of byte slices
	var extensions [][]byte
	var extPos int
	for extPos < extensionsLen {
		require.Greater(t, extensionsLen, extPos+4) // type and length
		extLen := int(extensionsData[extPos+2])<<8 | int(extensionsData[extPos+3])
		require.LessOrEqual(t, extPos+4+extLen, extensionsLen) // extension exceeds total length
		// extract entire extension (type: 2 bytes, length: 2 bytes, data)
		extData := extensionsData[extPos : extPos+4+extLen]
		extensions = append(extensions, extData)
		extPos += 4 + extLen
	}

	// shuffle extensions using a proper random source
	mrand.Shuffle(len(extensions), func(i, j int) {
		extensions[i], extensions[j] = extensions[j], extensions[i]
	})

	// reconstruct extensions data
	var newExtensionsData []byte
	for _, ext := range extensions {
		newExtensionsData = append(newExtensionsData, ext...)
	}

	// reconstruct body: prefix (up to and including extensions length) + shuffled extensions
	prefix := body[:pos]
	newBody := append(prefix, newExtensionsData...)
	// reconstruct ClientHello: type (0x01) + original length + new body
	newClientHello := []byte{0x01}
	lengthBytes := clientHello[1:4] // length unchanged since only extensions are shuffled
	newClientHello = append(newClientHello, lengthBytes...)
	newClientHello = append(newClientHello, newBody...)
	// check that it's actually valid
	checkClientHello(t, newClientHello)
	return newClientHello
}

func TestFindSNIWithECH(t *testing.T) {
	const serverName = "public.example"
	clientHello := shuffleClientHelloExtensions(t, getClientHelloWithECH(t, serverName))
	sniPos, sniLen, echPos, err := findSNIAndECH(clientHello)
	require.NoError(t, err)
	require.NotEqual(t, -1, echPos)
	require.Equal(t, uint16(extTypeECH), binary.BigEndian.Uint16(clientHello[echPos:echPos+2]))
	assert.Equal(t, len(serverName), sniLen)
	require.NotEqual(t, -1, sniPos)
	require.Equal(t, serverName, string(clientHello[sniPos:sniPos+sniLen]))

	for i := range clientHello {
		_, _, _, err := findSNIAndECH(clientHello[:i])
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	}
}

// findSNI is never run with attacker-controlled inputs (other than the session ticket),
// so this is not a high-value target to begin with,
// and doesn't need to be run in ClusterFuzz.
// It's still useful to find potential corner cases in the parser.
func FuzzFindSNI(f *testing.F) {
	f.Add(getClientHello(f, ""), 10)
	f.Add(getClientHello(f, "google.com"), 20)
	f.Add(getClientHello(f, "sub.do.ma.in.quic-go.net"), 30)
	f.Add(getClientHelloWithECH(f, "quic-go.net"), 40)

	f.Fuzz(func(t *testing.T, data []byte, maxSize int) {
		cs := newInitialCryptoStream(true)
		if _, err := cs.Write(data); err != nil {
			return
		}
		segments := make(map[protocol.ByteCount][]byte)
		if !cs.HasData() { // incomplete ClientHello
			return
		}
		for cs.HasData() {
			f := cs.PopCryptoFrame(5 + protocol.ByteCount(maxSize))
			if f == nil {
				return
			}
			segments[f.Offset] = f.Data
		}
		reassembled := reassembleCryptoData(t, segments)
		require.Equal(t, data, reassembled)
	})
}
