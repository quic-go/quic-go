package handshake

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func getSealerAndOpener(t *testing.T, cs cipherSuite, v protocol.Version) (LongHeaderSealer, LongHeaderOpener) {
	t.Helper()
	trafficSecret := make([]byte, cs.Hash.Size())
	hpKey := make([]byte, 16)
	rand.Read(trafficSecret)
	rand.Read(hpKey)
	aead := createAEAD(cs, trafficSecret, v)
	return newLongHeaderSealer(aead, newHeaderProtector(cs, hpKey, true, v)),
		newLongHeaderOpener(aead, newHeaderProtector(cs, hpKey, true, v))
}

func TestEncryptAndDecryptMessage(t *testing.T) {
	for _, v := range []protocol.Version{protocol.Version1, protocol.Version2} {
		for _, cs := range cipherSuites {
			t.Run(fmt.Sprintf("QUIC %s/%s", v, tls.CipherSuiteName(cs.ID)), func(t *testing.T) {
				sealer, opener := getSealerAndOpener(t, cs, v)
				msg := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")
				ad := []byte("Donec in velit neque.")

				encrypted := sealer.Seal(nil, msg, 0x1337, ad)

				opened, err := opener.Open(nil, encrypted, 0x1337, ad)
				require.NoError(t, err)
				require.Equal(t, msg, opened)

				// incorrect associated data
				_, err = opener.Open(nil, encrypted, 0x1337, []byte("wrong ad"))
				require.ErrorIs(t, err, ErrDecryptionFailed)

				// incorrect packet number
				_, err = opener.Open(nil, encrypted, 0x42, ad)
				require.ErrorIs(t, err, ErrDecryptionFailed)
			})
		}
	}
}

func TestEncryptAndDecryptHeader(t *testing.T) {
	for _, v := range []protocol.Version{protocol.Version1, protocol.Version2} {
		t.Run("QUIC "+v.String(), func(t *testing.T) {
			for _, cs := range cipherSuites {
				t.Run(tls.CipherSuiteName(cs.ID), func(t *testing.T) {
					testEncryptAndDecryptHeader(t, cs, v)
				})
			}
		})
	}
}

func testEncryptAndDecryptHeader(t *testing.T, cs cipherSuite, v protocol.Version) {
	sealer, opener := getSealerAndOpener(t, cs, v)
	var lastFourBitsDifferent int

	for range 100 {
		sample := make([]byte, 16)
		rand.Read(sample)
		header := []byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}
		sealer.EncryptHeader(sample, &header[0], header[9:13])
		if header[0]&0xf != 0xb5&0xf {
			lastFourBitsDifferent++
		}
		require.Equal(t, byte(0xb5&0xf0), header[0]&0xf0)
		require.Equal(t, []byte{1, 2, 3, 4, 5, 6, 7, 8}, header[1:9])
		require.NotEqual(t, []byte{0xde, 0xad, 0xbe, 0xef}, header[9:13])
		opener.DecryptHeader(sample, &header[0], header[9:13])
		require.Equal(t, []byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}, header)
	}
	require.Greater(t, lastFourBitsDifferent, 75)

	// decryption failure with different sample
	header := []byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}
	sample := make([]byte, 16)
	rand.Read(sample)
	sealer.EncryptHeader(sample, &header[0], header[9:13])
	rand.Read(sample) // use a different sample
	opener.DecryptHeader(sample, &header[0], header[9:13])
	require.NotEqual(t, []byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}, header)
}
