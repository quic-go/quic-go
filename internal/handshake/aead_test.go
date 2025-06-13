package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"github.com/Noooste/utls"
	"testing"

	"github.com/Noooste/uquic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func getSealerAndOpener(t *testing.T, cs *cipherSuite, v protocol.Version) (LongHeaderSealer, LongHeaderOpener) {
	t.Helper()
	key := make([]byte, 16)
	hpKey := make([]byte, 16)
	rand.Read(key)
	rand.Read(hpKey)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)

	return newLongHeaderSealer(&xorNonceAEAD{aead: aead}, newHeaderProtector(cs, hpKey, true, v)),
		newLongHeaderOpener(&xorNonceAEAD{aead: aead}, newHeaderProtector(cs, hpKey, true, v))
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
				require.Equal(t, ErrDecryptionFailed, err)

				// incorrect packet number
				_, err = opener.Open(nil, encrypted, 0x42, ad)
				require.Equal(t, ErrDecryptionFailed, err)
			})
		}
	}
}

func TestDecodePacketNumber(t *testing.T) {
	msg := []byte("Lorem ipsum dolor sit amet")
	ad := []byte("Donec in velit neque.")

	sealer, opener := getSealerAndOpener(t, getCipherSuite(tls.TLS_AES_128_GCM_SHA256), protocol.Version1)
	encrypted := sealer.Seal(nil, msg, 0x1337, ad)

	// can't decode the packet number if encryption failed
	_, err := opener.Open(nil, encrypted[:len(encrypted)-1], 0x1337, ad)
	require.Error(t, err)
	require.Equal(t, protocol.PacketNumber(0x38), opener.DecodePacketNumber(0x38, protocol.PacketNumberLen1))

	_, err = opener.Open(nil, encrypted, 0x1337, ad)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(0x1338), opener.DecodePacketNumber(0x38, protocol.PacketNumberLen1))
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

func testEncryptAndDecryptHeader(t *testing.T, cs *cipherSuite, v protocol.Version) {
	sealer, opener := getSealerAndOpener(t, cs, v)
	var lastFourBitsDifferent int

	for i := 0; i < 100; i++ {
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
