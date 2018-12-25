package handshake

import (
	"math/rand"

	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Initial AEAD using AES-GCM", func() {
	// values taken from https://github.com/quicwg/base-drafts/wiki/Test-Vector-for-the-Clear-Text-AEAD-key-derivation
	Context("using the test vector from the QUIC WG Wiki", func() {
		connID := protocol.ConnectionID([]byte{0xc6, 0x54, 0xef, 0xd8, 0xa3, 0x1b, 0x47, 0x92})

		It("computes the secrets", func() {
			clientSecret, serverSecret := computeSecrets(connID)
			Expect(clientSecret).To(Equal([]byte{
				0x0c, 0x74, 0xbb, 0x95, 0xa1, 0x04, 0x8e, 0x52,
				0xef, 0x3b, 0x72, 0xe1, 0x28, 0x89, 0x35, 0x1c,
				0xd7, 0x3a, 0x55, 0x0f, 0xb6, 0x2c, 0x4b, 0xb0,
				0x87, 0xe9, 0x15, 0xcc, 0xe9, 0x6c, 0xe3, 0xa0,
			}))
			Expect(serverSecret).To(Equal([]byte{
				0x4c, 0x9e, 0xdf, 0x24, 0xb0, 0xe5, 0xe5, 0x06,
				0xdd, 0x3b, 0xfa, 0x4e, 0x0a, 0x03, 0x11, 0xe8,
				0xc4, 0x1f, 0x35, 0x42, 0x73, 0xd8, 0xcb, 0x49,
				0xdd, 0xd8, 0x46, 0x41, 0x38, 0xd4, 0x7e, 0xc6,
			}))
		})

		It("computes the client key and IV", func() {
			clientSecret, _ := computeSecrets(connID)
			key, pnKey, iv := computeInitialKeyAndIV(clientSecret)
			Expect(key).To(Equal([]byte{
				0x86, 0xd1, 0x83, 0x04, 0x80, 0xb4, 0x0f, 0x86,
				0xcf, 0x9d, 0x68, 0xdc, 0xad, 0xf3, 0x5d, 0xfe,
			}))
			Expect(pnKey).To(Equal([]byte{
				0xcd, 0x25, 0x3a, 0x36, 0xff, 0x93, 0x93, 0x7c,
				0x46, 0x93, 0x84, 0xa8, 0x23, 0xaf, 0x6c, 0x56,
			}))
			Expect(iv).To(Equal([]byte{
				0x12, 0xf3, 0x93, 0x8a, 0xca, 0x34, 0xaa, 0x02,
				0x54, 0x31, 0x63, 0xd4,
			}))
		})

		It("computes the server key and IV", func() {
			_, serverSecret := computeSecrets(connID)
			key, pnKey, iv := computeInitialKeyAndIV(serverSecret)
			Expect(key).To(Equal([]byte{
				0x2c, 0x78, 0x63, 0x3e, 0x20, 0x6e, 0x99, 0xad,
				0x25, 0x19, 0x64, 0xf1, 0x9f, 0x6d, 0xcd, 0x6d,
			}))
			Expect(pnKey).To(Equal([]byte{
				0x25, 0x79, 0xd8, 0x69, 0x6f, 0x85, 0xed, 0xa6,
				0x8d, 0x35, 0x02, 0xb6, 0x55, 0x96, 0x58, 0x6b,
			}))
			Expect(iv).To(Equal([]byte{
				0x7b, 0x50, 0xbf, 0x36, 0x98, 0xa0, 0x6d, 0xfa,
				0xbf, 0x75, 0xf2, 0x87,
			}))
		})
	})

	It("seals and opens", func() {
		connectionID := protocol.ConnectionID{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef}
		clientSealer, clientOpener, err := newInitialAEAD(connectionID, protocol.PerspectiveClient)
		Expect(err).ToNot(HaveOccurred())
		serverSealer, serverOpener, err := newInitialAEAD(connectionID, protocol.PerspectiveServer)
		Expect(err).ToNot(HaveOccurred())

		clientMessage := clientSealer.Seal(nil, []byte("foobar"), 42, []byte("aad"))
		m, err := serverOpener.Open(nil, clientMessage, 42, []byte("aad"))
		Expect(err).ToNot(HaveOccurred())
		Expect(m).To(Equal([]byte("foobar")))
		serverMessage := serverSealer.Seal(nil, []byte("raboof"), 99, []byte("daa"))
		m, err = clientOpener.Open(nil, serverMessage, 99, []byte("daa"))
		Expect(err).ToNot(HaveOccurred())
		Expect(m).To(Equal([]byte("raboof")))
	})

	It("doesn't work if initialized with different connection IDs", func() {
		c1 := protocol.ConnectionID{0, 0, 0, 0, 0, 0, 0, 1}
		c2 := protocol.ConnectionID{0, 0, 0, 0, 0, 0, 0, 2}
		clientSealer, _, err := newInitialAEAD(c1, protocol.PerspectiveClient)
		Expect(err).ToNot(HaveOccurred())
		_, serverOpener, err := newInitialAEAD(c2, protocol.PerspectiveServer)
		Expect(err).ToNot(HaveOccurred())

		clientMessage := clientSealer.Seal(nil, []byte("foobar"), 42, []byte("aad"))
		_, err = serverOpener.Open(nil, clientMessage, 42, []byte("aad"))
		Expect(err).To(MatchError("cipher: message authentication failed"))
	})

	It("encrypts und decrypts the header", func() {
		connID := protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad}
		clientSealer, clientOpener, err := newInitialAEAD(connID, protocol.PerspectiveClient)
		Expect(err).ToNot(HaveOccurred())
		serverSealer, serverOpener, err := newInitialAEAD(connID, protocol.PerspectiveServer)
		Expect(err).ToNot(HaveOccurred())

		// the first byte and the last 4 bytes should be encrypted
		header := []byte{0x5e, 0, 1, 2, 3, 4, 0xde, 0xad, 0xbe, 0xef}
		sample := make([]byte, 16)
		rand.Read(sample)
		clientSealer.EncryptHeader(sample, &header[0], header[6:10])
		// only the last 4 bits of the first byte are encrypted. Check that the first 4 bits are unmodified
		Expect(header[0] & 0xf0).To(Equal(byte(0x5e & 0xf0)))
		Expect(header[1:6]).To(Equal([]byte{0, 1, 2, 3, 4}))
		Expect(header[6:10]).ToNot(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
		serverOpener.DecryptHeader(sample, &header[0], header[6:10])
		Expect(header[0]).To(Equal(byte(0x5e)))
		Expect(header[1:6]).To(Equal([]byte{0, 1, 2, 3, 4}))
		Expect(header[6:10]).To(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))

		serverSealer.EncryptHeader(sample, &header[0], header[6:10])
		// only the last 4 bits of the first byte are encrypted. Check that the first 4 bits are unmodified
		Expect(header[0] & 0xf0).To(Equal(byte(0x5e & 0xf0)))
		Expect(header[1:6]).To(Equal([]byte{0, 1, 2, 3, 4}))
		Expect(header[6:10]).ToNot(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
		clientOpener.DecryptHeader(sample, &header[0], header[6:10])
		Expect(header[0]).To(Equal(byte(0x5e)))
		Expect(header[1:6]).To(Equal([]byte{0, 1, 2, 3, 4}))
		Expect(header[6:10]).To(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
	})
})
