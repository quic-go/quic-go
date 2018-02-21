package crypto

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("NullAEAD using AES-GCM", func() {
	// values taken from https://github.com/quicwg/base-drafts/wiki/Test-Vector-for-the-Clear-Text-AEAD-key-derivation
	Context("using the test vector from the QUIC WG Wiki", func() {
		connID := protocol.ConnectionID(0x8394c8f03e515708)

		It("computes the secrets", func() {
			clientSecret, serverSecret := computeSecrets(connID)
			Expect(clientSecret).To(Equal([]byte{
				0x8e, 0x28, 0x6a, 0x27, 0x38, 0xe6, 0x66, 0x50,
				0xb4, 0xf8, 0x8f, 0xac, 0x5d, 0xc5, 0xd0, 0xef,
				0x7d, 0x36, 0x9b, 0x07, 0xd4, 0x74, 0x42, 0x99,
				0x1a, 0x00, 0x0c, 0x55, 0xac, 0xc4, 0x0c, 0xf4,
			}))
			Expect(serverSecret).To(Equal([]byte{
				0xfa, 0xb5, 0xb7, 0xf5, 0x26, 0xec, 0xaf, 0xaf,
				0x74, 0x71, 0x52, 0xdd, 0xaa, 0x88, 0x28, 0x56,
				0xf9, 0xbe, 0xd7, 0x48, 0x81, 0x1e, 0x37, 0xff,
				0xe1, 0xcb, 0xb1, 0x55, 0xe1, 0xc9, 0x91, 0xad,
			}))
		})

		It("computes the client key and IV", func() {
			clientSecret, _ := computeSecrets(connID)
			key, iv := computeNullAEADKeyAndIV(clientSecret)
			Expect(key).To(Equal([]byte{
				0x6b, 0x6a, 0xbc, 0x50, 0xf7, 0xac, 0x46, 0xd1,
				0x10, 0x8c, 0x19, 0xcc, 0x63, 0x64, 0xbd, 0xe3,
			}))
			Expect(iv).To(Equal([]byte{
				0xb1, 0xf9, 0xa7, 0xe2, 0x7c, 0xc2, 0x33, 0xbb,
				0x99, 0xe2, 0x03, 0x71,
			}))
		})

		It("computes the server key and IV", func() {
			_, serverSecret := computeSecrets(connID)
			key, iv := computeNullAEADKeyAndIV(serverSecret)
			Expect(key).To(Equal([]byte{
				0x9e, 0xe7, 0xe8, 0x57, 0x72, 0x00, 0x59, 0xaf,
				0x30, 0x11, 0xfb, 0x26, 0xe1, 0x21, 0x42, 0xc9,
			}))
			Expect(iv).To(Equal([]byte{
				0xd5, 0xee, 0xe8, 0xb5, 0x7c, 0x9e, 0xc7, 0xc4,
				0xbe, 0x98, 0x4a, 0xa5,
			}))
		})
	})

	It("seals and opens", func() {
		connectionID := protocol.ConnectionID(0x1234567890)
		clientAEAD, err := newNullAEADAESGCM(connectionID, protocol.PerspectiveClient)
		Expect(err).ToNot(HaveOccurred())
		serverAEAD, err := newNullAEADAESGCM(connectionID, protocol.PerspectiveServer)
		Expect(err).ToNot(HaveOccurred())

		clientMessage := clientAEAD.Seal(nil, []byte("foobar"), 42, []byte("aad"))
		m, err := serverAEAD.Open(nil, clientMessage, 42, []byte("aad"))
		Expect(err).ToNot(HaveOccurred())
		Expect(m).To(Equal([]byte("foobar")))
		serverMessage := serverAEAD.Seal(nil, []byte("raboof"), 99, []byte("daa"))
		m, err = clientAEAD.Open(nil, serverMessage, 99, []byte("daa"))
		Expect(err).ToNot(HaveOccurred())
		Expect(m).To(Equal([]byte("raboof")))
	})

	It("doesn't work if initialized with different connection IDs", func() {
		clientAEAD, err := newNullAEADAESGCM(1, protocol.PerspectiveClient)
		Expect(err).ToNot(HaveOccurred())
		serverAEAD, err := newNullAEADAESGCM(2, protocol.PerspectiveServer)
		Expect(err).ToNot(HaveOccurred())

		clientMessage := clientAEAD.Seal(nil, []byte("foobar"), 42, []byte("aad"))
		_, err = serverAEAD.Open(nil, clientMessage, 42, []byte("aad"))
		Expect(err).To(MatchError("cipher: message authentication failed"))
	})
})
