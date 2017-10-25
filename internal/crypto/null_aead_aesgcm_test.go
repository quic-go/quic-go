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
				0x31, 0xba, 0x96, 0x68, 0x73, 0xf7, 0xf4, 0x53,
				0xe6, 0xc8, 0xa1, 0xbf, 0x78, 0xed, 0x70, 0x13,
				0xfa, 0xd8, 0x3f, 0xfc, 0xee, 0xfc, 0x95, 0x68,
				0x81, 0xcd, 0x24, 0x1c, 0x0a, 0xe3, 0xa7, 0xa6,
			}))
			Expect(serverSecret).To(Equal([]byte{
				0x91, 0xa9, 0xe4, 0x22, 0x2c, 0xcb, 0xb9, 0xa9,
				0x8f, 0x14, 0xc8, 0xe1, 0xbe, 0xfd, 0x6a, 0x79,
				0xf0, 0x4e, 0x42, 0xa2, 0x4f, 0xbe, 0xb4, 0x83,
				0x1f, 0x50, 0x26, 0x80, 0x7a, 0xe8, 0x4c, 0xc3,
			}))
		})

		It("computes the client key and IV", func() {
			clientSecret, _ := computeSecrets(connID)
			key, iv := computeNullAEADKeyAndIV(clientSecret)
			Expect(key).To(Equal([]byte{
				0x2e, 0xbd, 0x78, 0x00, 0xdb, 0xed, 0x20, 0x10,
				0xe5, 0xa2, 0x1c, 0x4a, 0xd2, 0x4b, 0x4e, 0xc3,
			}))
			Expect(iv).To(Equal([]byte{
				0x55, 0x44, 0x0d, 0x5f, 0xf7, 0x50, 0x3d, 0xe4,
				0x99, 0x7b, 0xfd, 0x6b,
			}))
		})

		It("computes the server key and IV", func() {
			_, serverSecret := computeSecrets(connID)
			key, iv := computeNullAEADKeyAndIV(serverSecret)
			Expect(key).To(Equal([]byte{
				0xc8, 0xea, 0x1b, 0xc1, 0x71, 0xe5, 0x2b, 0xae,
				0x71, 0xfb, 0x78, 0x39, 0x52, 0xc7, 0xb8, 0xfc,
			}))
			Expect(iv).To(Equal([]byte{
				0x57, 0x82, 0x3b, 0x85, 0x2c, 0x7e, 0xf9, 0xe3,
				0x80, 0x2b, 0x69, 0x0b,
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
