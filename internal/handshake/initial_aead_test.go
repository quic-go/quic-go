package handshake

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Initial AEAD using AES-GCM", func() {
	// values taken from https://github.com/quicwg/base-drafts/wiki/Test-Vector-for-the-Clear-Text-AEAD-key-derivation
	Context("using the test vector from the QUIC WG Wiki", func() {
		connID := protocol.ConnectionID([]byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08})

		It("computes the secrets", func() {
			clientSecret, serverSecret := computeSecrets(connID)
			Expect(clientSecret).To(Equal([]byte{
				0x9f, 0x53, 0x64, 0x57, 0xf3, 0x2a, 0x1e, 0x0a,
				0xe8, 0x64, 0xbc, 0xb3, 0xca, 0xf1, 0x23, 0x51,
				0x10, 0x63, 0x0e, 0x1d, 0x1f, 0xb3, 0x38, 0x35,
				0xbd, 0x05, 0x41, 0x70, 0xf9, 0x9b, 0xf7, 0xdc,
			}))
			Expect(serverSecret).To(Equal([]byte{
				0xb0, 0x87, 0xdc, 0xd7, 0x47, 0x8d, 0xda, 0x8a,
				0x85, 0x8f, 0xbf, 0x3d, 0x60, 0x5c, 0x88, 0x85,
				0x86, 0xc0, 0xa3, 0xa9, 0x87, 0x54, 0x23, 0xad,
				0x4f, 0x11, 0x4f, 0x0b, 0xa3, 0x8e, 0x5a, 0x2e,
			}))
		})

		It("computes the client key and IV", func() {
			clientSecret, _ := computeSecrets(connID)
			key, pnKey, iv := computeInitialKeyAndIV(clientSecret)
			Expect(key).To(Equal([]byte{
				0xf2, 0x92, 0x8f, 0x26, 0x14, 0xad, 0x6c, 0x20,
				0xb9, 0xbd, 0x00, 0x8e, 0x9c, 0x89, 0x63, 0x1c,
			}))
			Expect(pnKey).To(Equal([]byte{
				0x68, 0xc3, 0xf6, 0x4e, 0x2d, 0x66, 0x34, 0x41,
				0x2b, 0x8e, 0x32, 0x94, 0x62, 0x8d, 0x76, 0xf1,
			}))
			Expect(iv).To(Equal([]byte{
				0xab, 0x95, 0x0b, 0x01, 0x98, 0x63, 0x79, 0x78,
				0xcf, 0x44, 0xaa, 0xb9,
			}))
		})

		It("computes the server key and IV", func() {
			_, serverSecret := computeSecrets(connID)
			key, pnKey, iv := computeInitialKeyAndIV(serverSecret)
			Expect(key).To(Equal([]byte{
				0xf5, 0x68, 0x17, 0xd0, 0xfc, 0x59, 0x5c, 0xfc,
				0x0a, 0x2b, 0x0b, 0xcf, 0xb1, 0x87, 0x35, 0xec,
			}))
			Expect(pnKey).To(Equal([]byte{
				0xa3, 0x13, 0xc8, 0x6d, 0x13, 0x73, 0xec, 0xbc,
				0xcb, 0x32, 0x94, 0xb1, 0x49, 0x74, 0x22, 0x6c,
			}))
			Expect(iv).To(Equal([]byte{
				0x32, 0x05, 0x03, 0x5a, 0x3c, 0x93, 0x7c, 0x90,
				0x2e, 0xe4, 0xf4, 0xd6,
			}))
		})
	})

	It("seals and opens", func() {
		connectionID := protocol.ConnectionID([]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef})
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
		c1 := protocol.ConnectionID([]byte{0, 0, 0, 0, 0, 0, 0, 1})
		c2 := protocol.ConnectionID([]byte{0, 0, 0, 0, 0, 0, 0, 2})
		clientSealer, _, err := newInitialAEAD(c1, protocol.PerspectiveClient)
		Expect(err).ToNot(HaveOccurred())
		_, serverOpener, err := newInitialAEAD(c2, protocol.PerspectiveServer)
		Expect(err).ToNot(HaveOccurred())

		clientMessage := clientSealer.Seal(nil, []byte("foobar"), 42, []byte("aad"))
		_, err = serverOpener.Open(nil, clientMessage, 42, []byte("aad"))
		Expect(err).To(MatchError("cipher: message authentication failed"))
	})
})
