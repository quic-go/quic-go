package handshake

import (
	"encoding/hex"
	"math/rand"
	"strings"

	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Initial AEAD using AES-GCM", func() {
	split := func(s string) (slice []byte) {
		for _, ss := range strings.Split(s, " ") {
			if ss[0:2] == "0x" {
				ss = ss[2:]
			}
			d, err := hex.DecodeString(ss)
			Expect(err).ToNot(HaveOccurred())
			slice = append(slice, d...)
		}
		return
	}

	It("converts the string representation used in the draft into byte slices", func() {
		Expect(split("0xdeadbeef")).To(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
		Expect(split("deadbeef")).To(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
		Expect(split("dead beef")).To(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
	})

	// values taken from https://github.com/quicwg/base-drafts/wiki/Test-Vector-for-the-Clear-Text-AEAD-key-derivation
	Context("using the test vector from the QUIC draft", func() {
		var connID protocol.ConnectionID

		BeforeEach(func() {
			connID = protocol.ConnectionID(split("0x8394c8f03e515708"))
		})

		It("computes the client key and IV", func() {
			clientSecret, _ := computeSecrets(connID)
			Expect(clientSecret).To(Equal(split("8a3515a14ae3c31b9c2d6d5bc58538ca 5cd2baa119087143e60887428dcb52f6")))
			key, hpKey, iv := computeInitialKeyAndIV(clientSecret)
			Expect(key).To(Equal(split("98b0d7e5e7a402c67c33f350fa65ea54")))
			Expect(iv).To(Equal(split("19e94387805eb0b46c03a788")))
			Expect(hpKey).To(Equal(split("0edd982a6ac527f2eddcbb7348dea5d7")))
		})

		It("computes the server key and IV", func() {
			_, serverSecret := computeSecrets(connID)
			Expect(serverSecret).To(Equal(split("47b2eaea6c266e32c0697a9e2a898bdf 5c4fb3e5ac34f0e549bf2c58581a3811")))
			key, hpKey, iv := computeInitialKeyAndIV(serverSecret)
			Expect(key).To(Equal(split("9a8be902a9bdd91d16064ca118045fb4")))
			Expect(iv).To(Equal(split("0a82086d32205ba22241d8dc")))
			Expect(hpKey).To(Equal(split("94b9452d2b3c7c7f6da7fdd8593537fd")))
		})
	})

	It("seals and opens", func() {
		connectionID := protocol.ConnectionID{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef}
		clientSealer, clientOpener, err := NewInitialAEAD(connectionID, protocol.PerspectiveClient)
		Expect(err).ToNot(HaveOccurred())
		serverSealer, serverOpener, err := NewInitialAEAD(connectionID, protocol.PerspectiveServer)
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
		clientSealer, _, err := NewInitialAEAD(c1, protocol.PerspectiveClient)
		Expect(err).ToNot(HaveOccurred())
		_, serverOpener, err := NewInitialAEAD(c2, protocol.PerspectiveServer)
		Expect(err).ToNot(HaveOccurred())

		clientMessage := clientSealer.Seal(nil, []byte("foobar"), 42, []byte("aad"))
		_, err = serverOpener.Open(nil, clientMessage, 42, []byte("aad"))
		Expect(err).To(MatchError("cipher: message authentication failed"))
	})

	It("encrypts und decrypts the header", func() {
		connID := protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad}
		clientSealer, clientOpener, err := NewInitialAEAD(connID, protocol.PerspectiveClient)
		Expect(err).ToNot(HaveOccurred())
		serverSealer, serverOpener, err := NewInitialAEAD(connID, protocol.PerspectiveServer)
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
