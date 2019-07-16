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
	// The draft didn't update the test vectors for -22.
	PContext("using the test vector from the QUIC draft", func() {
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

		It("encrypts the client's Initial", func() {
			sealer, _, err := NewInitialAEAD(connID, protocol.PerspectiveClient)
			Expect(err).ToNot(HaveOccurred())
			header := split("c3ff000012508394c8f03e51570800449f00000002")
			data := split("060040c4010000c003036660261ff947 cea49cce6cfad687f457cf1b14531ba1 4131a0e8f309a1d0b9c4000006130113 031302010000910000000b0009000006 736572766572ff01000100000a001400 12001d00170018001901000101010201 03010400230000003300260024001d00 204cfdfcd178b784bf328cae793b136f 2aedce005ff183d7bb14952072366470 37002b0003020304000d0020001e0403 05030603020308040805080604010501 060102010402050206020202002d0002 0101001c00024001")
			data = append(data, make([]byte, 1163-len(data))...) // add PADDING
			sealed := sealer.Seal(nil, data, 2, header)
			sample := sealed[0:16]
			Expect(sample).To(Equal(split("0000f3a694c75775b4e546172ce9e047")))
			sealer.EncryptHeader(sample, &header[0], header[len(header)-4:])
			Expect(header[0]).To(Equal(byte(0xc1)))
			Expect(header[17:21]).To(Equal(split("0dbc195a")))
			packet := append(header, sealed...)
			Expect(packet).To(Equal(split("c1ff000012508394c8f03e5157080044 9f0dbc195a0000f3a694c75775b4e546 172ce9e047cd0b5bee5181648c727adc 87f7eae54473ec6cba6bdad4f5982317 4b769f12358abd292d4f3286934484fb 8b239c38732e1f3bbbc6a003056487eb 8b5c88b9fd9279ffff3b0f4ecf95c462 4db6d65d4113329ee9b0bf8cdd7c8a8d 72806d55df25ecb66488bc119d7c9a29 abaf99bb33c56b08ad8c26995f838bb3 b7a3d5c1858b8ec06b839db2dcf918d5 ea9317f1acd6b663cc8925868e2f6a1b da546695f3c3f33175944db4a11a346a fb07e78489e509b02add51b7b203eda5 c330b03641179a31fbba9b56ce00f3d5 b5e3d7d9c5429aebb9576f2f7eacbe27 bc1b8082aaf68fb69c921aa5d33ec0c8 510410865a178d86d7e54122d55ef2c2 bbc040be46d7fece73fe8a1b24495ec1 60df2da9b20a7ba2f26dfa2a44366dbc 63de5cd7d7c94c57172fe6d79c901f02 5c0010b02c89b395402c009f62dc053b 8067a1e0ed0a1e0cf5087d7f78cbd94a fe0c3dd55d2d4b1a5cfe2b68b86264e3 51d1dcd858783a240f893f008ceed743 d969b8f735a1677ead960b1fb1ecc5ac 83c273b49288d02d7286207e663c45e1 a7baf50640c91e762941cf380ce8d79f 3e86767fbbcd25b42ef70ec334835a3a 6d792e170a432ce0cb7bde9aaa1e7563 7c1c34ae5fef4338f53db8b13a4d2df5 94efbfa08784543815c9c0d487bddfa1 539bc252cf43ec3686e9802d651cfd2a 829a06a9f332a733a4a8aed80efe3478 093fbc69c8608146b3f16f1a5c4eac93 20da49f1afa5f538ddecbbe7888f4355 12d0dd74fd9b8c99e3145ba84410d8ca 9a36dd884109e76e5fb8222a52e1473d a168519ce7a8a3c32e9149671b16724c 6c5c51bb5cd64fb591e567fb78b10f9f 6fee62c276f282a7df6bcf7c17747bc9 a81e6c9c3b032fdd0e1c3ac9eaa5077d e3ded18b2ed4faf328f49875af2e36ad 5ce5f6cc99ef4b60e57b3b5b9c9fcbcd 4cfb3975e70ce4c2506bcd71fef0e535 92461504e3d42c885caab21b782e2629 4c6a9d61118cc40a26f378441ceb48f3 1a362bf8502a723a36c63502229a462c c2a3796279a5e3a7f81a68c7f81312c3 81cc16a4ab03513a51ad5b54306ec1d7 8a5e47e2b15e5b7a1438e5b8b2882dbd ad13d6a4a8c3558cae043501b68eb3b0 40067152337c051c40b5af809aca2856 986fd1c86a4ade17d254b6262ac1bc07 7343b52bf89fa27d73e3c6f3118c9961 f0bebe68a5c323c2d84b8c29a2807df6 63635223242a2ce9828d4429ac270aab 5f1841e8e49cf433b1547989f419caa3 c758fff96ded40cf3427f0761b678daa 1a9e5554465d46b7a917493fc70f9ec5 e4e5d786ca501730898aaa1151dcd318 29641e29428d90e6065511c24d3109f7 cba32225d4accfc54fec42b733f95852 52ee36fa5ea0c656934385b468eee245 315146b8c047ed27c519b2c0a52d33ef e72c186ffe0a230f505676c5324baa6a e006a73e13aa8c39ab173ad2b2778eea 0b34c46f2b3beae2c62a2c8db238bf58 fc7c27bdceb96c56d29deec87c12351b fd5962497418716a4b915d334ffb5b92 ca94ffe1e4f78967042638639a9de325 357f5f08f6435061e5a274703936c06f c56af92c420797499ca431a7abaa4618 63bca656facfad564e6274d4a741033a ca1e31bf63200df41cdf41c10b912bec")))
		})

		It("encrypt the server's Initial", func() {
			sealer, _, err := NewInitialAEAD(connID, protocol.PerspectiveServer)
			Expect(err).ToNot(HaveOccurred())
			header := split("c1ff00001205f067a5502a4262b50040740001")
			data := split("0d0000000018410a020000560303eefc e7f7b37ba1d1632e96677825ddf73988 cfc79825df566dc5430b9a045a120013 0100002e00330024001d00209d3c940d 89690b84d08a60993c144eca684d1081 287c834d5311bcf32bb9da1a002b0002 0304")
			sealed := sealer.Seal(nil, data, 1, header)
			sample := sealed[2:18]
			Expect(sample).To(Equal(split("c4c2a2303d297e3c519bf6b22386e3d0")))
			sealer.EncryptHeader(sample, &header[0], header[len(header)-2:])
			Expect(header).To(Equal(split("c4ff00001205f067a5502a4262b5004074f7ed")))
			packet := append(header, sealed...)
			Expect(packet).To(Equal(split("c4ff00001205f067a5502a4262b50040 74f7ed5f01c4c2a2303d297e3c519bf6 b22386e3d0bd6dfc6612167729803104 1bb9a79c9f0f9d4c5877270a660f5da3 6207d98b73839b2fdf2ef8e7df5a51b1 7b8c68d864fd3e708c6c1b71a98a3318 15599ef5014ea38c44bdfd387c03b527 5c35e009b6238f831420047c7271281c cb54df7884")))
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
		Expect(err).To(MatchError(ErrDecryptionFailed))
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
