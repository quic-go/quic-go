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

	// values taken from the Appendix of the draft
	Context("using the test vector from the QUIC draft", func() {
		var connID protocol.ConnectionID

		BeforeEach(func() {
			connID = protocol.ConnectionID(split("0x8394c8f03e515708"))
		})

		It("computes the client key and IV", func() {
			clientSecret, _ := computeSecrets(connID)
			Expect(clientSecret).To(Equal(split("fda3953aecc040e48b34e27ef87de3a6 098ecf0e38b7e032c5c57bcbd5975b84")))
			key, iv := computeInitialKeyAndIV(clientSecret)
			Expect(key).To(Equal(split("af7fd7efebd21878ff66811248983694")))
			Expect(iv).To(Equal(split("8681359410a70bb9c92f0420")))
		})

		It("computes the server key and IV", func() {
			_, serverSecret := computeSecrets(connID)
			Expect(serverSecret).To(Equal(split("554366b81912ff90be41f17e80222130 90ab17d8149179bcadf222f29ff2ddd5")))
			key, iv := computeInitialKeyAndIV(serverSecret)
			Expect(key).To(Equal(split("5d51da9ee897a21b2659ccc7e5bfa577")))
			Expect(iv).To(Equal(split("5e5ae651fd1e8495af13508b")))
		})

		It("encrypts the client's Initial", func() {
			sealer, _ := NewInitialAEAD(connID, protocol.PerspectiveClient)
			header := split("c3ff000017088394c8f03e5157080000449e00000002")
			data := split("060040c4010000c003036660261ff947 cea49cce6cfad687f457cf1b14531ba1 4131a0e8f309a1d0b9c4000006130113 031302010000910000000b0009000006 736572766572ff01000100000a001400 12001d00170018001901000101010201 03010400230000003300260024001d00 204cfdfcd178b784bf328cae793b136f 2aedce005ff183d7bb14952072366470 37002b0003020304000d0020001e0403 05030603020308040805080604010501 060102010402050206020202002d0002 0101001c00024001")
			data = append(data, make([]byte, 1162-len(data))...) // add PADDING
			sealed := sealer.Seal(nil, data, 2, header)
			sample := sealed[0:16]
			Expect(sample).To(Equal(split("535064a4268a0d9d7b1c9d250ae35516")))
			sealer.EncryptHeader(sample, &header[0], header[len(header)-4:])
			Expect(header[0]).To(Equal(byte(0xc0)))
			Expect(header[len(header)-4:]).To(Equal(split("3b343aa8")))
			packet := append(header, sealed...)
			Expect(packet).To(Equal(split("c0ff000017088394c8f03e5157080000 449e3b343aa8535064a4268a0d9d7b1c 9d250ae355162276e9b1e3011ef6bbc0 ab48ad5bcc2681e953857ca62becd752 4daac473e68d7405fbba4e9ee616c870 38bdbe908c06d9605d9ac49030359eec b1d05a14e117db8cede2bb09d0dbbfee 271cb374d8f10abec82d0f59a1dee29f e95638ed8dd41da07487468791b719c5 5c46968eb3b54680037102a28e53dc1d 12903db0af5821794b41c4a93357fa59 ce69cfe7f6bdfa629eef78616447e1d6 11c4baf71bf33febcb03137c2c75d253 17d3e13b684370f668411c0f00304b50 1c8fd422bd9b9ad81d643b20da89ca05 25d24d2b142041cae0af205092e43008 0cd8559ea4c5c6e4fa3f66082b7d303e 52ce0162baa958532b0bbc2bc785681f cf37485dff6595e01e739c8ac9efba31 b985d5f656cc092432d781db95221724 87641c4d3ab8ece01e39bc85b1543661 4775a98ba8fa12d46f9b35e2a55eb72d 7f85181a366663387ddc20551807e007 673bd7e26bf9b29b5ab10a1ca87cbb7a d97e99eb66959c2a9bc3cbde4707ff77 20b110fa95354674e395812e47a0ae53 b464dcb2d1f345df360dc227270c7506 76f6724eb479f0d2fbb6124429990457 ac6c9167f40aab739998f38b9eccb24f d47c8410131bf65a52af841275d5b3d1 880b197df2b5dea3e6de56ebce3ffb6e 9277a82082f8d9677a6767089b671ebd 244c214f0bde95c2beb02cd1172d58bd f39dce56ff68eb35ab39b49b4eac7c81 5ea60451d6e6ab82119118df02a58684 4a9ffe162ba006d0669ef57668cab38b 62f71a2523a084852cd1d079b3658dc2 f3e87949b550bab3e177cfc49ed190df f0630e43077c30de8f6ae081537f1e83 da537da980afa668e7b7fb25301cf741 524be3c49884b42821f17552fbd1931a 813017b6b6590a41ea18b6ba49cd48a4 40bd9a3346a7623fb4ba34a3ee571e3c 731f35a7a3cf25b551a680fa68763507 b7fde3aaf023c50b9d22da6876ba337e b5e9dd9ec3daf970242b6c5aab3aa4b2 96ad8b9f6832f686ef70fa938b31b4e5 ddd7364442d3ea72e73d668fb0937796 f462923a81a47e1cee7426ff6d922126 9b5a62ec03d6ec94d12606cb485560ba b574816009e96504249385bb61a819be 04f62c2066214d8360a2022beb316240 b6c7d78bbe56c13082e0ca272661210a bf020bf3b5783f1426436cf9ff418405 93a5d0638d32fc51c5c65ff291a3a7a5 2fd6775e623a4439cc08dd25582febc9 44ef92d8dbd329c91de3e9c9582e41f1 7f3d186f104ad3f90995116c682a2a14 a3b4b1f547c335f0be710fc9fc03e0e5 87b8cda31ce65b969878a4ad4283e6d5 b0373f43da86e9e0ffe1ae0fddd35162 55bd74566f36a38703d5f34249ded1f6 6b3d9b45b9af2ccfefe984e13376b1b2 c6404aa48c8026132343da3f3a33659e c1b3e95080540b28b7f3fcd35fa5d843 b579a84c089121a60d8c1754915c344e eaf45a9bf27dc0c1e784161691220913 13eb0e87555abd706626e557fc36a04f cd191a58829104d6075c5594f627ca50 6bf181daec940f4a4f3af0074eee89da acde6758312622d4fa675b39f728e062 d2bee680d8f41a597c262648bb18bcfc 13c8b3d97b1a77b2ac3af745d61a34cc 4709865bac824a94bb19058015e4e42d c9be6c7803567321829dd85853396269")))
		})

		It("encrypt the server's Initial", func() {
			sealer, _ := NewInitialAEAD(connID, protocol.PerspectiveServer)
			header := split("c1ff0000170008f067a5502a4262b50040740001")
			data := split("0d0000000018410a020000560303eefc e7f7b37ba1d1632e96677825ddf73988 cfc79825df566dc5430b9a045a120013 0100002e00330024001d00209d3c940d 89690b84d08a60993c144eca684d1081 287c834d5311bcf32bb9da1a002b0002 0304")
			sealed := sealer.Seal(nil, data, 1, header)
			sample := sealed[2 : 2+16]
			Expect(sample).To(Equal(split("7002596f99ae67abf65a5852f54f58c3")))
			sealer.EncryptHeader(sample, &header[0], header[len(header)-2:])
			Expect(header).To(Equal(split("c9ff0000170008f067a5502a4262b5004074168b")))
			packet := append(header, sealed...)
			Expect(packet).To(Equal(split("c9ff0000170008f067a5502a4262b500 4074168bf22b7002596f99ae67abf65a 5852f54f58c37c808682e2e40492d8a3 899fb04fc0afe9aabc8767b18a0aa493 537426373b48d502214dd856d63b78ce e37bc664b3fe86d487ac7a77c53038a3 cd32f0b5004d9f5754c4f7f2d1f35cf3 f7116351c92b9cf9bb6d091ddfc8b32d 432348a2c413")))
		})
	})

	It("seals and opens", func() {
		connectionID := protocol.ConnectionID{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef}
		clientSealer, clientOpener := NewInitialAEAD(connectionID, protocol.PerspectiveClient)
		serverSealer, serverOpener := NewInitialAEAD(connectionID, protocol.PerspectiveServer)

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
		clientSealer, _ := NewInitialAEAD(c1, protocol.PerspectiveClient)
		_, serverOpener := NewInitialAEAD(c2, protocol.PerspectiveServer)

		clientMessage := clientSealer.Seal(nil, []byte("foobar"), 42, []byte("aad"))
		_, err := serverOpener.Open(nil, clientMessage, 42, []byte("aad"))
		Expect(err).To(MatchError(ErrDecryptionFailed))
	})

	It("encrypts und decrypts the header", func() {
		connID := protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad}
		clientSealer, clientOpener := NewInitialAEAD(connID, protocol.PerspectiveClient)
		serverSealer, serverOpener := NewInitialAEAD(connID, protocol.PerspectiveServer)

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
