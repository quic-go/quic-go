package handshake

import (
	"fmt"
	"math/rand"

	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Initial AEAD using AES-GCM", func() {
	It("converts the string representation used in the draft into byte slices", func() {
		Expect(splitHexString("0xdeadbeef")).To(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
		Expect(splitHexString("deadbeef")).To(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
		Expect(splitHexString("dead beef")).To(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
	})

	// values taken from the Appendix of the draft
	Context("using the test vector from the QUIC draft, for old draft version", func() {
		const version = protocol.VersionDraft29
		var connID protocol.ConnectionID

		BeforeEach(func() {
			connID = protocol.ConnectionID(splitHexString("0x8394c8f03e515708"))
		})

		It("computes the client key and IV", func() {
			clientSecret, _ := computeSecrets(connID, version)
			Expect(clientSecret).To(Equal(splitHexString("0088119288f1d866733ceeed15ff9d50 902cf82952eee27e9d4d4918ea371d87")))
			key, iv := computeInitialKeyAndIV(clientSecret)
			Expect(key).To(Equal(splitHexString("175257a31eb09dea9366d8bb79ad80ba")))
			Expect(iv).To(Equal(splitHexString("6b26114b9cba2b63a9e8dd4f")))
		})

		It("computes the server key and IV", func() {
			_, serverSecret := computeSecrets(connID, version)
			Expect(serverSecret).To(Equal(splitHexString("006f881359244dd9ad1acf85f595bad6 7c13f9f5586f5e64e1acae1d9ea8f616")))
			key, iv := computeInitialKeyAndIV(serverSecret)
			Expect(key).To(Equal(splitHexString("149d0b1662ab871fbe63c49b5e655a5d")))
			Expect(iv).To(Equal(splitHexString("bab2b12a4c76016ace47856d")))
		})

		It("encrypts the client's Initial", func() {
			sealer, _ := NewInitialAEAD(connID, protocol.PerspectiveClient, version)
			header := splitHexString("c3ff00001d088394c8f03e5157080000449e00000002")
			data := splitHexString("060040c4010000c003036660261ff947 cea49cce6cfad687f457cf1b14531ba1 4131a0e8f309a1d0b9c4000006130113 031302010000910000000b0009000006 736572766572ff01000100000a001400 12001d00170018001901000101010201 03010400230000003300260024001d00 204cfdfcd178b784bf328cae793b136f 2aedce005ff183d7bb14952072366470 37002b0003020304000d0020001e0403 05030603020308040805080604010501 060102010402050206020202002d0002 0101001c00024001")
			data = append(data, make([]byte, 1162-len(data))...) // add PADDING
			sealed := sealer.Seal(nil, data, 2, header)
			sample := sealed[0:16]
			Expect(sample).To(Equal(splitHexString("fb66bc5f93032b7ddd89fe0ff15d9c4f")))
			sealer.EncryptHeader(sample, &header[0], header[len(header)-4:])
			Expect(header[0]).To(Equal(byte(0xc5)))
			Expect(header[len(header)-4:]).To(Equal(splitHexString("4a95245b")))
			packet := append(header, sealed...)
			Expect(packet).To(Equal(splitHexString("c5ff00001d088394c8f03e5157080000 449e4a95245bfb66bc5f93032b7ddd89 fe0ff15d9c4f7050fccdb71c1cd80512 d4431643a53aafa1b0b518b44968b18b 8d3e7a4d04c30b3ed9410325b2abb2da fb1c12f8b70479eb8df98abcaf95dd8f 3d1c78660fbc719f88b23c8aef6771f3 d50e10fdfb4c9d92386d44481b6c52d5 9e5538d3d3942de9f13a7f8b702dc317 24180da9df22714d01003fc5e3d165c9 50e630b8540fbd81c9df0ee63f949970 26c4f2e1887a2def79050ac2d86ba318 e0b3adc4c5aa18bcf63c7cf8e85f5692 49813a2236a7e72269447cd1c755e451 f5e77470eb3de64c8849d29282069802 9cfa18e5d66176fe6e5ba4ed18026f90 900a5b4980e2f58e39151d5cd685b109 29636d4f02e7fad2a5a458249f5c0298 a6d53acbe41a7fc83fa7cc01973f7a74 d1237a51974e097636b6203997f921d0 7bc1940a6f2d0de9f5a11432946159ed 6cc21df65c4ddd1115f86427259a196c 7148b25b6478b0dc7766e1c4d1b1f515 9f90eabc61636226244642ee148b464c 9e619ee50a5e3ddc836227cad938987c 4ea3c1fa7c75bbf88d89e9ada642b2b8 8fe8107b7ea375b1b64889a4e9e5c38a 1c896ce275a5658d250e2d76e1ed3a34 ce7e3a3f383d0c996d0bed106c2899ca 6fc263ef0455e74bb6ac1640ea7bfedc 59f03fee0e1725ea150ff4d69a7660c5 542119c71de270ae7c3ecfd1af2c4ce5 51986949cc34a66b3e216bfe18b347e6 c05fd050f85912db303a8f054ec23e38 f44d1c725ab641ae929fecc8e3cefa56 19df4231f5b4c009fa0c0bbc60bc75f7 6d06ef154fc8577077d9d6a1d2bd9bf0 81dc783ece60111bea7da9e5a9748069 d078b2bef48de04cabe3755b197d52b3 2046949ecaa310274b4aac0d008b1948 c1082cdfe2083e386d4fd84c0ed0666d 3ee26c4515c4fee73433ac703b690a9f 7bf278a77486ace44c489a0c7ac8dfe4 d1a58fb3a730b993ff0f0d61b4d89557 831eb4c752ffd39c10f6b9f46d8db278 da624fd800e4af85548a294c1518893a 8778c4f6d6d73c93df200960104e062b 388ea97dcf4016bced7f62b4f062cb6c 04c20693d9a0e3b74ba8fe74cc012378 84f40d765ae56a51688d985cf0ceaef4 3045ed8c3f0c33bced08537f6882613a cd3b08d665fce9dd8aa73171e2d3771a 61dba2790e491d413d93d987e2745af2 9418e428be34941485c93447520ffe23 1da2304d6a0fd5d07d08372202369661 59bef3cf904d722324dd852513df39ae 030d8173908da6364786d3c1bfcb19ea 77a63b25f1e7fc661def480c5d00d444 56269ebd84efd8e3a8b2c257eec76060 682848cbf5194bc99e49ee75e4d0d254 bad4bfd74970c30e44b65511d4ad0e6e c7398e08e01307eeeea14e46ccd87cf3 6b285221254d8fc6a6765c524ded0085 dca5bd688ddf722e2c0faf9d0fb2ce7a 0c3f2cee19ca0ffba461ca8dc5d2c817 8b0762cf67135558494d2a96f1a139f0 edb42d2af89a9c9122b07acbc29e5e72 2df8615c343702491098478a389c9872 a10b0c9875125e257c7bfdf27eef4060 bd3d00f4c14fd3e3496c38d3c5d1a566 8c39350effbc2d16ca17be4ce29f02ed 969504dda2a8c6b9ff919e693ee79e09 089316e7d1d89ec099db3b2b268725d8 88536a4b8bf9aee8fb43e82a4d919d48 43b1ca70a2d8d3f725ead1391377dcc0")))
		})

		It("encrypt the server's Initial", func() {
			sealer, _ := NewInitialAEAD(connID, protocol.PerspectiveServer, version)
			header := splitHexString("c1ff00001d0008f067a5502a4262b50040740001")
			data := splitHexString("0d0000000018410a020000560303eefc e7f7b37ba1d1632e96677825ddf73988 cfc79825df566dc5430b9a045a120013 0100002e00330024001d00209d3c940d 89690b84d08a60993c144eca684d1081 287c834d5311bcf32bb9da1a002b0002 0304")
			sealed := sealer.Seal(nil, data, 1, header)
			sample := sealed[2 : 2+16]
			Expect(sample).To(Equal(splitHexString("823a5d3a1207c86ee49132824f046524")))
			sealer.EncryptHeader(sample, &header[0], header[len(header)-2:])
			Expect(header).To(Equal(splitHexString("caff00001d0008f067a5502a4262b5004074aaf2")))
			packet := append(header, sealed...)
			Expect(packet).To(Equal(splitHexString("caff00001d0008f067a5502a4262b500 4074aaf2f007823a5d3a1207c86ee491 32824f0465243d082d868b107a38092b c80528664cbf9456ebf27673fb5fa506 1ab573c9f001b81da028a00d52ab00b1 5bebaa70640e106cf2acd043e9c6b441 1c0a79637134d8993701fe779e58c2fe 753d14b0564021565ea92e57bc6faf56 dfc7a40870e6")))
		})
	})

	// values taken from the Appendix of the draft
	Context("using the test vector from the QUIC draft, for QUIC v1", func() {
		const version = protocol.Version1
		var connID protocol.ConnectionID

		BeforeEach(func() {
			connID = protocol.ConnectionID(splitHexString("0x8394c8f03e515708"))
		})

		It("computes the client key and IV", func() {
			clientSecret, _ := computeSecrets(connID, version)
			Expect(clientSecret).To(Equal(splitHexString("c00cf151ca5be075ed0ebfb5c80323c4 2d6b7db67881289af4008f1f6c357aea")))
			key, iv := computeInitialKeyAndIV(clientSecret)
			Expect(key).To(Equal(splitHexString("1f369613dd76d5467730efcbe3b1a22d")))
			Expect(iv).To(Equal(splitHexString("fa044b2f42a3fd3b46fb255c")))
		})

		It("computes the server key and IV", func() {
			_, serverSecret := computeSecrets(connID, version)
			Expect(serverSecret).To(Equal(splitHexString("3c199828fd139efd216c155ad844cc81 fb82fa8d7446fa7d78be803acdda951b")))
			key, iv := computeInitialKeyAndIV(serverSecret)
			Expect(key).To(Equal(splitHexString("cf3a5331653c364c88f0f379b6067e37")))
			Expect(iv).To(Equal(splitHexString("0ac1493ca1905853b0bba03e")))
		})

		It("encrypts the client's Initial", func() {
			sealer, _ := NewInitialAEAD(connID, protocol.PerspectiveClient, version)
			header := splitHexString("c300000001088394c8f03e5157080000449e00000002")
			data := splitHexString("060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868 04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578 616d706c652e636f6dff01000100000a 00080006001d00170018001000070005 04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400 0d0010000e0403050306030203080408 050806002d00020101001c0002400100 3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000 75300901100f088394c8f03e51570806 048000ffff")
			data = append(data, make([]byte, 1162-len(data))...) // add PADDING
			sealed := sealer.Seal(nil, data, 2, header)
			sample := sealed[0:16]
			Expect(sample).To(Equal(splitHexString("d1b1c98dd7689fb8ec11d242b123dc9b")))
			sealer.EncryptHeader(sample, &header[0], header[len(header)-4:])
			Expect(header[0]).To(Equal(byte(0xc0)))
			Expect(header[len(header)-4:]).To(Equal(splitHexString("7b9aec34")))
			packet := append(header, sealed...)
			Expect(packet).To(Equal(splitHexString("c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11 d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399 1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c 8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212 30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5 457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208 4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec 4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3 485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db 059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c 7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8 9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556 be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74 68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00 f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632 291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964 25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd 14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198 e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73 203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047 90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2 162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4 40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0 6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e 8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0 be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400 54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab 760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9 f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4 056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064 7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241 e221af44860018ab0856972e194cd934")))
		})

		It("encrypt the server's Initial", func() {
			sealer, _ := NewInitialAEAD(connID, protocol.PerspectiveServer, version)
			header := splitHexString("c1000000010008f067a5502a4262b50040750001")
			data := splitHexString("02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739 88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94 0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00 020304")
			sealed := sealer.Seal(nil, data, 1, header)
			sample := sealed[2 : 2+16]
			Expect(sample).To(Equal(splitHexString("2cd0991cd25b0aac406a5816b6394100")))
			sealer.EncryptHeader(sample, &header[0], header[len(header)-2:])
			Expect(header).To(Equal(splitHexString("cf000000010008f067a5502a4262b5004075c0d9")))
			packet := append(header, sealed...)
			Expect(packet).To(Equal(splitHexString("cf000000010008f067a5502a4262b500 4075c0d95a482cd0991cd25b0aac406a 5816b6394100f37a1c69797554780bb3 8cc5a99f5ede4cf73c3ec2493a1839b3 dbcba3f6ea46c5b7684df3548e7ddeb9 c3bf9c73cc3f3bded74b562bfb19fb84 022f8ef4cdd93795d77d06edbb7aaf2f 58891850abbdca3d20398c276456cbc4 2158407dd074ee")))
		})
	})

	for _, ver := range []protocol.VersionNumber{protocol.VersionDraft29, protocol.Version1} {
		v := ver

		Context(fmt.Sprintf("using version %s", v), func() {
			It("seals and opens", func() {
				connectionID := protocol.ConnectionID{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef}
				clientSealer, clientOpener := NewInitialAEAD(connectionID, protocol.PerspectiveClient, v)
				serverSealer, serverOpener := NewInitialAEAD(connectionID, protocol.PerspectiveServer, v)

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
				clientSealer, _ := NewInitialAEAD(c1, protocol.PerspectiveClient, v)
				_, serverOpener := NewInitialAEAD(c2, protocol.PerspectiveServer, v)

				clientMessage := clientSealer.Seal(nil, []byte("foobar"), 42, []byte("aad"))
				_, err := serverOpener.Open(nil, clientMessage, 42, []byte("aad"))
				Expect(err).To(MatchError(ErrDecryptionFailed))
			})

			It("encrypts und decrypts the header", func() {
				connID := protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad}
				clientSealer, clientOpener := NewInitialAEAD(connID, protocol.PerspectiveClient, v)
				serverSealer, serverOpener := NewInitialAEAD(connID, protocol.PerspectiveServer, v)

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
	}
})
