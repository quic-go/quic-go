package handshake

import (
	"crypto/rand"
	"fmt"

	"github.com/quic-go/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Initial AEAD using AES-GCM", func() {
	It("converts the string representation used in the draft into byte slices", func() {
		Expect(splitHexString("0xdeadbeef")).To(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
		Expect(splitHexString("deadbeef")).To(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
		Expect(splitHexString("dead beef")).To(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
	})

	connID := protocol.ParseConnectionID(splitHexString("0x8394c8f03e515708"))

	DescribeTable("computes the client key and IV",
		func(v protocol.VersionNumber, expectedClientSecret, expectedKey, expectedIV []byte) {
			clientSecret, _ := computeSecrets(connID, v)
			Expect(clientSecret).To(Equal(expectedClientSecret))
			key, iv := computeInitialKeyAndIV(clientSecret, v)
			Expect(key).To(Equal(expectedKey))
			Expect(iv).To(Equal(expectedIV))
		},
		Entry("QUIC v1",
			protocol.Version1,
			splitHexString("c00cf151ca5be075ed0ebfb5c80323c4 2d6b7db67881289af4008f1f6c357aea"),
			splitHexString("1f369613dd76d5467730efcbe3b1a22d"),
			splitHexString("fa044b2f42a3fd3b46fb255c"),
		),
		Entry("QUIC v2",
			protocol.Version2,
			splitHexString("14ec9d6eb9fd7af83bf5a668bc17a7e2 83766aade7ecd0891f70f9ff7f4bf47b"),
			splitHexString("8b1a0bc121284290a29e0971b5cd045d"),
			splitHexString("91f73e2351d8fa91660e909f"),
		),
	)

	DescribeTable("computes the server key and IV",
		func(v protocol.VersionNumber, expectedServerSecret, expectedKey, expectedIV []byte) {
			_, serverSecret := computeSecrets(connID, v)
			Expect(serverSecret).To(Equal(expectedServerSecret))
			key, iv := computeInitialKeyAndIV(serverSecret, v)
			Expect(key).To(Equal(expectedKey))
			Expect(iv).To(Equal(expectedIV))
		},
		Entry("QUIC v1",
			protocol.Version1,
			splitHexString("3c199828fd139efd216c155ad844cc81 fb82fa8d7446fa7d78be803acdda951b"),
			splitHexString("cf3a5331653c364c88f0f379b6067e37"),
			splitHexString("0ac1493ca1905853b0bba03e"),
		),
		Entry("QUIC v2",
			protocol.Version2,
			splitHexString("0263db1782731bf4588e7e4d93b74639 07cb8cd8200b5da55a8bd488eafc37c1"),
			splitHexString("82db637861d55e1d011f19ea71d5d2a7"),
			splitHexString("dd13c276499c0249d3310652"),
		),
	)

	DescribeTable("encrypts the client's Initial",
		func(v protocol.VersionNumber, header, data, expectedSample []byte, expectedHdrFirstByte byte, expectedHdr, expectedPacket []byte) {
			sealer, _ := NewInitialAEAD(connID, protocol.PerspectiveClient, v)
			data = append(data, make([]byte, 1162-len(data))...) // add PADDING
			sealed := sealer.Seal(nil, data, 2, header)
			sample := sealed[0:16]
			Expect(sample).To(Equal(expectedSample))
			sealer.EncryptHeader(sample, &header[0], header[len(header)-4:])
			Expect(header[0]).To(Equal(expectedHdrFirstByte))
			Expect(header[len(header)-4:]).To(Equal(expectedHdr))
			packet := append(header, sealed...)
			Expect(packet).To(Equal(expectedPacket))
		},
		Entry("QUIC v1",
			protocol.Version1,
			splitHexString("c300000001088394c8f03e5157080000449e00000002"),
			splitHexString("060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868 04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578 616d706c652e636f6dff01000100000a 00080006001d00170018001000070005 04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400 0d0010000e0403050306030203080408 050806002d00020101001c0002400100 3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000 75300901100f088394c8f03e51570806 048000ffff"),
			splitHexString("d1b1c98dd7689fb8ec11d242b123dc9b"),
			byte(0xc0),
			splitHexString("7b9aec34"),
			splitHexString("c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11 d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399 1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c 8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212 30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5 457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208 4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec 4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3 485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db 059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c 7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8 9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556 be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74 68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00 f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632 291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964 25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd 14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198 e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73 203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047 90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2 162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4 40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0 6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e 8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0 be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400 54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab 760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9 f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4 056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064 7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241 e221af44860018ab0856972e194cd934"),
		),
		Entry("QUIC v2",
			protocol.Version2,
			splitHexString("d36b3343cf088394c8f03e5157080000449e00000002"),
			splitHexString("060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868 04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578 616d706c652e636f6dff01000100000a 00080006001d00170018001000070005 04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400 0d0010000e0403050306030203080408 050806002d00020101001c0002400100 3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000 75300901100f088394c8f03e51570806 048000ffff"),
			splitHexString("ffe67b6abcdb4298b485dd04de806071"),
			byte(0xd7),
			splitHexString("a0c95e82"),
			splitHexString("d76b3343cf088394c8f03e5157080000 449ea0c95e82ffe67b6abcdb4298b485 dd04de806071bf03dceebfa162e75d6c 96058bdbfb127cdfcbf903388e99ad04 9f9a3dd4425ae4d0992cfff18ecf0fdb 5a842d09747052f17ac2053d21f57c5d 250f2c4f0e0202b70785b7946e992e58 a59ac52dea6774d4f03b55545243cf1a 12834e3f249a78d395e0d18f4d766004 f1a2674802a747eaa901c3f10cda5500 cb9122faa9f1df66c392079a1b40f0de 1c6054196a11cbea40afb6ef5253cd68 18f6625efce3b6def6ba7e4b37a40f77 32e093daa7d52190935b8da58976ff33 12ae50b187c1433c0f028edcc4c2838b 6a9bfc226ca4b4530e7a4ccee1bfa2a3 d396ae5a3fb512384b2fdd851f784a65 e03f2c4fbe11a53c7777c023462239dd 6f7521a3f6c7d5dd3ec9b3f233773d4b 46d23cc375eb198c63301c21801f6520 bcfb7966fc49b393f0061d974a2706df 8c4a9449f11d7f3d2dcbb90c6b877045 636e7c0c0fe4eb0f697545460c806910 d2c355f1d253bc9d2452aaa549e27a1f ac7cf4ed77f322e8fa894b6a83810a34 b361901751a6f5eb65a0326e07de7c12 16ccce2d0193f958bb3850a833f7ae43 2b65bc5a53975c155aa4bcb4f7b2c4e5 4df16efaf6ddea94e2c50b4cd1dfe060 17e0e9d02900cffe1935e0491d77ffb4 fdf85290fdd893d577b1131a610ef6a5 c32b2ee0293617a37cbb08b847741c3b 8017c25ca9052ca1079d8b78aebd4787 6d330a30f6a8c6d61dd1ab5589329de7 14d19d61370f8149748c72f132f0fc99 f34d766c6938597040d8f9e2bb522ff9 9c63a344d6a2ae8aa8e51b7b90a4a806 105fcbca31506c446151adfeceb51b91 abfe43960977c87471cf9ad4074d30e1 0d6a7f03c63bd5d4317f68ff325ba3bd 80bf4dc8b52a0ba031758022eb025cdd 770b44d6d6cf0670f4e990b22347a7db 848265e3e5eb72dfe8299ad7481a4083 22cac55786e52f633b2fb6b614eaed18 d703dd84045a274ae8bfa73379661388 d6991fe39b0d93debb41700b41f90a15 c4d526250235ddcd6776fc77bc97e7a4 17ebcb31600d01e57f32162a8560cacc 7e27a096d37a1a86952ec71bd89a3e9a 30a2a26162984d7740f81193e8238e61 f6b5b984d4d3dfa033c1bb7e4f0037fe bf406d91c0dccf32acf423cfa1e70710 10d3f270121b493ce85054ef58bada42 310138fe081adb04e2bd901f2f13458b 3d6758158197107c14ebb193230cd115 7380aa79cae1374a7c1e5bbcb80ee23e 06ebfde206bfb0fcbc0edc4ebec30966 1bdd908d532eb0c6adc38b7ca7331dce 8dfce39ab71e7c32d318d136b6100671 a1ae6a6600e3899f31f0eed19e3417d1 34b90c9058f8632c798d4490da498730 7cba922d61c39805d072b589bd52fdf1 e86215c2d54e6670e07383a27bbffb5a ddf47d66aa85a0c6f9f32e59d85a44dd 5d3b22dc2be80919b490437ae4f36a0a e55edf1d0b5cb4e9a3ecabee93dfc6e3 8d209d0fa6536d27a5d6fbb17641cde2 7525d61093f1b28072d111b2b4ae5f89 d5974ee12e5cf7d5da4d6a31123041f3 3e61407e76cffcdcfd7e19ba58cf4b53 6f4c4938ae79324dc402894b44faf8af bab35282ab659d13c93f70412e85cb19 9a37ddec600545473cfb5a05e08d0b20 9973b2172b4d21fb69745a262ccde96b a18b2faa745b6fe189cf772a9f84cbfc"),
		),
	)

	DescribeTable("encrypts the server's Initial",
		func(v protocol.VersionNumber, header, data, expectedSample, expectedHdr, expectedPacket []byte) {
			sealer, _ := NewInitialAEAD(connID, protocol.PerspectiveServer, v)
			sealed := sealer.Seal(nil, data, 1, header)
			sample := sealed[2 : 2+16]
			Expect(sample).To(Equal(expectedSample))
			sealer.EncryptHeader(sample, &header[0], header[len(header)-2:])
			Expect(header).To(Equal(expectedHdr))
			packet := append(header, sealed...)
			Expect(packet).To(Equal(expectedPacket))
		},
		Entry("QUIC v1",
			protocol.Version1,
			splitHexString("c1000000010008f067a5502a4262b50040750001"),
			splitHexString("02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739 88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94 0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00 020304"),
			splitHexString("2cd0991cd25b0aac406a5816b6394100"),
			splitHexString("cf000000010008f067a5502a4262b5004075c0d9"),
			splitHexString("cf000000010008f067a5502a4262b500 4075c0d95a482cd0991cd25b0aac406a 5816b6394100f37a1c69797554780bb3 8cc5a99f5ede4cf73c3ec2493a1839b3 dbcba3f6ea46c5b7684df3548e7ddeb9 c3bf9c73cc3f3bded74b562bfb19fb84 022f8ef4cdd93795d77d06edbb7aaf2f 58891850abbdca3d20398c276456cbc4 2158407dd074ee"),
		),
		Entry("QUIC v2",
			protocol.Version2,
			splitHexString("d16b3343cf0008f067a5502a4262b50040750001"),
			splitHexString("02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739 88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94 0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00 020304"),
			splitHexString("6f05d8a4398c47089698baeea26b91eb"),
			splitHexString("dc6b3343cf0008f067a5502a4262b5004075d92f"),
			splitHexString("dc6b3343cf0008f067a5502a4262b500 4075d92faaf16f05d8a4398c47089698 baeea26b91eb761d9b89237bbf872630 17915358230035f7fd3945d88965cf17 f9af6e16886c61bfc703106fbaf3cb4c fa52382dd16a393e42757507698075b2 c984c707f0a0812d8cd5a6881eaf21ce da98f4bd23f6fe1a3e2c43edd9ce7ca8 4bed8521e2e140"),
		),
	)

	for _, ver := range []protocol.VersionNumber{protocol.Version1, protocol.Version2} {
		v := ver

		Context(fmt.Sprintf("using version %s", v), func() {
			It("seals and opens", func() {
				connectionID := protocol.ParseConnectionID([]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef})
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
				c1 := protocol.ParseConnectionID([]byte{0, 0, 0, 0, 0, 0, 0, 1})
				c2 := protocol.ParseConnectionID([]byte{0, 0, 0, 0, 0, 0, 0, 2})
				clientSealer, _ := NewInitialAEAD(c1, protocol.PerspectiveClient, v)
				_, serverOpener := NewInitialAEAD(c2, protocol.PerspectiveServer, v)

				clientMessage := clientSealer.Seal(nil, []byte("foobar"), 42, []byte("aad"))
				_, err := serverOpener.Open(nil, clientMessage, 42, []byte("aad"))
				Expect(err).To(MatchError(ErrDecryptionFailed))
			})

			It("encrypts und decrypts the header", func() {
				connID := protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad})
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
