package handshake

import (
	"fmt"
	"math/rand"

	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Initial AEAD using AES-GCM", func() {
	It("converts the string representation used in the draft into byte slices", func() {
		Expect(splitHexString("0xdeadbeef")).To(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
		Expect(splitHexString("deadbeef")).To(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
		Expect(splitHexString("dead beef")).To(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
	})

	connID := protocol.ConnectionID(splitHexString("0x8394c8f03e515708"))

	DescribeTable("computes the client key and IV",
		func(v protocol.VersionNumber, expectedClientSecret, expectedKey, expectedIV []byte) {
			clientSecret, _ := computeSecrets(connID, v)
			Expect(clientSecret).To(Equal(expectedClientSecret))
			key, iv := computeInitialKeyAndIV(clientSecret, v)
			Expect(key).To(Equal(expectedKey))
			Expect(iv).To(Equal(expectedIV))
		},
		Entry("draft-29",
			protocol.VersionDraft29,
			splitHexString("0088119288f1d866733ceeed15ff9d50 902cf82952eee27e9d4d4918ea371d87"),
			splitHexString("175257a31eb09dea9366d8bb79ad80ba"),
			splitHexString("6b26114b9cba2b63a9e8dd4f"),
		),
		Entry("QUIC v1",
			protocol.Version1,
			splitHexString("c00cf151ca5be075ed0ebfb5c80323c4 2d6b7db67881289af4008f1f6c357aea"),
			splitHexString("1f369613dd76d5467730efcbe3b1a22d"),
			splitHexString("fa044b2f42a3fd3b46fb255c"),
		),
		Entry("QUIC v2",
			protocol.Version2,
			splitHexString("9fe72e1452e91f551b770005054034e4 7575d4a0fb4c27b7c6cb303a338423ae"),
			splitHexString("95df2be2e8d549c82e996fc9339f4563"),
			splitHexString("ea5e3c95f933db14b7020ad8"),
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
		Entry("draft 29",
			protocol.VersionDraft29,
			splitHexString("006f881359244dd9ad1acf85f595bad6 7c13f9f5586f5e64e1acae1d9ea8f616"),
			splitHexString("149d0b1662ab871fbe63c49b5e655a5d"),
			splitHexString("bab2b12a4c76016ace47856d"),
		),
		Entry("QUIC v1",
			protocol.Version1,
			splitHexString("3c199828fd139efd216c155ad844cc81 fb82fa8d7446fa7d78be803acdda951b"),
			splitHexString("cf3a5331653c364c88f0f379b6067e37"),
			splitHexString("0ac1493ca1905853b0bba03e"),
		),
		Entry("QUIC v2",
			protocol.Version2,
			splitHexString("3c9bf6a9c1c8c71819876967bd8b979e fd98ec665edf27f22c06e9845ba0ae2f"),
			splitHexString("15d5b4d9a2b8916aa39b1bfe574d2aad"),
			splitHexString("a85e7ac31cd275cbb095c626"),
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
		Entry("draft 29",
			protocol.VersionDraft29,
			splitHexString("c3ff00001d088394c8f03e5157080000449e00000002"),
			splitHexString("060040c4010000c003036660261ff947 cea49cce6cfad687f457cf1b14531ba1 4131a0e8f309a1d0b9c4000006130113 031302010000910000000b0009000006 736572766572ff01000100000a001400 12001d00170018001901000101010201 03010400230000003300260024001d00 204cfdfcd178b784bf328cae793b136f 2aedce005ff183d7bb14952072366470 37002b0003020304000d0020001e0403 05030603020308040805080604010501 060102010402050206020202002d0002 0101001c00024001"),
			splitHexString("fb66bc5f93032b7ddd89fe0ff15d9c4f"),
			byte(0xc5),
			splitHexString("4a95245b"),
			splitHexString("c5ff00001d088394c8f03e5157080000 449e4a95245bfb66bc5f93032b7ddd89 fe0ff15d9c4f7050fccdb71c1cd80512 d4431643a53aafa1b0b518b44968b18b 8d3e7a4d04c30b3ed9410325b2abb2da fb1c12f8b70479eb8df98abcaf95dd8f 3d1c78660fbc719f88b23c8aef6771f3 d50e10fdfb4c9d92386d44481b6c52d5 9e5538d3d3942de9f13a7f8b702dc317 24180da9df22714d01003fc5e3d165c9 50e630b8540fbd81c9df0ee63f949970 26c4f2e1887a2def79050ac2d86ba318 e0b3adc4c5aa18bcf63c7cf8e85f5692 49813a2236a7e72269447cd1c755e451 f5e77470eb3de64c8849d29282069802 9cfa18e5d66176fe6e5ba4ed18026f90 900a5b4980e2f58e39151d5cd685b109 29636d4f02e7fad2a5a458249f5c0298 a6d53acbe41a7fc83fa7cc01973f7a74 d1237a51974e097636b6203997f921d0 7bc1940a6f2d0de9f5a11432946159ed 6cc21df65c4ddd1115f86427259a196c 7148b25b6478b0dc7766e1c4d1b1f515 9f90eabc61636226244642ee148b464c 9e619ee50a5e3ddc836227cad938987c 4ea3c1fa7c75bbf88d89e9ada642b2b8 8fe8107b7ea375b1b64889a4e9e5c38a 1c896ce275a5658d250e2d76e1ed3a34 ce7e3a3f383d0c996d0bed106c2899ca 6fc263ef0455e74bb6ac1640ea7bfedc 59f03fee0e1725ea150ff4d69a7660c5 542119c71de270ae7c3ecfd1af2c4ce5 51986949cc34a66b3e216bfe18b347e6 c05fd050f85912db303a8f054ec23e38 f44d1c725ab641ae929fecc8e3cefa56 19df4231f5b4c009fa0c0bbc60bc75f7 6d06ef154fc8577077d9d6a1d2bd9bf0 81dc783ece60111bea7da9e5a9748069 d078b2bef48de04cabe3755b197d52b3 2046949ecaa310274b4aac0d008b1948 c1082cdfe2083e386d4fd84c0ed0666d 3ee26c4515c4fee73433ac703b690a9f 7bf278a77486ace44c489a0c7ac8dfe4 d1a58fb3a730b993ff0f0d61b4d89557 831eb4c752ffd39c10f6b9f46d8db278 da624fd800e4af85548a294c1518893a 8778c4f6d6d73c93df200960104e062b 388ea97dcf4016bced7f62b4f062cb6c 04c20693d9a0e3b74ba8fe74cc012378 84f40d765ae56a51688d985cf0ceaef4 3045ed8c3f0c33bced08537f6882613a cd3b08d665fce9dd8aa73171e2d3771a 61dba2790e491d413d93d987e2745af2 9418e428be34941485c93447520ffe23 1da2304d6a0fd5d07d08372202369661 59bef3cf904d722324dd852513df39ae 030d8173908da6364786d3c1bfcb19ea 77a63b25f1e7fc661def480c5d00d444 56269ebd84efd8e3a8b2c257eec76060 682848cbf5194bc99e49ee75e4d0d254 bad4bfd74970c30e44b65511d4ad0e6e c7398e08e01307eeeea14e46ccd87cf3 6b285221254d8fc6a6765c524ded0085 dca5bd688ddf722e2c0faf9d0fb2ce7a 0c3f2cee19ca0ffba461ca8dc5d2c817 8b0762cf67135558494d2a96f1a139f0 edb42d2af89a9c9122b07acbc29e5e72 2df8615c343702491098478a389c9872 a10b0c9875125e257c7bfdf27eef4060 bd3d00f4c14fd3e3496c38d3c5d1a566 8c39350effbc2d16ca17be4ce29f02ed 969504dda2a8c6b9ff919e693ee79e09 089316e7d1d89ec099db3b2b268725d8 88536a4b8bf9aee8fb43e82a4d919d48 43b1ca70a2d8d3f725ead1391377dcc0"),
		),
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
			splitHexString("d3709a50c4088394c8f03e5157080000449e00000002"),
			splitHexString("060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868 04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578 616d706c652e636f6dff01000100000a 00080006001d00170018001000070005 04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400 0d0010000e0403050306030203080408 050806002d00020101001c0002400100 3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000 75300901100f088394c8f03e51570806 048000ffff"),
			splitHexString("23b8e610589c83c92d0e97eb7a6e5003"),
			byte(0xdd),
			splitHexString("4391d848"),
			splitHexString("dd709a50c4088394c8f03e5157080000 449e4391d84823b8e610589c83c92d0e 97eb7a6e5003f57764c5c7f0095ba54b 90818f1bfeecc1c97c54fc731edbd2a2 44e3b1e639a9bc75ed545b98649343b2 53615ec6b3e4df0fd2e7fe9d691a09e6 a144b436d8a2c088a404262340dfd995 ec3865694e3026ecd8c6d2561a5a3667 2a1005018168c0f081c10e2bf14d550c 977e28bb9a759c57d0f7ffb1cdfb40bd 774dec589657542047dffefa56fc8089 a4d1ef379c81ba3df71a05ddc7928340 775910feb3ce4cbcfd8d253edd05f161 458f9dc44bea017c3117cca7065a315d eda9464e672ec80c3f79ac993437b441 ef74227ecc4dc9d597f66ab0ab8d214b 55840c70349d7616cbe38e5e1d052d07 f1fedb3dd3c4d8ce295724945e67ed2e efcd9fb52472387f318e3d9d233be7df c79d6bf6080dcbbb41feb180d7858849 7c3e439d38c334748d2b56fd19ab364d 057a9bd5a699ae145d7fdbc8f5777518 1b0a97c3bdedc91a555d6c9b8634e106 d8c9ca45a9d5450a7679edc545da9102 5bc93a7cf9a023a066ffadb9717ffaf3 414c3b646b5738b3cc4116502d18d79d 8227436306d9b2b3afc6c785ce3c817f eb703a42b9c83b59f0dcef1245d0b3e4 0299821ec19549ce489714fe2611e72c d882f4f70dce7d3671296fc045af5c9f 630d7b49a3eb821bbca60f1984dce664 91713bfe06001a56f51bb3abe92f7960 547c4d0a70f4a962b3f05dc25a34bbe8 30a7ea4736d3b0161723500d82beda9b e3327af2aa413821ff678b2a876ec4b0 0bb605ffcc3917ffdc279f187daa2fce 8cde121980bba8ec8f44ca562b0f1319 14c901cfbd847408b778e6738c7bb5b1 b3f97d01b0a24dcca40e3bed29411b1b a8f60843c4a241021b23132b9500509b 9a3516d4a9dd41d3bacbcd426b451393 521828afedcf20fa46ac24f44a8e2973 30b16705d5d5f798eff9e9134a065979 87a1db4617caa2d93837730829d4d89e 16413be4d8a8a38a7e6226623b64a820 178ec3a66954e10710e043ae73dd3fb2 715a0525a46343fb7590e5eac7ee55fc 810e0d8b4b8f7be82cd5a214575a1b99 629d47a9b281b61348c8627cab38e2a6 4db6626e97bb8f77bdcb0fee476aedd7 ba8f5441acaab00f4432edab3791047d 9091b2a753f035648431f6d12f7d6a68 1e64c861f4ac911a0f7d6ec0491a78c9 f192f96b3a5e7560a3f056bc1ca85983 67ad6acb6f2e034c7f37beeb9ed470c4 304af0107f0eb919be36a86f68f37fa6 1dae7aff14decd67ec3157a11488a14f ed0142828348f5f608b0fe03e1f3c0af 3acca0ce36852ed42e220ae9abf8f890 6f00f1b86bff8504c8f16c784fd52d25 e013ff4fda903e9e1eb453c1464b1196 6db9b28e8f26a3fc419e6a60a48d4c72 14ee9c6c6a12b68a32cac8f61580c64f 29cb6922408783c6d12e725b014fe485 cd17e484c5952bf99bc94941d4b1919d 04317b8aa1bd3754ecbaa10ec227de85 40695bf2fb8ee56f6dc526ef366625b9 1aa4970b6ffa5c8284b9b5ab852b905f 9d83f5669c0535bc377bcc05ad5e48e2 81ec0e1917ca3c6a471f8da0894bc82a c2a8965405d6eef3b5e293a88fda203f 09bdc72757b107ab14880eaa3ef7045b 580f4821ce6dd325b5a90655d8c5b55f 76fb846279a9b518c5e9b9a21165c509 3ed49baaacadf1f21873266c767f6769"),
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
		Entry("draft 29",
			protocol.VersionDraft29,
			splitHexString("c1ff00001d0008f067a5502a4262b50040740001"),
			splitHexString("0d0000000018410a020000560303eefc e7f7b37ba1d1632e96677825ddf73988 cfc79825df566dc5430b9a045a120013 0100002e00330024001d00209d3c940d 89690b84d08a60993c144eca684d1081 287c834d5311bcf32bb9da1a002b0002 0304"),
			splitHexString("823a5d3a1207c86ee49132824f046524"),
			splitHexString("caff00001d0008f067a5502a4262b5004074aaf2"),
			splitHexString("caff00001d0008f067a5502a4262b500 4074aaf2f007823a5d3a1207c86ee491 32824f0465243d082d868b107a38092b c80528664cbf9456ebf27673fb5fa506 1ab573c9f001b81da028a00d52ab00b1 5bebaa70640e106cf2acd043e9c6b441 1c0a79637134d8993701fe779e58c2fe 753d14b0564021565ea92e57bc6faf56 dfc7a40870e6"),
		),
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
			splitHexString("d1709a50c40008f067a5502a4262b50040750001"),
			splitHexString("02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739 88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94 0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00 020304"),
			splitHexString("ebb7972fdce59d50e7e49ff2a7e8de76"),
			splitHexString("d0709a50c40008f067a5502a4262b5004075103e"),
			splitHexString("d0709a50c40008f067a5502a4262b500 4075103e63b4ebb7972fdce59d50e7e4 9ff2a7e8de76b0cd8c10100a1f13d549 dd6fe801588fb14d279bef8d7c53ef62 66a9a7a1a5f2fa026c236a5bf8df5aa0 f9d74773aeccfffe910b0f76814b5e33 f7b7f8ec278d23fd8c7a9e66856b8bbe 72558135bca27c54d63fcc902253461c fc089d4e6b9b19"),
		),
	)

	for _, ver := range []protocol.VersionNumber{protocol.VersionDraft29, protocol.Version1, protocol.Version2} {
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
