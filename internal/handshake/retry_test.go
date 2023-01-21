package handshake

import (
	"encoding/binary"

	"github.com/quic-go/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Retry Integrity Check", func() {
	It("calculates retry integrity tags", func() {
		connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
		fooTag := GetRetryIntegrityTag([]byte("foo"), connID, protocol.VersionDraft29)
		barTag := GetRetryIntegrityTag([]byte("bar"), connID, protocol.VersionDraft29)
		Expect(fooTag).ToNot(BeNil())
		Expect(barTag).ToNot(BeNil())
		Expect(*fooTag).ToNot(Equal(*barTag))
	})

	It("includes the original connection ID in the tag calculation", func() {
		connID1 := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
		connID2 := protocol.ParseConnectionID([]byte{4, 3, 2, 1})
		t1 := GetRetryIntegrityTag([]byte("foobar"), connID1, protocol.Version1)
		t2 := GetRetryIntegrityTag([]byte("foobar"), connID2, protocol.Version1)
		Expect(*t1).ToNot(Equal(*t2))
	})

	DescribeTable("using the test vectors",
		func(version protocol.VersionNumber, data []byte) {
			v := binary.BigEndian.Uint32(data[1:5])
			Expect(protocol.VersionNumber(v)).To(Equal(version))
			connID := protocol.ParseConnectionID(splitHexString("0x8394c8f03e515708"))
			Expect(GetRetryIntegrityTag(data[:len(data)-16], connID, version)[:]).To(Equal(data[len(data)-16:]))
		},
		Entry("draft-29",
			protocol.VersionDraft29,
			splitHexString("ffff00001d0008f067a5502a4262b574 6f6b656ed16926d81f6f9ca2953a8aa4 575e1e49"),
		),
		Entry("v1",
			protocol.Version1,
			splitHexString("ff000000010008f067a5502a4262b574 6f6b656e04a265ba2eff4d829058fb3f 0f2496ba"),
		),
		Entry("v2",
			protocol.Version2,
			splitHexString("cf6b3343cf0008f067a5502a4262b574 6f6b656ec8646ce8bfe33952d9555436 65dcc7b6"),
		),
	)
})
