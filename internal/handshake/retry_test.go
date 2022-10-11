package handshake

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"

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

	It("uses the test vector from the draft, for old draft versions", func() {
		connID := protocol.ParseConnectionID(splitHexString("0x8394c8f03e515708"))
		data := splitHexString("ffff00001d0008f067a5502a4262b574 6f6b656ed16926d81f6f9ca2953a8aa4 575e1e49")
		Expect(GetRetryIntegrityTag(data[:len(data)-16], connID, protocol.VersionDraft29)[:]).To(Equal(data[len(data)-16:]))
	})

	It("uses the test vector from the draft, for version 1", func() {
		connID := protocol.ParseConnectionID(splitHexString("0x8394c8f03e515708"))
		data := splitHexString("ff000000010008f067a5502a4262b574 6f6b656e04a265ba2eff4d829058fb3f 0f2496ba")
		Expect(GetRetryIntegrityTag(data[:len(data)-16], connID, protocol.Version1)[:]).To(Equal(data[len(data)-16:]))
	})
})
