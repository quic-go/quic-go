package handshake

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Retry Integrity Check", func() {
	It("calculates retry integrity tags", func() {
		fooTag := GetRetryIntegrityTag([]byte("foo"), protocol.ConnectionID{1, 2, 3, 4})
		barTag := GetRetryIntegrityTag([]byte("bar"), protocol.ConnectionID{1, 2, 3, 4})
		Expect(fooTag).ToNot(BeNil())
		Expect(barTag).ToNot(BeNil())
		Expect(*fooTag).ToNot(Equal(*barTag))
	})

	It("includes the original connection ID in the tag calculation", func() {
		t1 := GetRetryIntegrityTag([]byte("foobar"), protocol.ConnectionID{1, 2, 3, 4})
		t2 := GetRetryIntegrityTag([]byte("foobar"), protocol.ConnectionID{4, 3, 2, 1})
		Expect(*t1).ToNot(Equal(*t2))
	})
})
