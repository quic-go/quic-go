package quic

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stream", func() {
	var str *cryptoStream

	str = newCryptoStream(nil, nil, protocol.VersionWhatever).(*cryptoStream)

	It("sets the read offset", func() {
		str.SetReadOffset(0x42)
		Expect(str.readOffset).To(Equal(protocol.ByteCount(0x42)))
		Expect(str.frameQueue.readPosition).To(Equal(protocol.ByteCount(0x42)))
	})
})
