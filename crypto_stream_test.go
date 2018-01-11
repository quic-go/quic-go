package quic

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Crypto Stream", func() {
	var (
		str        *cryptoStream
		mockSender *MockStreamSender
	)

	BeforeEach(func() {
		mockSender = NewMockStreamSender(mockCtrl)
		str = newCryptoStream(mockSender, nil, protocol.VersionWhatever).(*cryptoStream)
	})

	It("sets the read offset", func() {
		str.setReadOffset(0x42)
		Expect(str.receiveStream.readOffset).To(Equal(protocol.ByteCount(0x42)))
		Expect(str.receiveStream.frameQueue.readPosition).To(Equal(protocol.ByteCount(0x42)))
	})
})
