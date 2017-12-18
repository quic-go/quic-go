package quic

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stream", func() {
	var str *cryptoStream

	str = newCryptoStream(func() {}, nil, protocol.VersionWhatever).(*cryptoStream)

	It("sets the read offset", func() {
		str.setReadOffset(0x42)
		Expect(str.receiveStream.readOffset).To(Equal(protocol.ByteCount(0x42)))
		Expect(str.receiveStream.frameQueue.readPosition).To(Equal(protocol.ByteCount(0x42)))
	})

	It("says if it has data for writing", func() {
		Expect(str.hasDataForWriting()).To(BeFalse())
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			_, err := str.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())
			close(done)
		}()
		Eventually(str.hasDataForWriting).Should(BeTrue())
	})
})
