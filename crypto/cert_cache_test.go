package crypto

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Certificate cache", func() {
	BeforeEach(func() {
		compressedCertsCache = map[uint64][]byte{}
	})

	It("gives a compressed cert", func() {
		chain := [][]byte{{0xde, 0xca, 0xfb, 0xad}}
		expected, err := compressChain(chain, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		compressed, err := getCompressedCert(chain, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(compressed).To(Equal(expected))
	})

	It("gets the same result multiple times", func() {
		chain := [][]byte{{0xde, 0xca, 0xfb, 0xad}}
		compressed, err := getCompressedCert(chain, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		compressed2, err := getCompressedCert(chain, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(compressed).To(Equal(compressed2))
	})

	It("stores cached values", func() {
		Expect(compressedCertsCache).To(HaveLen(0))
		chain := [][]byte{{0xde, 0xca, 0xfb, 0xad}}
		compressed, err := getCompressedCert(chain, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(compressedCertsCache).To(HaveLen(1))
		Expect(compressedCertsCache[3838929964809501833]).To(Equal(compressed))
	})
})
