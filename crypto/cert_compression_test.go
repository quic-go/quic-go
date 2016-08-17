package crypto

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/binary"
	"hash/fnv"

	"github.com/lucas-clemente/quic-go-certificates"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func byteHash(d []byte) []byte {
	h := fnv.New64()
	h.Write(d)
	s := h.Sum64()
	res := make([]byte, 8)
	binary.LittleEndian.PutUint64(res, s)
	return res
}

var _ = Describe("Cert compression", func() {
	It("compresses empty", func() {
		compressed, err := compressChain(nil, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(compressed).To(Equal([]byte{0}))
	})

	It("gives correct single cert", func() {
		cert := []byte{0xde, 0xca, 0xfb, 0xad}
		certZlib := &bytes.Buffer{}
		z, err := zlib.NewWriterLevelDict(certZlib, flate.BestCompression, certDictZlib)
		Expect(err).ToNot(HaveOccurred())
		z.Write([]byte{0x04, 0x00, 0x00, 0x00})
		z.Write(cert)
		z.Close()
		chain := [][]byte{cert}
		compressed, err := compressChain(chain, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(compressed).To(Equal(append([]byte{
			0x01, 0x00,
			0x08, 0x00, 0x00, 0x00,
		}, certZlib.Bytes()...)))
	})

	It("gives correct cert and intermediate", func() {
		cert1 := []byte{0xde, 0xca, 0xfb, 0xad}
		cert2 := []byte{0xde, 0xad, 0xbe, 0xef}
		certZlib := &bytes.Buffer{}
		z, err := zlib.NewWriterLevelDict(certZlib, flate.BestCompression, certDictZlib)
		Expect(err).ToNot(HaveOccurred())
		z.Write([]byte{0x04, 0x00, 0x00, 0x00})
		z.Write(cert1)
		z.Write([]byte{0x04, 0x00, 0x00, 0x00})
		z.Write(cert2)
		z.Close()
		chain := [][]byte{cert1, cert2}
		compressed, err := compressChain(chain, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(compressed).To(Equal(append([]byte{
			0x01, 0x01, 0x00,
			0x10, 0x00, 0x00, 0x00,
		}, certZlib.Bytes()...)))
	})

	It("uses cached certificates", func() {
		cert := []byte{0xde, 0xca, 0xfb, 0xad}
		certHash := byteHash(cert)
		chain := [][]byte{cert}
		compressed, err := compressChain(chain, nil, certHash)
		Expect(err).ToNot(HaveOccurred())
		expected := append([]byte{0x02}, certHash...)
		expected = append(expected, 0x00)
		Expect(compressed).To(Equal(expected))
	})

	It("uses cached certificates and compressed combined", func() {
		cert1 := []byte{0xde, 0xca, 0xfb, 0xad}
		cert2 := []byte{0xde, 0xad, 0xbe, 0xef}
		cert2Hash := byteHash(cert2)
		certZlib := &bytes.Buffer{}
		z, err := zlib.NewWriterLevelDict(certZlib, flate.BestCompression, append(cert2, certDictZlib...))
		Expect(err).ToNot(HaveOccurred())
		z.Write([]byte{0x04, 0x00, 0x00, 0x00})
		z.Write(cert1)
		z.Close()
		chain := [][]byte{cert1, cert2}
		compressed, err := compressChain(chain, nil, cert2Hash)
		Expect(err).ToNot(HaveOccurred())
		expected := []byte{0x01, 0x02}
		expected = append(expected, cert2Hash...)
		expected = append(expected, 0x00)
		expected = append(expected, []byte{0x08, 0, 0, 0}...)
		expected = append(expected, certZlib.Bytes()...)
		Expect(compressed).To(Equal(expected))
	})

	It("uses common certificate sets", func() {
		cert := certsets.CertSet3[42]
		setHash := make([]byte, 8)
		binary.LittleEndian.PutUint64(setHash, certsets.CertSet3Hash)
		chain := [][]byte{cert}
		compressed, err := compressChain(chain, setHash, nil)
		Expect(err).ToNot(HaveOccurred())
		expected := []byte{0x03}
		expected = append(expected, setHash...)
		expected = append(expected, []byte{42, 0, 0, 0}...)
		expected = append(expected, 0x00)
		Expect(compressed).To(Equal(expected))
	})

	It("ignores uncommon certificate sets", func() {
		cert := []byte{0xde, 0xca, 0xfb, 0xad}
		setHash := make([]byte, 8)
		binary.LittleEndian.PutUint64(setHash, 0xdeadbeef)
		chain := [][]byte{cert}
		compressed, err := compressChain(chain, setHash, nil)
		Expect(err).ToNot(HaveOccurred())
		certZlib := &bytes.Buffer{}
		z, err := zlib.NewWriterLevelDict(certZlib, flate.BestCompression, certDictZlib)
		Expect(err).ToNot(HaveOccurred())
		z.Write([]byte{0x04, 0x00, 0x00, 0x00})
		z.Write(cert)
		z.Close()
		Expect(compressed).To(Equal(append([]byte{
			0x01, 0x00,
			0x08, 0x00, 0x00, 0x00,
		}, certZlib.Bytes()...)))
	})

	It("uses common certificates and compressed combined", func() {
		cert1 := []byte{0xde, 0xca, 0xfb, 0xad}
		cert2 := certsets.CertSet3[42]
		setHash := make([]byte, 8)
		binary.LittleEndian.PutUint64(setHash, certsets.CertSet3Hash)
		certZlib := &bytes.Buffer{}
		z, err := zlib.NewWriterLevelDict(certZlib, flate.BestCompression, append(cert2, certDictZlib...))
		Expect(err).ToNot(HaveOccurred())
		z.Write([]byte{0x04, 0x00, 0x00, 0x00})
		z.Write(cert1)
		z.Close()
		chain := [][]byte{cert1, cert2}
		compressed, err := compressChain(chain, setHash, nil)
		Expect(err).ToNot(HaveOccurred())
		expected := []byte{0x01, 0x03}
		expected = append(expected, setHash...)
		expected = append(expected, []byte{42, 0, 0, 0}...)
		expected = append(expected, 0x00)
		expected = append(expected, []byte{0x08, 0, 0, 0}...)
		expected = append(expected, certZlib.Bytes()...)
		Expect(compressed).To(Equal(expected))
	})

	It("rejects invalid CCS / CCRT hashes", func() {
		cert := []byte{0xde, 0xca, 0xfb, 0xad}
		chain := [][]byte{cert}
		_, err := compressChain(chain, []byte("foo"), nil)
		Expect(err).To(MatchError("expected a multiple of 8 bytes for CCS / CCRT hashes"))
		_, err = compressChain(chain, nil, []byte("foo"))
		Expect(err).To(MatchError("expected a multiple of 8 bytes for CCS / CCRT hashes"))
	})
})
