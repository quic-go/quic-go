package quic

import (
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CryptoStream", func() {
	Context("when parsing", func() {
		It("parses sample CHLO message", func() {
			tag, msg, err := ParseCryptoMessage(sampleCHLO)
			Expect(err).ToNot(HaveOccurred())
			Expect(tag).To(Equal(TagCHLO))
			Expect(msg).To(Equal(map[Tag][]byte{
				TagPAD:  []byte(strings.Repeat("-", 1016)),
				TagSNI:  []byte("www.example.org"),
				TagVER:  []byte("Q030"),
				TagCCS:  []byte("{&\xe9\xe7\xe4\\q\xff\x01\xe8\x81`\x92\x92\x1a\xe8"),
				TagMSPC: []byte("d\x00\x00\x00"),
				TagUAID: []byte("dev Chrome/51.0.2700.0 Intel Mac OS X 10_11_4"),
				TagTCID: []byte("\x00\x00\x00\x00"),
				TagSRBF: []byte("\x00\x00\x10\x00"),
				TagICSL: []byte("\x1e\x00\x00\x00"),
				TagNONP: []byte("\xe1\x84T\x1b\xe3\xd6|\x1fi\xb2N\x9eF\xf4Fݫ\xe5\xdef\x94\xf6\xb2\xee\x01ĥw\xfe\xc9\v\xa3"),
				TagSCLS: []byte("\x01\x00\x00\x00"),
				TagCSCT: []byte{},
				TagCOPT: []byte("FIXD"),
				TagSFCW: []byte("\x00\x00`\x00"),
				TagCFCW: []byte("\x00\x00\xf0\x00"),
				TagPDMD: []byte("X509"),
			}))
		})
	})
})
