package http3

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/quicvarint"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Settings", func() {
	Context("SETTINGS frames", func() {
		It("writes", func() {
			settings := Settings{
				1:  2,
				99: 999,
				13: 37,
			}
			buf := &bytes.Buffer{}
			settings.writeFrame(buf)
			parsed, err := readSettings(&FrameReader{R: buf})
			Expect(err).ToNot(HaveOccurred())
			Expect(parsed).To(Equal(settings))
		})

		It("rejects duplicate settings", func() {
			payload := &bytes.Buffer{}
			quicvarint.Write(payload, 13)
			quicvarint.Write(payload, 37)
			quicvarint.Write(payload, 13)
			quicvarint.Write(payload, 38)
			buf := &bytes.Buffer{}
			quicvarint.Write(buf, uint64(FrameTypeSettings))
			quicvarint.Write(buf, uint64(payload.Len()))
			buf.Write(payload.Bytes())
			_, err := readSettings(&FrameReader{R: buf})
			Expect(err).To(MatchError("duplicate setting: 13"))
		})

		Context("H3_DATAGRAM", func() {
			It("rejects invalid values for the H3_DATAGRAM entry", func() {
				settings := Settings{
					SettingDatagram: 1337,
				}
				buf := &bytes.Buffer{}
				settings.writeFrame(buf)
				_, err := readSettings(&FrameReader{R: buf})
				Expect(err).To(MatchError("invalid value for H3_DATAGRAM: 1337"))
			})

			It("rejects invalid values for the H3_DATAGRAM (draft 00) entry", func() {
				settings := Settings{
					SettingDatagramDraft00: 1337,
				}
				buf := &bytes.Buffer{}
				settings.writeFrame(buf)
				_, err := readSettings(&FrameReader{R: buf})
				Expect(err).To(MatchError("invalid value for H3_DATAGRAM (draft 00): 1337"))
			})

			It("writes the H3_DATAGRAM setting", func() {
				settings := Settings{SettingDatagram: 1}
				buf := &bytes.Buffer{}
				settings.writeFrame(buf)
				parsed, err := readSettings(&FrameReader{R: buf})
				Expect(err).ToNot(HaveOccurred())
				Expect(parsed).To(Equal(settings))
			})
		})
	})
})
