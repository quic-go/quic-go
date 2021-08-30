package http3

import (
	"bytes"
	"fmt"
	"io"

	"github.com/lucas-clemente/quic-go/quicvarint"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Frames", func() {
	appendVarInt := func(b []byte, val uint64) []byte {
		buf := &bytes.Buffer{}
		quicvarint.Write(buf, val)
		return append(b, buf.Bytes()...)
	}

	It("skips unknown frames", func() {
		data := appendVarInt(nil, 0xdeadbeef) // type byte
		data = appendVarInt(data, 0x42)
		data = append(data, make([]byte, 0x42)...)
		buf := bytes.NewBuffer(data)
		quicvarint.Write(buf, uint64(FrameTypeData))
		quicvarint.Write(buf, 0x1234)
		frame, err := parseNextFrame(buf)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(BeAssignableToTypeOf(&dataFrame{}))
		Expect(frame.(*dataFrame).len).To(Equal(uint64(0x1234)))
	})

	Context("DATA frames", func() {
		It("parses", func() {
			data := appendVarInt(nil, 0) // type byte
			data = appendVarInt(data, 0x1337)
			frame, err := parseNextFrame(bytes.NewReader(data))
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeAssignableToTypeOf(&dataFrame{}))
			Expect(frame.(*dataFrame).len).To(Equal(uint64(0x1337)))
		})

		It("writes", func() {
			buf := &bytes.Buffer{}
			quicvarint.Write(buf, uint64(FrameTypeData))
			quicvarint.Write(buf, 0xdeadbeef)
			frame, err := parseNextFrame(buf)
			Expect(err).ToNot(HaveOccurred())
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeAssignableToTypeOf(&dataFrame{}))
			Expect(frame.(*dataFrame).len).To(Equal(uint64(0xdeadbeef)))
		})
	})

	Context("HEADERS frames", func() {
		It("parses", func() {
			data := appendVarInt(nil, 1) // type byte
			data = appendVarInt(data, 0x1337)
			frame, err := parseNextFrame(bytes.NewReader(data))
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeAssignableToTypeOf(&headersFrame{}))
			Expect(frame.(*headersFrame).len).To(Equal(uint64(0x1337)))
		})

		It("writes", func() {
			buf := &bytes.Buffer{}
			(&headersFrame{len: 0xdeadbeef}).writeFrame(buf)
			frame, err := parseNextFrame(buf)
			Expect(err).ToNot(HaveOccurred())
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeAssignableToTypeOf(&headersFrame{}))
			Expect(frame.(*headersFrame).len).To(Equal(uint64(0xdeadbeef)))
		})
	})

	Context("SETTINGS frames", func() {
		It("parses", func() {
			settings := appendVarInt(nil, 13)
			settings = appendVarInt(settings, 37)
			settings = appendVarInt(settings, 0xdead)
			settings = appendVarInt(settings, 0xbeef)
			data := appendVarInt(nil, 4) // type byte
			data = appendVarInt(data, uint64(len(settings)))
			data = append(data, settings...)
			frame, err := parseNextFrame(bytes.NewReader(data))
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeAssignableToTypeOf(Settings{}))
			s := frame.(Settings)
			Expect(s).To(HaveKeyWithValue(SettingID(13), uint64(37)))
			Expect(s).To(HaveKeyWithValue(SettingID(0xdead), uint64(0xbeef)))
		})

		It("rejects duplicate settings", func() {
			settings := appendVarInt(nil, 13)
			settings = appendVarInt(settings, 37)
			settings = appendVarInt(settings, 13)
			settings = appendVarInt(settings, 38)
			data := appendVarInt(nil, 4) // type byte
			data = appendVarInt(data, uint64(len(settings)))
			data = append(data, settings...)
			_, err := parseNextFrame(bytes.NewReader(data))
			Expect(err).To(MatchError("duplicate setting: 13"))
		})

		It("writes", func() {
			settings := Settings{
				1:  2,
				99: 999,
				13: 37,
			}
			buf := &bytes.Buffer{}
			settings.writeFrame(buf)
			parsed, err := parseNextFrame(buf)
			Expect(err).ToNot(HaveOccurred())
			Expect(parsed).To(Equal(settings))
		})

		It("errors on EOF", func() {
			settings := Settings{
				13:         37,
				0xdeadbeef: 0xdecafbad,
			}
			buf := &bytes.Buffer{}
			settings.writeFrame(buf)

			data := buf.Bytes()
			_, err := parseNextFrame(bytes.NewReader(data))
			Expect(err).ToNot(HaveOccurred())

			for i := range data {
				b := make([]byte, i)
				copy(b, data[:i])
				_, err := parseNextFrame(bytes.NewReader(b))
				Expect(err).To(MatchError(io.EOF))
			}
		})

		Context("H3_DATAGRAM", func() {
			It("reads the H3_DATAGRAM value", func() {
				settings := appendVarInt(nil, uint64(SettingDatagram))
				settings = appendVarInt(settings, 1)
				data := appendVarInt(nil, 4) // type byte
				data = appendVarInt(data, uint64(len(settings)))
				data = append(data, settings...)
				f, err := parseNextFrame(bytes.NewReader(data))
				Expect(err).ToNot(HaveOccurred())
				Expect(f).To(BeAssignableToTypeOf(Settings{}))
				sf := f.(Settings)
				Expect(sf[SettingDatagram]).To(Equal(uint64(1)))
			})

			It("rejects duplicate H3_DATAGRAM entries", func() {
				settings := appendVarInt(nil, uint64(SettingDatagram))
				settings = appendVarInt(settings, 1)
				settings = appendVarInt(settings, uint64(SettingDatagram))
				settings = appendVarInt(settings, 1)
				data := appendVarInt(nil, 4) // type byte
				data = appendVarInt(data, uint64(len(settings)))
				data = append(data, settings...)
				_, err := parseNextFrame(bytes.NewReader(data))
				Expect(err).To(MatchError(fmt.Sprintf("duplicate setting: %d", SettingDatagram)))
			})

			It("rejects invalid values for the H3_DATAGRAM entry", func() {
				settings := appendVarInt(nil, uint64(SettingDatagram))
				settings = appendVarInt(settings, 1337)
				data := appendVarInt(nil, 4) // type byte
				data = appendVarInt(data, uint64(len(settings)))
				data = append(data, settings...)
				_, err := parseNextFrame(bytes.NewReader(data))
				Expect(err).To(MatchError("invalid value for H3_DATAGRAM: 1337"))
			})

			It("rejects invalid values for the H3_DATAGRAM (draft 00) entry", func() {
				settings := appendVarInt(nil, uint64(SettingDatagramDraft00))
				settings = appendVarInt(settings, 1337)
				data := appendVarInt(nil, 4) // type byte
				data = appendVarInt(data, uint64(len(settings)))
				data = append(data, settings...)
				_, err := parseNextFrame(bytes.NewReader(data))
				Expect(err).To(MatchError("invalid value for H3_DATAGRAM (draft 00): 1337"))
			})

			It("writes the H3_DATAGRAM setting", func() {
				settings := Settings{SettingDatagram: 1}
				buf := &bytes.Buffer{}
				settings.writeFrame(buf)
				frame, err := parseNextFrame(buf)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame).To(Equal(settings))
			})
		})
	})
})
