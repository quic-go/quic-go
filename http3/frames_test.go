package http3

import (
	"bytes"
	"io"

	"github.com/lucas-clemente/quic-go/internal/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Frames", func() {
	appendVarInt := func(b []byte, val uint64) []byte {
		buf := &bytes.Buffer{}
		utils.WriteVarInt(buf, val)
		return append(b, buf.Bytes()...)
	}

	It("skips unknown frames", func() {
		data := appendVarInt(nil, 0xdeadbeef) // type byte
		data = appendVarInt(data, 0x42)
		data = append(data, make([]byte, 0x42)...)
		buf := bytes.NewBuffer(data)
		(&dataFrame{Length: 0x1234}).Write(buf)
		frame, err := parseNextFrame(buf)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(BeAssignableToTypeOf(&dataFrame{}))
		Expect(frame.(*dataFrame).Length).To(Equal(uint64(0x1234)))
	})

	Context("DATA frames", func() {
		It("parses", func() {
			data := appendVarInt(nil, 0) // type byte
			data = appendVarInt(data, 0x1337)
			frame, err := parseNextFrame(bytes.NewReader(data))
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeAssignableToTypeOf(&dataFrame{}))
			Expect(frame.(*dataFrame).Length).To(Equal(uint64(0x1337)))
		})

		It("writes", func() {
			buf := &bytes.Buffer{}
			(&dataFrame{Length: 0xdeadbeef}).Write(buf)
			frame, err := parseNextFrame(buf)
			Expect(err).ToNot(HaveOccurred())
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeAssignableToTypeOf(&dataFrame{}))
			Expect(frame.(*dataFrame).Length).To(Equal(uint64(0xdeadbeef)))
		})
	})

	Context("HEADERS frames", func() {
		It("parses", func() {
			data := appendVarInt(nil, 1) // type byte
			data = appendVarInt(data, 0x1337)
			frame, err := parseNextFrame(bytes.NewReader(data))
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeAssignableToTypeOf(&headersFrame{}))
			Expect(frame.(*headersFrame).Length).To(Equal(uint64(0x1337)))
		})

		It("writes", func() {
			buf := &bytes.Buffer{}
			(&headersFrame{Length: 0xdeadbeef}).Write(buf)
			frame, err := parseNextFrame(buf)
			Expect(err).ToNot(HaveOccurred())
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeAssignableToTypeOf(&headersFrame{}))
			Expect(frame.(*headersFrame).Length).To(Equal(uint64(0xdeadbeef)))
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
			Expect(frame).To(BeAssignableToTypeOf(&settingsFrame{}))
			sf := frame.(*settingsFrame)
			Expect(sf.settings).To(HaveKeyWithValue(uint64(13), uint64(37)))
			Expect(sf.settings).To(HaveKeyWithValue(uint64(0xdead), uint64(0xbeef)))
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
			sf := &settingsFrame{settings: map[uint64]uint64{
				1:  2,
				99: 999,
				13: 37,
			}}
			buf := &bytes.Buffer{}
			sf.Write(buf)
			frame, err := parseNextFrame(buf)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(Equal(sf))
		})

		It("errors on EOF", func() {
			sf := &settingsFrame{settings: map[uint64]uint64{
				13:         37,
				0xdeadbeef: 0xdecafbad,
			}}
			buf := &bytes.Buffer{}
			sf.Write(buf)

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
	})
})
