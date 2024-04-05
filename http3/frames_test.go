package http3

import (
	"bytes"
	"fmt"
	"io"

	"github.com/quic-go/quic-go/quicvarint"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Frames", func() {
	It("skips unknown frames", func() {
		b := quicvarint.Append(nil, 0xdeadbeef) // type byte
		b = quicvarint.Append(b, 0x42)
		b = append(b, make([]byte, 0x42)...)
		b = (&dataFrame{Length: 0x1234}).Append(b)
		r := bytes.NewReader(b)
		frame, err := parseNextFrame(r)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(BeAssignableToTypeOf(&dataFrame{}))
		Expect(frame.(*dataFrame).Length).To(Equal(uint64(0x1234)))
	})

	Context("DATA frames", func() {
		It("parses", func() {
			data := quicvarint.Append(nil, 0) // type byte
			data = quicvarint.Append(data, 0x1337)
			frame, err := parseNextFrame(bytes.NewReader(data))
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeAssignableToTypeOf(&dataFrame{}))
			Expect(frame.(*dataFrame).Length).To(Equal(uint64(0x1337)))
		})

		It("writes", func() {
			b := (&dataFrame{Length: 0xdeadbeef}).Append(nil)
			frame, err := parseNextFrame(bytes.NewReader(b))
			Expect(err).ToNot(HaveOccurred())
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeAssignableToTypeOf(&dataFrame{}))
			Expect(frame.(*dataFrame).Length).To(Equal(uint64(0xdeadbeef)))
		})
	})

	Context("HEADERS frames", func() {
		It("parses", func() {
			data := quicvarint.Append(nil, 1) // type byte
			data = quicvarint.Append(data, 0x1337)
			frame, err := parseNextFrame(bytes.NewReader(data))
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeAssignableToTypeOf(&headersFrame{}))
			Expect(frame.(*headersFrame).Length).To(Equal(uint64(0x1337)))
		})

		It("writes", func() {
			b := (&headersFrame{Length: 0xdeadbeef}).Append(nil)
			frame, err := parseNextFrame(bytes.NewReader(b))
			Expect(err).ToNot(HaveOccurred())
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeAssignableToTypeOf(&headersFrame{}))
			Expect(frame.(*headersFrame).Length).To(Equal(uint64(0xdeadbeef)))
		})
	})

	Context("SETTINGS frames", func() {
		It("parses", func() {
			settings := quicvarint.Append(nil, 13)
			settings = quicvarint.Append(settings, 37)
			settings = quicvarint.Append(settings, 0xdead)
			settings = quicvarint.Append(settings, 0xbeef)
			data := quicvarint.Append(nil, 4) // type byte
			data = quicvarint.Append(data, uint64(len(settings)))
			data = append(data, settings...)
			frame, err := parseNextFrame(bytes.NewReader(data))
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeAssignableToTypeOf(&settingsFrame{}))
			sf := frame.(*settingsFrame)
			Expect(sf.Other).To(HaveKeyWithValue(uint64(13), uint64(37)))
			Expect(sf.Other).To(HaveKeyWithValue(uint64(0xdead), uint64(0xbeef)))
		})

		It("rejects duplicate settings", func() {
			settings := quicvarint.Append(nil, 13)
			settings = quicvarint.Append(settings, 37)
			settings = quicvarint.Append(settings, 13)
			settings = quicvarint.Append(settings, 38)
			data := quicvarint.Append(nil, 4) // type byte
			data = quicvarint.Append(data, uint64(len(settings)))
			data = append(data, settings...)
			_, err := parseNextFrame(bytes.NewReader(data))
			Expect(err).To(MatchError("duplicate setting: 13"))
		})

		It("writes", func() {
			sf := &settingsFrame{Other: map[uint64]uint64{
				1:  2,
				99: 999,
				13: 37,
			}}
			frame, err := parseNextFrame(bytes.NewReader(sf.Append(nil)))
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(Equal(sf))
		})

		It("errors on EOF", func() {
			sf := &settingsFrame{Other: map[uint64]uint64{
				13:         37,
				0xdeadbeef: 0xdecafbad,
			}}
			data := sf.Append(nil)

			_, err := parseNextFrame(bytes.NewReader(data))
			Expect(err).ToNot(HaveOccurred())

			for i := range data {
				b := make([]byte, i)
				copy(b, data[:i])
				_, err := parseNextFrame(bytes.NewReader(b))
				Expect(err).To(MatchError(io.EOF))
			}
		})

		Context("HTTP Datagrams", func() {
			It("reads the SETTINGS_H3_DATAGRAM value", func() {
				settings := quicvarint.Append(nil, settingDatagram)
				settings = quicvarint.Append(settings, 1)
				data := quicvarint.Append(nil, 4) // type byte
				data = quicvarint.Append(data, uint64(len(settings)))
				data = append(data, settings...)
				f, err := parseNextFrame(bytes.NewReader(data))
				Expect(err).ToNot(HaveOccurred())
				Expect(f).To(BeAssignableToTypeOf(&settingsFrame{}))
				sf := f.(*settingsFrame)
				Expect(sf.Datagram).To(BeTrue())
			})

			It("rejects duplicate SETTINGS_H3_DATAGRAM entries", func() {
				settings := quicvarint.Append(nil, settingDatagram)
				settings = quicvarint.Append(settings, 1)
				settings = quicvarint.Append(settings, settingDatagram)
				settings = quicvarint.Append(settings, 1)
				data := quicvarint.Append(nil, 4) // type byte
				data = quicvarint.Append(data, uint64(len(settings)))
				data = append(data, settings...)
				_, err := parseNextFrame(bytes.NewReader(data))
				Expect(err).To(MatchError(fmt.Sprintf("duplicate setting: %d", settingDatagram)))
			})

			It("rejects invalid values for the SETTINGS_H3_DATAGRAM entry", func() {
				settings := quicvarint.Append(nil, settingDatagram)
				settings = quicvarint.Append(settings, 1337)
				data := quicvarint.Append(nil, 4) // type byte
				data = quicvarint.Append(data, uint64(len(settings)))
				data = append(data, settings...)
				_, err := parseNextFrame(bytes.NewReader(data))
				Expect(err).To(MatchError("invalid value for SETTINGS_H3_DATAGRAM: 1337"))
			})

			It("writes the SETTINGS_H3_DATAGRAM setting", func() {
				sf := &settingsFrame{Datagram: true}
				frame, err := parseNextFrame(bytes.NewReader(sf.Append(nil)))
				Expect(err).ToNot(HaveOccurred())
				Expect(frame).To(Equal(sf))
			})
		})

		Context("Extended Connect", func() {
			It("reads the SETTINGS_ENABLE_CONNECT_PROTOCOL value", func() {
				settings := quicvarint.Append(nil, settingExtendedConnect)
				settings = quicvarint.Append(settings, 1)
				data := quicvarint.Append(nil, 4) // type byte
				data = quicvarint.Append(data, uint64(len(settings)))
				data = append(data, settings...)
				f, err := parseNextFrame(bytes.NewReader(data))
				Expect(err).ToNot(HaveOccurred())
				Expect(f).To(BeAssignableToTypeOf(&settingsFrame{}))
				sf := f.(*settingsFrame)
				Expect(sf.ExtendedConnect).To(BeTrue())
			})

			It("rejects duplicate SETTINGS_ENABLE_CONNECT_PROTOCOL entries", func() {
				settings := quicvarint.Append(nil, settingExtendedConnect)
				settings = quicvarint.Append(settings, 1)
				settings = quicvarint.Append(settings, settingExtendedConnect)
				settings = quicvarint.Append(settings, 1)
				data := quicvarint.Append(nil, 4) // type byte
				data = quicvarint.Append(data, uint64(len(settings)))
				data = append(data, settings...)
				_, err := parseNextFrame(bytes.NewReader(data))
				Expect(err).To(MatchError(fmt.Sprintf("duplicate setting: %d", settingExtendedConnect)))
			})

			It("rejects invalid values for the SETTINGS_ENABLE_CONNECT_PROTOCOL entry", func() {
				settings := quicvarint.Append(nil, settingExtendedConnect)
				settings = quicvarint.Append(settings, 1337)
				data := quicvarint.Append(nil, 4) // type byte
				data = quicvarint.Append(data, uint64(len(settings)))
				data = append(data, settings...)
				_, err := parseNextFrame(bytes.NewReader(data))
				Expect(err).To(MatchError("invalid value for SETTINGS_ENABLE_CONNECT_PROTOCOL: 1337"))
			})

			It("writes the SETTINGS_ENABLE_CONNECT_PROTOCOL setting", func() {
				sf := &settingsFrame{ExtendedConnect: true}
				frame, err := parseNextFrame(bytes.NewReader(sf.Append(nil)))
				Expect(err).ToNot(HaveOccurred())
				Expect(frame).To(Equal(sf))
			})
		})
	})
})
