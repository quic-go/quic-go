package http3

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/quic-go/quic-go"
	mockquic "github.com/quic-go/quic-go/internal/mocks/quic"
	"github.com/quic-go/quic-go/quicvarint"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

var _ = Describe("Frames", func() {
	It("skips unknown frames", func() {
		data := quicvarint.Append(nil, 0xdeadbeef) // type byte
		data = quicvarint.Append(data, 0x42)
		data = append(data, make([]byte, 0x42)...)
		data = (&dataFrame{Length: 0x1234}).Append(data)
		fp := frameParser{r: bytes.NewReader(data)}
		frame, err := fp.ParseNext()
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(BeAssignableToTypeOf(&dataFrame{}))
		Expect(frame.(*dataFrame).Length).To(Equal(uint64(0x1234)))
	})

	It("closes the connection when encountering a reserved frame type", func() {
		conn := mockquic.NewMockEarlyConnection(mockCtrl)
		for _, ft := range []uint64{0x2, 0x6, 0x8, 0x9} {
			data := quicvarint.Append(nil, ft)
			data = quicvarint.Append(data, 6)
			data = append(data, []byte("foobar")...)

			conn.EXPECT().CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), gomock.Any())
			fp := frameParser{
				r:    bytes.NewReader(data),
				conn: conn,
			}
			_, err := fp.ParseNext()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("http3: reserved frame type"))
		}
	})

	Context("DATA frames", func() {
		It("parses", func() {
			data := quicvarint.Append(nil, 0) // type byte
			data = quicvarint.Append(data, 0x1337)
			fp := frameParser{r: bytes.NewReader(data)}
			frame, err := fp.ParseNext()
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeAssignableToTypeOf(&dataFrame{}))
			Expect(frame.(*dataFrame).Length).To(Equal(uint64(0x1337)))
		})

		It("writes", func() {
			fp := frameParser{r: bytes.NewReader((&dataFrame{Length: 0xdeadbeef}).Append(nil))}
			frame, err := fp.ParseNext()
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
			fp := frameParser{r: bytes.NewReader(data)}
			frame, err := fp.ParseNext()
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeAssignableToTypeOf(&headersFrame{}))
			Expect(frame.(*headersFrame).Length).To(Equal(uint64(0x1337)))
		})

		It("writes", func() {
			data := (&headersFrame{Length: 0xdeadbeef}).Append(nil)
			fp := frameParser{r: bytes.NewReader(data)}
			frame, err := fp.ParseNext()
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
			fp := frameParser{r: bytes.NewReader(data)}
			frame, err := fp.ParseNext()
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
			fp := frameParser{r: bytes.NewReader(data)}
			_, err := fp.ParseNext()
			Expect(err).To(MatchError("duplicate setting: 13"))
		})

		It("writes", func() {
			sf := &settingsFrame{Other: map[uint64]uint64{
				1:  2,
				99: 999,
				13: 37,
			}}
			fp := frameParser{r: bytes.NewReader(sf.Append(nil))}
			frame, err := fp.ParseNext()
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(Equal(sf))
		})

		It("errors on EOF", func() {
			sf := &settingsFrame{Other: map[uint64]uint64{
				13:         37,
				0xdeadbeef: 0xdecafbad,
			}}
			data := sf.Append(nil)
			fp := frameParser{r: bytes.NewReader(data)}
			_, err := fp.ParseNext()
			Expect(err).ToNot(HaveOccurred())

			for i := range data {
				b := make([]byte, i)
				copy(b, data[:i])
				fp := frameParser{r: bytes.NewReader(b)}
				_, err := fp.ParseNext()
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
				fp := frameParser{r: bytes.NewReader(data)}
				f, err := fp.ParseNext()
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
				fp := frameParser{r: bytes.NewReader(data)}
				_, err := fp.ParseNext()
				Expect(err).To(MatchError(fmt.Sprintf("duplicate setting: %d", settingDatagram)))
			})

			It("rejects invalid values for the SETTINGS_H3_DATAGRAM entry", func() {
				settings := quicvarint.Append(nil, settingDatagram)
				settings = quicvarint.Append(settings, 1337)
				data := quicvarint.Append(nil, 4) // type byte
				data = quicvarint.Append(data, uint64(len(settings)))
				data = append(data, settings...)
				fp := frameParser{r: bytes.NewReader(data)}
				_, err := fp.ParseNext()
				Expect(err).To(MatchError("invalid value for SETTINGS_H3_DATAGRAM: 1337"))
			})

			It("writes the SETTINGS_H3_DATAGRAM setting", func() {
				sf := &settingsFrame{Datagram: true}
				fp := frameParser{r: bytes.NewReader(sf.Append(nil))}
				frame, err := fp.ParseNext()
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
				fp := frameParser{r: bytes.NewReader(data)}
				f, err := fp.ParseNext()
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
				fp := frameParser{r: bytes.NewReader(data)}
				_, err := fp.ParseNext()
				Expect(err).To(MatchError(fmt.Sprintf("duplicate setting: %d", settingExtendedConnect)))
			})

			It("rejects invalid values for the SETTINGS_ENABLE_CONNECT_PROTOCOL entry", func() {
				settings := quicvarint.Append(nil, settingExtendedConnect)
				settings = quicvarint.Append(settings, 1337)
				data := quicvarint.Append(nil, 4) // type byte
				data = quicvarint.Append(data, uint64(len(settings)))
				data = append(data, settings...)
				fp := frameParser{r: bytes.NewReader(data)}
				_, err := fp.ParseNext()
				Expect(err).To(MatchError("invalid value for SETTINGS_ENABLE_CONNECT_PROTOCOL: 1337"))
			})

			It("writes the SETTINGS_ENABLE_CONNECT_PROTOCOL setting", func() {
				sf := &settingsFrame{ExtendedConnect: true}
				fp := frameParser{r: bytes.NewReader(sf.Append(nil))}
				frame, err := fp.ParseNext()
				Expect(err).ToNot(HaveOccurred())
				Expect(frame).To(Equal(sf))
			})
		})
	})

	Context("GOAWAY frames", func() {
		It("parses", func() {
			data := quicvarint.Append(nil, 0x7) // type byte
			data = quicvarint.Append(data, uint64(quicvarint.Len(100)))
			data = quicvarint.Append(data, 100)
			fp := frameParser{r: bytes.NewReader(data)}
			frame, err := fp.ParseNext()
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeAssignableToTypeOf(&goAwayFrame{}))
			Expect(frame.(*goAwayFrame).StreamID).To(Equal(quic.StreamID(100)))
		})

		It("errors on inconsistent lengths", func() {
			data := quicvarint.Append(nil, 0x7) // type byte
			data = quicvarint.Append(data, uint64(quicvarint.Len(100))+1)
			data = quicvarint.Append(data, 100)
			fp := frameParser{r: bytes.NewReader(data)}
			_, err := fp.ParseNext()
			Expect(err).To(MatchError("GOAWAY frame: inconsistent length"))
		})

		It("writes", func() {
			data := (&goAwayFrame{StreamID: 200}).Append(nil)
			fp := frameParser{r: bytes.NewReader(data)}
			frame, err := fp.ParseNext()
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeAssignableToTypeOf(&goAwayFrame{}))
			Expect(frame.(*goAwayFrame).StreamID).To(Equal(quic.StreamID(200)))
		})

		It("errors on EOF", func() {
			data := (&goAwayFrame{StreamID: 1337}).Append(nil)
			fp := frameParser{r: bytes.NewReader(data)}
			_, err := fp.ParseNext()
			Expect(err).ToNot(HaveOccurred())
			for i := range data {
				fp := frameParser{r: bytes.NewReader(data[:i])}
				_, err := fp.ParseNext()
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("hijacking", func() {
		It("reads a frame without hijacking the stream", func() {
			buf := bytes.NewBuffer(quicvarint.Append(nil, 1337))
			customFrameContents := []byte("foobar")
			buf.Write(customFrameContents)

			var called bool
			fp := frameParser{
				r: buf,
				unknownFrameHandler: func(ft FrameType, e error) (hijacked bool, err error) {
					Expect(e).ToNot(HaveOccurred())
					Expect(ft).To(BeEquivalentTo(1337))
					called = true
					b := make([]byte, 3)
					_, err = io.ReadFull(buf, b)
					Expect(err).ToNot(HaveOccurred())
					Expect(string(b)).To(Equal("foo"))
					return true, nil
				},
			}
			_, err := fp.ParseNext()
			Expect(err).To(MatchError(errHijacked))
			Expect(called).To(BeTrue())
		})

		It("passes on errors that occur when reading the frame type", func() {
			testErr := errors.New("test error")
			var called bool
			fp := frameParser{
				r: errReader{err: testErr},
				unknownFrameHandler: func(ft FrameType, e error) (hijacked bool, err error) {
					Expect(e).To(MatchError(testErr))
					Expect(ft).To(BeZero())
					called = true
					return true, nil
				},
			}
			_, err := fp.ParseNext()
			Expect(err).To(MatchError(errHijacked))
			Expect(called).To(BeTrue())
		})

		It("reads a frame without hijacking the stream", func() {
			b := quicvarint.Append(nil, 1337)
			customFrameContents := []byte("custom frame")
			b = quicvarint.Append(b, uint64(len(customFrameContents)))
			b = append(b, customFrameContents...)
			b = (&dataFrame{Length: 6}).Append(b)
			b = append(b, []byte("foobar")...)

			var called bool
			fp := frameParser{
				r: bytes.NewReader(b),
				unknownFrameHandler: func(ft FrameType, e error) (hijacked bool, err error) {
					Expect(e).ToNot(HaveOccurred())
					Expect(ft).To(BeEquivalentTo(1337))
					called = true
					return false, nil
				},
			}
			frame, err := fp.ParseNext()
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(Equal(&dataFrame{Length: 6}))
			Expect(called).To(BeTrue())
		})
	})
})
