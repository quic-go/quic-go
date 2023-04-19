package wire

import (
	"bytes"
	"io"

	"github.com/quic-go/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CONNECTION_CLOSE Frame", func() {
	Context("when parsing", func() {
		It("accepts sample frame containing a QUIC error code", func() {
			reason := "No recent network activity."
			data := encodeVarInt(0x19)
			data = append(data, encodeVarInt(0x1337)...)              // frame type
			data = append(data, encodeVarInt(uint64(len(reason)))...) // reason phrase length
			data = append(data, []byte(reason)...)
			b := bytes.NewReader(data)
			frame, err := parseConnectionCloseFrame(b, connectionCloseFrameType, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.IsApplicationError).To(BeFalse())
			Expect(frame.ErrorCode).To(BeEquivalentTo(0x19))
			Expect(frame.FrameType).To(BeEquivalentTo(0x1337))
			Expect(frame.ReasonPhrase).To(Equal(reason))
			Expect(b.Len()).To(BeZero())
		})

		It("accepts sample frame containing an application error code", func() {
			reason := "The application messed things up."
			data := encodeVarInt(0xcafe)
			data = append(data, encodeVarInt(uint64(len(reason)))...) // reason phrase length
			data = append(data, reason...)
			b := bytes.NewReader(data)
			frame, err := parseConnectionCloseFrame(b, applicationCloseFrameType, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.IsApplicationError).To(BeTrue())
			Expect(frame.ErrorCode).To(BeEquivalentTo(0xcafe))
			Expect(frame.ReasonPhrase).To(Equal(reason))
			Expect(b.Len()).To(BeZero())
		})

		It("rejects long reason phrases", func() {
			data := encodeVarInt(0xcafe)
			data = append(data, encodeVarInt(0x42)...)   // frame type
			data = append(data, encodeVarInt(0xffff)...) // reason phrase length
			_, err := parseConnectionCloseFrame(bytes.NewReader(data), connectionCloseFrameType, protocol.Version1)
			Expect(err).To(MatchError(io.EOF))
		})

		It("errors on EOFs", func() {
			reason := "No recent network activity."
			data := encodeVarInt(0x19)
			data = append(data, encodeVarInt(0x1337)...)              // frame type
			data = append(data, encodeVarInt(uint64(len(reason)))...) // reason phrase length
			data = append(data, []byte(reason)...)
			b := bytes.NewReader(data)
			_, err := parseConnectionCloseFrame(b, connectionCloseFrameType, protocol.Version1)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				b := bytes.NewReader(data[:i])
				_, err = parseConnectionCloseFrame(b, connectionCloseFrameType, protocol.Version1)
				Expect(err).To(MatchError(io.EOF))
			}
		})

		It("parses a frame without a reason phrase", func() {
			data := encodeVarInt(0xcafe)
			data = append(data, encodeVarInt(0x42)...) // frame type
			data = append(data, encodeVarInt(0)...)
			b := bytes.NewReader(data)
			frame, err := parseConnectionCloseFrame(b, connectionCloseFrameType, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.ReasonPhrase).To(BeEmpty())
			Expect(b.Len()).To(BeZero())
		})
	})

	Context("when writing", func() {
		It("writes a frame without a reason phrase", func() {
			frame := &ConnectionCloseFrame{
				ErrorCode: 0xbeef,
				FrameType: 0x12345,
			}
			b, err := frame.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{connectionCloseFrameType}
			expected = append(expected, encodeVarInt(0xbeef)...)
			expected = append(expected, encodeVarInt(0x12345)...) // frame type
			expected = append(expected, encodeVarInt(0)...)       // reason phrase length
			Expect(b).To(Equal(expected))
		})

		It("writes a frame with a reason phrase", func() {
			frame := &ConnectionCloseFrame{
				ErrorCode:    0xdead,
				ReasonPhrase: "foobar",
			}
			b, err := frame.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{connectionCloseFrameType}
			expected = append(expected, encodeVarInt(0xdead)...)
			expected = append(expected, encodeVarInt(0)...) // frame type
			expected = append(expected, encodeVarInt(6)...) // reason phrase length
			expected = append(expected, []byte("foobar")...)
			Expect(b).To(Equal(expected))
		})

		It("writes a frame with an application error code", func() {
			frame := &ConnectionCloseFrame{
				IsApplicationError: true,
				ErrorCode:          0xdead,
				ReasonPhrase:       "foobar",
			}
			b, err := frame.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{applicationCloseFrameType}
			expected = append(expected, encodeVarInt(0xdead)...)
			expected = append(expected, encodeVarInt(6)...) // reason phrase length
			expected = append(expected, []byte("foobar")...)
			Expect(b).To(Equal(expected))
		})

		It("has proper min length, for a frame containing a QUIC error code", func() {
			f := &ConnectionCloseFrame{
				ErrorCode:    0xcafe,
				FrameType:    0xdeadbeef,
				ReasonPhrase: "foobar",
			}
			b, err := f.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(HaveLen(int(f.Length(protocol.Version1))))
		})

		It("has proper min length, for a frame containing an application error code", func() {
			f := &ConnectionCloseFrame{
				IsApplicationError: true,
				ErrorCode:          0xcafe,
				ReasonPhrase:       "foobar",
			}
			b, err := f.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(HaveLen(int(f.Length(protocol.Version1))))
		})
	})
})
