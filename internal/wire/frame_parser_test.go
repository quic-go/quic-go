package wire

import (
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Frame parsing", func() {
	var parser FrameParser

	BeforeEach(func() {
		parser = NewFrameParser(true)
	})

	It("returns nil if there's nothing more to read", func() {
		l, f, err := parser.ParseNext(nil, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(l).To(BeZero())
		Expect(f).To(BeNil())
	})

	It("skips PADDING frames", func() {
		b := []byte{0, 0} // 2 PADDING frames
		b, err := (&PingFrame{}).Append(b, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		l, f, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(f).To(Equal(&PingFrame{}))
		Expect(l).To(Equal(2 + 1))
	})

	It("handles PADDING at the end", func() {
		l, f, err := parser.ParseNext([]byte{0, 0, 0}, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(f).To(BeNil())
		Expect(l).To(Equal(3))
	})

	It("parses a single frame", func() {
		var b []byte
		for i := 0; i < 10; i++ {
			var err error
			b, err = (&PingFrame{}).Append(b, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
		}
		l, f, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(f).To(BeAssignableToTypeOf(&PingFrame{}))
		Expect(l).To(Equal(1))
	})

	It("unpacks ACK frames", func() {
		f := &AckFrame{AckRanges: []AckRange{{Smallest: 1, Largest: 0x13}}}
		b, err := f.Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).ToNot(BeNil())
		Expect(frame).To(BeAssignableToTypeOf(f))
		Expect(frame.(*AckFrame).LargestAcked()).To(Equal(protocol.PacketNumber(0x13)))
		Expect(l).To(Equal(len(b)))
	})

	It("uses the custom ack delay exponent for 1RTT packets", func() {
		parser.SetAckDelayExponent(protocol.AckDelayExponent + 2)
		f := &AckFrame{
			AckRanges: []AckRange{{Smallest: 1, Largest: 1}},
			DelayTime: time.Second,
		}
		b, err := f.Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		_, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		// The ACK frame is always written using the protocol.AckDelayExponent.
		// That's why we expect a different value when parsing.
		Expect(frame.(*AckFrame).DelayTime).To(Equal(4 * time.Second))
	})

	It("uses the default ack delay exponent for non-1RTT packets", func() {
		parser.SetAckDelayExponent(protocol.AckDelayExponent + 2)
		f := &AckFrame{
			AckRanges: []AckRange{{Smallest: 1, Largest: 1}},
			DelayTime: time.Second,
		}
		b, err := f.Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		_, frame, err := parser.ParseNext(b, protocol.EncryptionHandshake, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame.(*AckFrame).DelayTime).To(Equal(time.Second))
	})

	It("unpacks RESET_STREAM frames", func() {
		f := &ResetStreamFrame{
			StreamID:  0xdeadbeef,
			FinalSize: 0xdecafbad1234,
			ErrorCode: 0x1337,
		}
		b, err := f.Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
		Expect(l).To(Equal(len(b)))
	})

	It("unpacks STOP_SENDING frames", func() {
		f := &StopSendingFrame{StreamID: 0x42}
		b, err := f.Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
		Expect(l).To(Equal(len(b)))
	})

	It("unpacks CRYPTO frames", func() {
		f := &CryptoFrame{
			Offset: 0x1337,
			Data:   []byte("lorem ipsum"),
		}
		b, err := f.Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).ToNot(BeNil())
		Expect(frame).To(Equal(f))
		Expect(l).To(Equal(len(b)))
	})

	It("unpacks NEW_TOKEN frames", func() {
		f := &NewTokenFrame{Token: []byte("foobar")}
		b, err := f.Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).ToNot(BeNil())
		Expect(frame).To(Equal(f))
		Expect(l).To(Equal(len(b)))
	})

	It("unpacks STREAM frames", func() {
		f := &StreamFrame{
			StreamID: 0x42,
			Offset:   0x1337,
			Fin:      true,
			Data:     []byte("foobar"),
		}
		b, err := f.Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).ToNot(BeNil())
		Expect(frame).To(Equal(f))
		Expect(l).To(Equal(len(b)))
	})

	It("unpacks MAX_DATA frames", func() {
		f := &MaxDataFrame{
			MaximumData: 0xcafe,
		}
		b, err := f.Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
		Expect(l).To(Equal(len(b)))
	})

	It("unpacks MAX_STREAM_DATA frames", func() {
		f := &MaxStreamDataFrame{
			StreamID:          0xdeadbeef,
			MaximumStreamData: 0xdecafbad,
		}
		b, err := f.Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
		Expect(l).To(Equal(len(b)))
	})

	It("unpacks MAX_STREAMS frames", func() {
		f := &MaxStreamsFrame{
			Type:         protocol.StreamTypeBidi,
			MaxStreamNum: 0x1337,
		}
		b, err := f.Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
		Expect(l).To(Equal(len(b)))
	})

	It("unpacks DATA_BLOCKED frames", func() {
		f := &DataBlockedFrame{MaximumData: 0x1234}
		b, err := f.Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
		Expect(l).To(Equal(len(b)))
	})

	It("unpacks STREAM_DATA_BLOCKED frames", func() {
		f := &StreamDataBlockedFrame{
			StreamID:          0xdeadbeef,
			MaximumStreamData: 0xdead,
		}
		b, err := f.Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
		Expect(l).To(Equal(len(b)))
	})

	It("unpacks STREAMS_BLOCKED frames", func() {
		f := &StreamsBlockedFrame{
			Type:        protocol.StreamTypeBidi,
			StreamLimit: 0x1234567,
		}
		b, err := f.Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
		Expect(l).To(Equal(len(b)))
	})

	It("unpacks NEW_CONNECTION_ID frames", func() {
		f := &NewConnectionIDFrame{
			SequenceNumber:      0x1337,
			ConnectionID:        protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
			StatelessResetToken: protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		}
		b, err := f.Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
		Expect(l).To(Equal(len(b)))
	})

	It("unpacks RETIRE_CONNECTION_ID frames", func() {
		f := &RetireConnectionIDFrame{SequenceNumber: 0x1337}
		b, err := f.Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
		Expect(l).To(Equal(len(b)))
	})

	It("unpacks PATH_CHALLENGE frames", func() {
		f := &PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
		b, err := f.Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).ToNot(BeNil())
		Expect(frame).To(BeAssignableToTypeOf(f))
		Expect(frame.(*PathChallengeFrame).Data).To(Equal([8]byte{1, 2, 3, 4, 5, 6, 7, 8}))
		Expect(l).To(Equal(len(b)))
	})

	It("unpacks PATH_RESPONSE frames", func() {
		f := &PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
		b, err := f.Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).ToNot(BeNil())
		Expect(frame).To(BeAssignableToTypeOf(f))
		Expect(frame.(*PathResponseFrame).Data).To(Equal([8]byte{1, 2, 3, 4, 5, 6, 7, 8}))
		Expect(l).To(Equal(len(b)))
	})

	It("unpacks CONNECTION_CLOSE frames", func() {
		f := &ConnectionCloseFrame{
			IsApplicationError: true,
			ReasonPhrase:       "foobar",
		}
		b, err := f.Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
		Expect(l).To(Equal(len(b)))
	})

	It("unpacks HANDSHAKE_DONE frames", func() {
		f := &HandshakeDoneFrame{}
		b, err := f.Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
		Expect(l).To(Equal(len(b)))
	})

	It("unpacks DATAGRAM frames", func() {
		f := &DatagramFrame{Data: []byte("foobar")}
		b, err := f.Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
		Expect(l).To(Equal(len(b)))
	})

	It("errors when DATAGRAM frames are not supported", func() {
		parser = NewFrameParser(false)
		f := &DatagramFrame{Data: []byte("foobar")}
		b, err := f.Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		_, _, err = parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
		Expect(err).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.FrameEncodingError,
			FrameType:    0x30,
			ErrorMessage: "unknown frame type",
		}))
	})

	It("errors on invalid type", func() {
		_, _, err := parser.ParseNext(encodeVarInt(0x42), protocol.Encryption1RTT, protocol.Version1)
		Expect(err).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.FrameEncodingError,
			FrameType:    0x42,
			ErrorMessage: "unknown frame type",
		}))
	})

	It("errors on invalid frames", func() {
		f := &MaxStreamDataFrame{
			StreamID:          0x1337,
			MaximumStreamData: 0xdeadbeef,
		}
		b, err := f.Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		_, _, err = parser.ParseNext(b[:len(b)-2], protocol.Encryption1RTT, protocol.Version1)
		Expect(err).To(HaveOccurred())
		Expect(err.(*qerr.TransportError).ErrorCode).To(Equal(qerr.FrameEncodingError))
	})

	Context("encryption level check", func() {
		frames := []Frame{
			&PingFrame{},
			&AckFrame{AckRanges: []AckRange{{Smallest: 1, Largest: 42}}},
			&ResetStreamFrame{},
			&StopSendingFrame{},
			&CryptoFrame{},
			&NewTokenFrame{Token: []byte("lorem ipsum")},
			&StreamFrame{Data: []byte("foobar")},
			&MaxDataFrame{},
			&MaxStreamDataFrame{},
			&MaxStreamsFrame{},
			&DataBlockedFrame{},
			&StreamDataBlockedFrame{},
			&StreamsBlockedFrame{},
			&NewConnectionIDFrame{ConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})},
			&RetireConnectionIDFrame{},
			&PathChallengeFrame{},
			&PathResponseFrame{},
			&ConnectionCloseFrame{},
			&HandshakeDoneFrame{},
			&DatagramFrame{},
		}

		var framesSerialized [][]byte

		BeforeEach(func() {
			framesSerialized = nil
			for _, frame := range frames {
				b, err := frame.Append(nil, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				framesSerialized = append(framesSerialized, b)
			}
		})

		It("rejects all frames but ACK, CRYPTO, PING and CONNECTION_CLOSE in Initial packets", func() {
			for i, b := range framesSerialized {
				_, _, err := parser.ParseNext(b, protocol.EncryptionInitial, protocol.Version1)
				switch frames[i].(type) {
				case *AckFrame, *ConnectionCloseFrame, *CryptoFrame, *PingFrame:
					Expect(err).ToNot(HaveOccurred())
				default:
					Expect(err).To(BeAssignableToTypeOf(&qerr.TransportError{}))
					Expect(err.(*qerr.TransportError).ErrorCode).To(Equal(qerr.FrameEncodingError))
					Expect(err.(*qerr.TransportError).ErrorMessage).To(ContainSubstring("not allowed at encryption level Initial"))
				}
			}
		})

		It("rejects all frames but ACK, CRYPTO, PING and CONNECTION_CLOSE in Handshake packets", func() {
			for i, b := range framesSerialized {
				_, _, err := parser.ParseNext(b, protocol.EncryptionHandshake, protocol.Version1)
				switch frames[i].(type) {
				case *AckFrame, *ConnectionCloseFrame, *CryptoFrame, *PingFrame:
					Expect(err).ToNot(HaveOccurred())
				default:
					Expect(err).To(BeAssignableToTypeOf(&qerr.TransportError{}))
					Expect(err.(*qerr.TransportError).ErrorCode).To(Equal(qerr.FrameEncodingError))
					Expect(err.(*qerr.TransportError).ErrorMessage).To(ContainSubstring("not allowed at encryption level Handshake"))
				}
			}
		})

		It("rejects all frames but ACK, CRYPTO, CONNECTION_CLOSE, NEW_TOKEN, PATH_RESPONSE and RETIRE_CONNECTION_ID in 0-RTT packets", func() {
			for i, b := range framesSerialized {
				_, _, err := parser.ParseNext(b, protocol.Encryption0RTT, protocol.Version1)
				switch frames[i].(type) {
				case *AckFrame, *ConnectionCloseFrame, *CryptoFrame, *NewTokenFrame, *PathResponseFrame, *RetireConnectionIDFrame:
					Expect(err).To(BeAssignableToTypeOf(&qerr.TransportError{}))
					Expect(err.(*qerr.TransportError).ErrorCode).To(Equal(qerr.FrameEncodingError))
					Expect(err.(*qerr.TransportError).ErrorMessage).To(ContainSubstring("not allowed at encryption level 0-RTT"))
				default:
					Expect(err).ToNot(HaveOccurred())
				}
			}
		})

		It("accepts all frame types in 1-RTT packets", func() {
			for _, b := range framesSerialized {
				_, _, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
			}
		})
	})
})
