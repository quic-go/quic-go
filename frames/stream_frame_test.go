package frames

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("StreamFrame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			// a STREAM frame, plus 3 additional bytes, not belonging to this frame
			b := bytes.NewReader([]byte{0xa0, 0x1, 0x06, 0x00, 'f', 'o', 'o', 'b', 'a', 'r' /* additional bytes */, 'f', 'o', 'o'})
			frame, err := ParseStreamFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.FinBit).To(BeFalse())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(1)))
			Expect(frame.Offset).To(BeZero())
			Expect(frame.DataLenPresent).To(BeTrue())
			Expect(frame.Data).To(Equal([]byte("foobar")))
			Expect(b.Len()).To(Equal(3))
		})

		It("accepts frame without data length", func() {
			b := bytes.NewReader([]byte{0x80, 0x1, 'f', 'o', 'o', 'b', 'a', 'r'})
			frame, err := ParseStreamFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.FinBit).To(BeFalse())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(1)))
			Expect(frame.Offset).To(BeZero())
			Expect(frame.DataLenPresent).To(BeFalse())
			Expect(frame.Data).To(Equal([]byte("foobar")))
			Expect(b.Len()).To(BeZero())
		})

		It("accepts an empty frame with FinBit set, with data length set", func() {
			// the STREAM frame, plus 3 additional bytes, not belonging to this frame
			b := bytes.NewReader([]byte{0x80 ^ 0x40 ^ 0x20, 0x1 /* stream id */, 0, 0, 'f', 'o', 'o'})
			frame, err := ParseStreamFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.FinBit).To(BeTrue())
			Expect(frame.DataLenPresent).To(BeTrue())
			Expect(frame.Data).To(BeEmpty())
			Expect(b.Len()).To(Equal(3))
		})

		It("accepts an empty frame with the FinBit set", func() {
			b := bytes.NewReader([]byte{0x80 ^ 0x40, 0x1 /* stream id */, 'f', 'o', 'o', 'b', 'a', 'r'})
			frame, err := ParseStreamFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.FinBit).To(BeTrue())
			Expect(frame.DataLenPresent).To(BeFalse())
			Expect(frame.Data).To(Equal([]byte("foobar")))
			Expect(b.Len()).To(BeZero())
		})

		It("accepts frames with offsets", func() {
			b := bytes.NewReader([]byte{0xa4, 0x1, 0x2a, 0x00, 0x06, 0x00, 'f', 'o', 'o', 'b', 'a', 'r'})
			frame, err := ParseStreamFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.FinBit).To(BeFalse())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(1)))
			Expect(frame.Offset).To(Equal(protocol.ByteCount(42)))
			Expect(frame.DataLenPresent).To(BeTrue())
			Expect(frame.Data).To(Equal([]byte("foobar")))
			Expect(b.Len()).To(BeZero())
		})

		It("errors on empty stream frames that don't have the FinBit set", func() {
			b := bytes.NewReader([]byte{0x80 ^ 0x20, 0x1, 0, 0})
			_, err := ParseStreamFrame(b)
			Expect(err).To(MatchError(qerr.EmptyStreamFrameNoFin))
		})

		It("rejects frames to too large dataLen", func() {
			b := bytes.NewReader([]byte{0xa0, 0x1, 0xff, 0xf})
			_, err := ParseStreamFrame(b)
			Expect(err).To(MatchError(qerr.Error(qerr.InvalidStreamData, "data len too large")))
		})

		It("rejects frames that overflow the offset", func() {
			// Offset + len(Data) overflows MaxByteCount
			f := &StreamFrame{
				StreamID: 1,
				Offset:   protocol.MaxByteCount,
				Data:     []byte{'f'},
			}
			b := &bytes.Buffer{}
			f.Write(b, protocol.VersionWhatever)
			_, err := ParseStreamFrame(bytes.NewReader(b.Bytes()))
			Expect(err).To(MatchError(qerr.Error(qerr.InvalidStreamData, "data overflows maximum offset")))
		})

		It("errors on EOFs", func() {
			data := []byte{0xa4, 0x1, 0x2a, 0x00, 0x06, 0x00, 'f', 'o', 'o', 'b', 'a', 'r'}
			_, err := ParseStreamFrame(bytes.NewReader(data))
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := ParseStreamFrame(bytes.NewReader(data[0:i]))
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("when writing", func() {
		It("writes sample frame", func() {
			b := &bytes.Buffer{}
			err := (&StreamFrame{
				StreamID:       1,
				Data:           []byte("foobar"),
				DataLenPresent: true,
			}).Write(b, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Bytes()).To(Equal([]byte{0xa0, 0x1, 0x06, 0x00, 'f', 'o', 'o', 'b', 'a', 'r'}))
		})

		It("sets the FinBit", func() {
			b := &bytes.Buffer{}
			err := (&StreamFrame{
				StreamID: 1,
				Data:     []byte("foobar"),
				FinBit:   true,
			}).Write(b, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Bytes()[0] & 0x40).To(Equal(byte(0x40)))
		})

		It("errors when length is zero and FIN is not set", func() {
			b := &bytes.Buffer{}
			err := (&StreamFrame{
				StreamID: 1,
			}).Write(b, 0)
			Expect(err).To(MatchError("StreamFrame: attempting to write empty frame without FIN"))
		})

		It("has proper min length for a short StreamID and a short offset", func() {
			b := &bytes.Buffer{}
			f := &StreamFrame{
				StreamID: 1,
				Data:     []byte{},
				Offset:   0,
				FinBit:   true,
			}
			err := f.Write(b, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(b.Len())))
		})

		It("has proper min length for a long StreamID and a big offset", func() {
			b := &bytes.Buffer{}
			f := &StreamFrame{
				StreamID: 0xDECAFBAD,
				Data:     []byte{},
				Offset:   0xDEADBEEFCAFE,
				FinBit:   true,
			}
			err := f.Write(b, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(b.Len())))
		})

		Context("data length field", func() {
			It("writes the data length", func() {
				dataLen := 0x1337
				b := &bytes.Buffer{}
				f := &StreamFrame{
					StreamID:       1,
					Data:           bytes.Repeat([]byte{'f'}, dataLen),
					DataLenPresent: true,
					Offset:         0,
				}
				err := f.Write(b, 0)
				Expect(err).ToNot(HaveOccurred())
				minLength, _ := f.MinLength(0)
				Expect(b.Bytes()[0] & 0x20).To(Equal(uint8(0x20)))
				Expect(b.Bytes()[minLength-2 : minLength]).To(Equal([]byte{0x37, 0x13}))
			})

			It("omits the data length field", func() {
				dataLen := 0x1337
				b := &bytes.Buffer{}
				f := &StreamFrame{
					StreamID:       1,
					Data:           bytes.Repeat([]byte{'f'}, dataLen),
					DataLenPresent: false,
					Offset:         0,
				}
				err := f.Write(b, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Bytes()[0] & 0x20).To(Equal(uint8(0)))
				Expect(b.Bytes()[1 : b.Len()-dataLen]).ToNot(ContainSubstring(string([]byte{0x37, 0x13})))
				minLength, _ := f.MinLength(0)
				f.DataLenPresent = true
				minLengthWithoutDataLen, _ := f.MinLength(0)
				Expect(minLength).To(Equal(minLengthWithoutDataLen - 2))
			})

			It("calculates the correcct min-length", func() {
				f := &StreamFrame{
					StreamID:       0xCAFE,
					Data:           []byte("foobar"),
					DataLenPresent: false,
					Offset:         0xDEADBEEF,
				}
				minLengthWithoutDataLen, _ := f.MinLength(0)
				f.DataLenPresent = true
				Expect(f.MinLength(0)).To(Equal(minLengthWithoutDataLen + 2))
			})
		})

		Context("offset lengths", func() {
			It("does not write an offset if the offset is 0", func() {
				b := &bytes.Buffer{}
				err := (&StreamFrame{
					StreamID: 1,
					Data:     []byte("foobar"),
					Offset:   0,
				}).Write(b, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Bytes()[0] & 0x1c).To(Equal(uint8(0x0)))
			})

			It("writes a 2-byte offset if the offset is larger than 0", func() {
				b := &bytes.Buffer{}
				err := (&StreamFrame{
					StreamID: 1,
					Data:     []byte("foobar"),
					Offset:   0x1337,
				}).Write(b, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Bytes()[0] & 0x1c).To(Equal(uint8(0x1 << 2)))
				Expect(b.Bytes()[2:4]).To(Equal([]byte{0x37, 0x13}))
			})

			It("writes a 3-byte offset if the offset", func() {
				b := &bytes.Buffer{}
				(&StreamFrame{
					StreamID: 1,
					Data:     []byte("foobar"),
					Offset:   0x13CAFE,
				}).Write(b, 0)
				Expect(b.Bytes()[0] & 0x1c).To(Equal(uint8(0x2 << 2)))
				Expect(b.Bytes()[2:5]).To(Equal([]byte{0xFE, 0xCA, 0x13}))
			})

			It("writes a 4-byte offset if the offset", func() {
				b := &bytes.Buffer{}
				err := (&StreamFrame{
					StreamID: 1,
					Data:     []byte("foobar"),
					Offset:   0xDEADBEEF,
				}).Write(b, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Bytes()[0] & 0x1c).To(Equal(uint8(0x3 << 2)))
				Expect(b.Bytes()[2:6]).To(Equal([]byte{0xEF, 0xBE, 0xAD, 0xDE}))
			})

			It("writes a 5-byte offset if the offset", func() {
				b := &bytes.Buffer{}
				err := (&StreamFrame{
					StreamID: 1,
					Data:     []byte("foobar"),
					Offset:   0x13DEADBEEF,
				}).Write(b, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Bytes()[0] & 0x1c).To(Equal(uint8(0x4 << 2)))
				Expect(b.Bytes()[2:7]).To(Equal([]byte{0xEF, 0xBE, 0xAD, 0xDE, 0x13}))
			})

			It("writes a 6-byte offset if the offset", func() {
				b := &bytes.Buffer{}
				err := (&StreamFrame{
					StreamID: 1,
					Data:     []byte("foobar"),
					Offset:   0xDEADBEEFCAFE,
				}).Write(b, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Bytes()[0] & 0x1c).To(Equal(uint8(0x5 << 2)))
				Expect(b.Bytes()[2:8]).To(Equal([]byte{0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE}))
			})

			It("writes a 7-byte offset if the offset", func() {
				b := &bytes.Buffer{}
				err := (&StreamFrame{
					StreamID: 1,
					Data:     []byte("foobar"),
					Offset:   0x13DEADBEEFCAFE,
				}).Write(b, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Bytes()[0] & 0x1c).To(Equal(uint8(0x6 << 2)))
				Expect(b.Bytes()[2:9]).To(Equal([]byte{0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE, 0x13}))
			})

			It("writes a 8-byte offset if the offset", func() {
				b := &bytes.Buffer{}
				err := (&StreamFrame{
					StreamID: 1,
					Data:     []byte("foobar"),
					Offset:   0x1337DEADBEEFCAFE,
				}).Write(b, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Bytes()[0] & 0x1c).To(Equal(uint8(0x7 << 2)))
				Expect(b.Bytes()[2:10]).To(Equal([]byte{0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE, 0x37, 0x13}))
			})
		})

		Context("lengths of StreamIDs", func() {
			It("writes a 1 byte StreamID", func() {
				b := &bytes.Buffer{}
				err := (&StreamFrame{
					StreamID: 13,
					Data:     []byte("foobar"),
				}).Write(b, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Bytes()[0] & 0x3).To(Equal(uint8(0x0)))
				Expect(b.Bytes()[1]).To(Equal(uint8(13)))
			})

			It("writes a 2 byte StreamID", func() {
				b := &bytes.Buffer{}
				err := (&StreamFrame{
					StreamID: 0xCAFE,
					Data:     []byte("foobar"),
				}).Write(b, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Bytes()[0] & 0x3).To(Equal(uint8(0x1)))
				Expect(b.Bytes()[1:3]).To(Equal([]byte{0xFE, 0xCA}))
			})

			It("writes a 3 byte StreamID", func() {
				b := &bytes.Buffer{}
				err := (&StreamFrame{
					StreamID: 0x13BEEF,
					Data:     []byte("foobar"),
				}).Write(b, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Bytes()[0] & 0x3).To(Equal(uint8(0x2)))
				Expect(b.Bytes()[1:4]).To(Equal([]byte{0xEF, 0xBE, 0x13}))
			})

			It("writes a 4 byte StreamID", func() {
				b := &bytes.Buffer{}
				err := (&StreamFrame{
					StreamID: 0xDECAFBAD,
					Data:     []byte("foobar"),
				}).Write(b, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Bytes()[0] & 0x3).To(Equal(uint8(0x3)))
				Expect(b.Bytes()[1:5]).To(Equal([]byte{0xAD, 0xFB, 0xCA, 0xDE}))
			})

			It("writes a multiple byte StreamID, after the Stream length was already determined by MinLenght()", func() {
				b := &bytes.Buffer{}
				frame := &StreamFrame{
					StreamID: 0xDECAFBAD,
					Data:     []byte("foobar"),
				}
				frame.MinLength(0)
				err := frame.Write(b, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Bytes()[0] & 0x3).To(Equal(uint8(0x3)))
				Expect(b.Bytes()[1:5]).To(Equal([]byte{0xAD, 0xFB, 0xCA, 0xDE}))
			})
		})
	})

	Context("shortening of StreamIDs", func() {
		It("determines the length of a 1 byte StreamID", func() {
			f := &StreamFrame{StreamID: 0xFF}
			Expect(f.calculateStreamIDLength()).To(Equal(uint8(1)))
		})

		It("determines the length of a 2 byte StreamID", func() {
			f := &StreamFrame{StreamID: 0xFFFF}
			Expect(f.calculateStreamIDLength()).To(Equal(uint8(2)))
		})

		It("determines the length of a 3 byte StreamID", func() {
			f := &StreamFrame{StreamID: 0xFFFFFF}
			Expect(f.calculateStreamIDLength()).To(Equal(uint8(3)))
		})

		It("determines the length of a 4 byte StreamID", func() {
			f := &StreamFrame{StreamID: 0xFFFFFFFF}
			Expect(f.calculateStreamIDLength()).To(Equal(uint8(4)))
		})
	})

	Context("shortening of Offsets", func() {
		It("determines length 0 of offset 0", func() {
			f := &StreamFrame{Offset: 0}
			Expect(f.getOffsetLength()).To(Equal(protocol.ByteCount(0)))
		})

		It("determines the length of a 2 byte offset", func() {
			f := &StreamFrame{Offset: 0xFFFF}
			Expect(f.getOffsetLength()).To(Equal(protocol.ByteCount(2)))
		})

		It("determines the length of a 2 byte offset, even if it would fit into 1 byte", func() {
			f := &StreamFrame{Offset: 0x1}
			Expect(f.getOffsetLength()).To(Equal(protocol.ByteCount(2)))
		})

		It("determines the length of a 3 byte offset", func() {
			f := &StreamFrame{Offset: 0xFFFFFF}
			Expect(f.getOffsetLength()).To(Equal(protocol.ByteCount(3)))
		})

		It("determines the length of a 4 byte offset", func() {
			f := &StreamFrame{Offset: 0xFFFFFFFF}
			Expect(f.getOffsetLength()).To(Equal(protocol.ByteCount(4)))
		})

		It("determines the length of a 5 byte offset", func() {
			f := &StreamFrame{Offset: 0xFFFFFFFFFF}
			Expect(f.getOffsetLength()).To(Equal(protocol.ByteCount(5)))
		})

		It("determines the length of a 6 byte offset", func() {
			f := &StreamFrame{Offset: 0xFFFFFFFFFFFF}
			Expect(f.getOffsetLength()).To(Equal(protocol.ByteCount(6)))
		})

		It("determines the length of a 7 byte offset", func() {
			f := &StreamFrame{Offset: 0xFFFFFFFFFFFFFF}
			Expect(f.getOffsetLength()).To(Equal(protocol.ByteCount(7)))
		})

		It("determines the length of an 8 byte offset", func() {
			f := &StreamFrame{Offset: 0xFFFFFFFFFFFFFFFF}
			Expect(f.getOffsetLength()).To(Equal(protocol.ByteCount(8)))
		})
	})

	Context("DataLen", func() {
		It("determines the length of the data", func() {
			frame := StreamFrame{
				Data: []byte("foobar"),
			}
			Expect(frame.DataLen()).To(Equal(protocol.ByteCount(6)))
		})
	})
})
