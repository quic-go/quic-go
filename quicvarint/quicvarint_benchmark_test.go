package quicvarint

import (
	"bytes"
	"io"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Benchmarks", func() {
	values := []uint64{
		0,
		1,
		maxVarInt1,
		maxVarInt2,
		maxVarInt4,
		maxVarInt8,
		maxVarInt1 - 1,
		maxVarInt2 - 1,
		maxVarInt4 - 1,
		maxVarInt8 - 1,
	}

	const pow = 5
	for i := 0; i < pow; i++ {
		values = append(values, values...)
	}

	buf := &bytes.Buffer{}
	for _, v := range values {
		Write(buf, v)
	}

	data := buf.Bytes()[:]

	Context("Read", func() {
		Measure("reading from a bytes.Reader", func(b Benchmarker) {
			r := bytes.NewReader(data)
			got := make([]uint64, len(values))
			runtime := b.Time("read", func() {
				for i := 0; i < len(values); i++ {
					got[i], _ = Read(r)
				}
			})
			Expect(got).To(Equal(values))

			b.RecordValue("read one (ns)", float64(runtime)/float64(len(values)))
			b.RecordValue("read all (ns)", float64(runtime))
		}, 100)
	})

	Context("Read(io.ByteReader) without type assertion", func() {
		Measure("reading from a bytes.Reader", func(b Benchmarker) {
			r := bytes.NewReader(data)
			got := make([]uint64, len(values))
			runtime := b.Time("read", func() {
				for i := 0; i < len(values); i++ {
					got[i], _ = readFromByteReader(r)
				}
			})
			Expect(got).To(Equal(values))

			b.RecordValue("read one (ns)", float64(runtime)/float64(len(values)))
			b.RecordValue("read all (ns)", float64(runtime))
		}, 100)
	})

	Context("Read(Reader) without type assertion", func() {
		Measure("reading from a bytes.Reader", func(b Benchmarker) {
			r := bytes.NewReader(data)
			got := make([]uint64, len(values))
			runtime := b.Time("read", func() {
				for i := 0; i < len(values); i++ {
					got[i], _ = readFromQUICVarintReader(r)
				}
			})
			Expect(got).To(Equal(values))

			b.RecordValue("read one (ns)", float64(runtime)/float64(len(values)))
			b.RecordValue("read all (ns)", float64(runtime))
		}, 100)
	})

	Context("Read(io.Reader) using Read", func() {
		Measure("reading from an io.Reader", func(b Benchmarker) {
			r := bytes.NewReader(data)
			got := make([]uint64, len(values))
			runtime := b.Time("read", func() {
				for i := 0; i < len(values); i++ {
					got[i], _ = readFromIOReader(r)
				}
			})
			Expect(got).To(Equal(values))

			b.RecordValue("read one (ns)", float64(runtime)/float64(len(values)))
			b.RecordValue("read all (ns)", float64(runtime))
		}, 100)
	})

	Context("Read(io.Reader) with type assertion", func() {
		Measure("reading from an io.Reader", func(b Benchmarker) {
			r := bytes.NewReader(data)
			got := make([]uint64, len(values))
			runtime := b.Time("read", func() {
				for i := 0; i < len(values); i++ {
					got[i], _ = readFromIOReaderWithTypeAssertion(r)
				}
			})
			Expect(got).To(Equal(values))

			b.RecordValue("read one (ns)", float64(runtime)/float64(len(values)))
			b.RecordValue("read all (ns)", float64(runtime))
		}, 100)
	})
})

func readFromByteReader(r io.ByteReader) (uint64, error) {
	firstByte, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	// the first two bits of the first byte encode the length
	len := 1 << ((firstByte & 0xc0) >> 6)
	b1 := firstByte & (0xff - 0xc0)
	if len == 1 {
		return uint64(b1), nil
	}
	b2, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if len == 2 {
		return uint64(b2) + uint64(b1)<<8, nil
	}
	b3, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b4, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if len == 4 {
		return uint64(b4) + uint64(b3)<<8 + uint64(b2)<<16 + uint64(b1)<<24, nil
	}
	b5, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b6, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b7, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b8, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	return uint64(b8) + uint64(b7)<<8 + uint64(b6)<<16 + uint64(b5)<<24 + uint64(b4)<<32 + uint64(b3)<<40 + uint64(b2)<<48 + uint64(b1)<<56, nil
}

func readFromQUICVarintReader(r Reader) (uint64, error) {
	firstByte, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	// the first two bits of the first byte encode the length
	len := 1 << ((firstByte & 0xc0) >> 6)
	b1 := firstByte & (0xff - 0xc0)
	if len == 1 {
		return uint64(b1), nil
	}
	b2, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if len == 2 {
		return uint64(b2) + uint64(b1)<<8, nil
	}
	b3, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b4, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if len == 4 {
		return uint64(b4) + uint64(b3)<<8 + uint64(b2)<<16 + uint64(b1)<<24, nil
	}
	b5, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b6, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b7, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b8, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	return uint64(b8) + uint64(b7)<<8 + uint64(b6)<<16 + uint64(b5)<<24 + uint64(b4)<<32 + uint64(b3)<<40 + uint64(b2)<<48 + uint64(b1)<<56, nil
}

func readFromIOReader(r io.Reader) (uint64, error) {
	var b [8]byte
	_, err := r.Read(b[:1])
	if err != nil {
		return 0, err
	}
	// the first two bits of the first byte encode the length
	len := 1 << ((b[0] & 0xc0) >> 6)
	b0 := b[0] & (0xff - 0xc0)
	if len == 1 {
		return uint64(b0), nil
	}
	_, err = io.ReadAtLeast(r, b[1:len], len-1)
	if err != nil {
		return 0, err
	}
	if len == 2 {
		return uint64(b[1]) + uint64(b0)<<8, nil
	}
	if len == 4 {
		return uint64(b[3]) + uint64(b[2])<<8 + uint64(b[1])<<16 + uint64(b0)<<24, nil
	}
	return uint64(b[7]) + uint64(b[6])<<8 + uint64(b[5])<<16 + uint64(b[4])<<24 + uint64(b[3])<<32 + uint64(b[2])<<40 + uint64(b[1])<<48 + uint64(b0)<<56, nil
}

func readFromIOReaderWithTypeAssertion(r io.Reader) (uint64, error) {
	qr := NewReader(r)
	firstByte, err := qr.ReadByte()
	if err != nil {
		return 0, err
	}
	// the first two bits of the first byte encode the length
	len := 1 << ((firstByte & 0xc0) >> 6)
	b1 := firstByte & (0xff - 0xc0)
	if len == 1 {
		return uint64(b1), nil
	}
	b2, err := qr.ReadByte()
	if err != nil {
		return 0, err
	}
	if len == 2 {
		return uint64(b2) + uint64(b1)<<8, nil
	}
	b3, err := qr.ReadByte()
	if err != nil {
		return 0, err
	}
	b4, err := qr.ReadByte()
	if err != nil {
		return 0, err
	}
	if len == 4 {
		return uint64(b4) + uint64(b3)<<8 + uint64(b2)<<16 + uint64(b1)<<24, nil
	}
	b5, err := qr.ReadByte()
	if err != nil {
		return 0, err
	}
	b6, err := qr.ReadByte()
	if err != nil {
		return 0, err
	}
	b7, err := qr.ReadByte()
	if err != nil {
		return 0, err
	}
	b8, err := qr.ReadByte()
	if err != nil {
		return 0, err
	}
	return uint64(b8) + uint64(b7)<<8 + uint64(b6)<<16 + uint64(b5)<<24 + uint64(b4)<<32 + uint64(b3)<<40 + uint64(b2)<<48 + uint64(b1)<<56, nil
}
