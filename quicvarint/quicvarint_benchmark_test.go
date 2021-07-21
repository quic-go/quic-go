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

	Context("with type assertion to quicvarint.Reader", func() {
		Measure("reading from a bytes.Reader", func(b Benchmarker) {
			r := bytes.NewReader(data)
			got := make([]uint64, len(values))
			runtime := b.Time("read", func() {
				for i := 0; i < len(values); i++ {
					got[i], _ = Read(r)
				}
			})
			Expect(got).To(Equal(values))

			b.RecordValue("read all (ns)", float64(runtime))
			b.RecordValue("read one (ns)", float64(runtime)/float64(len(values)))
		}, 100)

		Measure("reading from an io.Reader", func(b Benchmarker) {
			r := onlyReader(bytes.NewReader(data).Read)
			got := make([]uint64, len(values))
			runtime := b.Time("read", func() {
				for i := 0; i < len(values); i++ {
					got[i], _ = Read(r)
				}
			})
			Expect(got).To(Equal(values))

			b.RecordValue("read all (ns)", float64(runtime))
			b.RecordValue("read one (ns)", float64(runtime)/float64(len(values)))
		}, 0)
	})

	// Benchmark old version without type assertion
	Context("old Read(io.ByteReader) without type assertion", func() {
		Measure("reading from a bytes.Reader", func(b Benchmarker) {
			r := bytes.NewReader(data)
			got := make([]uint64, len(values))
			runtime := b.Time("read", func() {
				for i := 0; i < len(values); i++ {
					got[i], _ = readFromByteReader(r)
				}
			})
			Expect(got).To(Equal(values))

			b.RecordValue("read all (ns)", float64(runtime))
			b.RecordValue("read one (ns)", float64(runtime)/float64(len(values)))
		}, 100)
	})

	// Benchmark new version without type assertion
	Context("new Read(Reader) without type assertion", func() {
		Measure("reading from a bytes.Reader", func(b Benchmarker) {
			r := bytes.NewReader(data)
			got := make([]uint64, len(values))
			runtime := b.Time("read", func() {
				for i := 0; i < len(values); i++ {
					got[i], _ = readFromQUICVarintReader(r)
				}
			})
			Expect(got).To(Equal(values))

			b.RecordValue("read all (ns)", float64(runtime))
			b.RecordValue("read one (ns)", float64(runtime)/float64(len(values)))
		}, 100)
	})

})

type onlyReader func(p []byte) (int, error)

func (r onlyReader) Read(p []byte) (int, error) {
	return r(p)
}

// Earlier version of Read that accepted an io.ByteReader argument.
// Can be deleted when benchmarks are resolved.
func readFromByteReader(br io.ByteReader) (uint64, error) {
	firstByte, err := br.ReadByte()
	if err != nil {
		return 0, err
	}
	// the first two bits of the first byte encode the length
	len := 1 << ((firstByte & 0xc0) >> 6)
	b1 := firstByte & (0xff - 0xc0)
	if len == 1 {
		return uint64(b1), nil
	}
	b2, err := br.ReadByte()
	if err != nil {
		return 0, err
	}
	if len == 2 {
		return uint64(b2) + uint64(b1)<<8, nil
	}
	b3, err := br.ReadByte()
	if err != nil {
		return 0, err
	}
	b4, err := br.ReadByte()
	if err != nil {
		return 0, err
	}
	if len == 4 {
		return uint64(b4) + uint64(b3)<<8 + uint64(b2)<<16 + uint64(b1)<<24, nil
	}
	b5, err := br.ReadByte()
	if err != nil {
		return 0, err
	}
	b6, err := br.ReadByte()
	if err != nil {
		return 0, err
	}
	b7, err := br.ReadByte()
	if err != nil {
		return 0, err
	}
	b8, err := br.ReadByte()
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
