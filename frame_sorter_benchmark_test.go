package quic

import (
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
)

const (
	benchmarkFrameCount = 256
	benchmarkFrameSize  = 1200
)

func BenchmarkFrameSorterPushOrdered(b *testing.B) {
	payload := make([]byte, benchmarkFrameSize)
	b.ReportAllocs()
	b.SetBytes(int64(benchmarkFrameCount * benchmarkFrameSize))

	for b.Loop() {
		sorter := newFrameSorter()
		for index := range benchmarkFrameCount {
			offset := protocol.ByteCount(index * benchmarkFrameSize)
			if err := sorter.Push(payload, offset, nil); err != nil {
				b.Fatal(err)
			}
			poppedOffset, data, _ := sorter.Pop()
			if poppedOffset != offset || len(data) != benchmarkFrameSize {
				b.Fatalf("popped (%d, %d bytes), expected (%d, %d bytes)", poppedOffset, len(data), offset, benchmarkFrameSize)
			}
		}
	}
}

func BenchmarkFrameSorterPushSlightlyReordered(b *testing.B) {
	payload := make([]byte, benchmarkFrameSize)
	b.ReportAllocs()
	b.SetBytes(int64(benchmarkFrameCount * benchmarkFrameSize))

	for b.Loop() {
		sorter := newFrameSorter()
		for index := 0; index < benchmarkFrameCount; {
			if index%40 == 20 && index+1 < benchmarkFrameCount {
				for _, reordered := range [...]int{index + 1, index} {
					offset := protocol.ByteCount(reordered * benchmarkFrameSize)
					if err := sorter.Push(payload, offset, nil); err != nil {
						b.Fatal(err)
					}
				}
				for expected := index; expected <= index+1; expected++ {
					offset, data, _ := sorter.Pop()
					if offset != protocol.ByteCount(expected*benchmarkFrameSize) || len(data) != benchmarkFrameSize {
						b.Fatalf("popped (%d, %d bytes), expected frame %d", offset, len(data), expected)
					}
				}
				index += 2
				continue
			}
			offset := protocol.ByteCount(index * benchmarkFrameSize)
			if err := sorter.Push(payload, offset, nil); err != nil {
				b.Fatal(err)
			}
			poppedOffset, data, _ := sorter.Pop()
			if poppedOffset != offset || len(data) != benchmarkFrameSize {
				b.Fatalf("popped (%d, %d bytes), expected (%d, %d bytes)", poppedOffset, len(data), offset, benchmarkFrameSize)
			}
			index++
		}
	}
}

func BenchmarkFrameSorterPushReordered(b *testing.B) {
	payload := make([]byte, benchmarkFrameSize)
	b.ReportAllocs()
	b.SetBytes(int64(benchmarkFrameCount * benchmarkFrameSize))

	for b.Loop() {
		sorter := newFrameSorter()
		var callbacks int
		callback := func() { callbacks++ }
		for windowStart := 0; windowStart < benchmarkFrameCount; windowStart += 32 {
			for index := windowStart + 16; index < windowStart+32; index++ {
				offset := protocol.ByteCount(index * benchmarkFrameSize)
				if err := sorter.Push(payload, offset, callback); err != nil {
					b.Fatal(err)
				}
			}
			for index := windowStart; index < windowStart+16; index++ {
				offset := protocol.ByteCount(index * benchmarkFrameSize)
				if err := sorter.Push(payload, offset, callback); err != nil {
					b.Fatal(err)
				}
			}
			for index := windowStart; index < windowStart+32; index++ {
				expectedOffset := protocol.ByteCount(index * benchmarkFrameSize)
				poppedOffset, data, done := sorter.Pop()
				if poppedOffset != expectedOffset || len(data) != benchmarkFrameSize || done == nil {
					b.Fatalf("popped (%d, %d bytes), expected (%d, %d bytes)", poppedOffset, len(data), expectedOffset, benchmarkFrameSize)
				}
				done()
			}
		}
		if callbacks != benchmarkFrameCount {
			b.Fatalf("callbacks = %d, expected %d", callbacks, benchmarkFrameCount)
		}
	}
}

func BenchmarkFrameSorterPushManyGaps(b *testing.B) {
	separator := make([]byte, benchmarkFrameSize)
	partial := make([]byte, benchmarkFrameSize/2)
	b.ReportAllocs()
	b.SetBytes(int64(benchmarkFrameCount * (len(separator) + len(partial))))

	for b.Loop() {
		sorter := newFrameSorter()
		for index := range benchmarkFrameCount {
			offset := protocol.ByteCount((2*index + 1) * benchmarkFrameSize)
			if err := sorter.Push(separator, offset, nil); err != nil {
				b.Fatal(err)
			}
		}
		for index := range benchmarkFrameCount {
			offset := protocol.ByteCount(2 * index * benchmarkFrameSize)
			if err := sorter.Push(partial, offset, nil); err != nil {
				b.Fatal(err)
			}
		}
		if sorter.gaps.Len() != benchmarkFrameCount+1 {
			b.Fatalf("gap count = %d, want %d", sorter.gaps.Len(), benchmarkFrameCount+1)
		}
	}
}

func BenchmarkFrameSorterPushMaxGaps(b *testing.B) {
	payload := make([]byte, 6)
	b.ReportAllocs()
	b.SetBytes(int64(protocol.MaxStreamFrameSorterGaps * len(payload)))

	for b.Loop() {
		sorter := newFrameSorter()
		for index := range protocol.MaxStreamFrameSorterGaps {
			offset := protocol.ByteCount(index * 7)
			if err := sorter.Push(payload, offset, nil); err != nil {
				b.Fatal(err)
			}
		}
		if sorter.gaps.Len() != protocol.MaxStreamFrameSorterGaps {
			b.Fatalf("gap count = %d, want %d", sorter.gaps.Len(), protocol.MaxStreamFrameSorterGaps)
		}
	}
}

func BenchmarkFrameSorterPushMaxGapsShuffled(b *testing.B) {
	payload := make([]byte, 6)
	b.ReportAllocs()
	b.SetBytes(int64(protocol.MaxStreamFrameSorterGaps * len(payload)))

	for b.Loop() {
		sorter := newFrameSorter()
		for index := range protocol.MaxStreamFrameSorterGaps {
			permuted := index * 499 % protocol.MaxStreamFrameSorterGaps
			offset := protocol.ByteCount(permuted * 7)
			if err := sorter.Push(payload, offset, nil); err != nil {
				b.Fatal(err)
			}
		}
		if sorter.gaps.Len() != protocol.MaxStreamFrameSorterGaps {
			b.Fatalf("gap count = %d, want %d", sorter.gaps.Len(), protocol.MaxStreamFrameSorterGaps)
		}
	}
}
