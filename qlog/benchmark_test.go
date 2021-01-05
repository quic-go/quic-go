package qlog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/francoispqt/gojay"

	"github.com/lucas-clemente/quic-go/logging"
)

var ack = &logging.AckFrame{
	DelayTime: 12345 * time.Microsecond,
	AckRanges: []logging.AckRange{{Smallest: 1, Largest: 10}, {Smallest: 12, Largest: 20}},
}

var sf = &logging.StreamFrame{
	StreamID: 1337,
	Offset:   123456,
	Length:   42,
}

func BenchmarkAckFrameGojay(b *testing.B) {
	buf := bytes.NewBuffer(make([]byte, 0, 1<<15))
	enc := gojay.NewEncoder(buf)
	for i := 0; i < b.N; i++ {
		f := &frame{Frame: ack}
		if err := enc.Encode(f); err != nil {
			panic(err)
		}
		buf.Reset()
	}
}

func BenchmarkAckFrameStdlib(b *testing.B) {
	buf := bytes.NewBuffer(make([]byte, 1<<15))
	for i := 0; i < b.N; i++ {
		f := toAckFrame(ack)
		enc := json.NewEncoder(buf)
		enc.Encode(f)
		buf.Reset()
	}
}

func BenchmarkAckFrameCustom(b *testing.B) {
	buf := make([]byte, 0, 1<<15)
	for i := 0; i < b.N; i++ {
		buf = encodeAckFrame(buf, ack)
		buf = buf[:0]
	}
}

func BenchmarkStreamFrameGojay(b *testing.B) {
	buf := bytes.NewBuffer(make([]byte, 0, 1<<15))
	enc := gojay.NewEncoder(buf)
	for i := 0; i < b.N; i++ {
		f := &frame{Frame: sf}
		if err := enc.Encode(f); err != nil {
			panic(err)
		}
		buf.Reset()
	}
}

func BenchmarkStreamFrameStdlib(b *testing.B) {
	buf := bytes.NewBuffer(make([]byte, 1<<15))
	for i := 0; i < b.N; i++ {
		f := toStreamFrame(sf)
		enc := json.NewEncoder(buf)
		enc.Encode(f)
		buf.Reset()
	}
}

func TestEncodeAckFrameStdlib(t *testing.T) {
	buf := bytes.NewBuffer(make([]byte, 0, 1<<15))
	f := toAckFrame(ack)
	enc := json.NewEncoder(buf)
	enc.Encode(f)
	fmt.Println(buf.String())
}

func TestEncodeAckFrameGoJay(t *testing.T) {
	buf := bytes.NewBuffer(make([]byte, 0, 1<<15))
	enc := gojay.NewEncoder(buf)
	f := &frame{Frame: ack}
	if err := enc.Encode(f); err != nil {
		panic(err)
	}
	fmt.Println(buf.String())
}

func TestEncodeAckFrameCustom(t *testing.T) {
	b := make([]byte, 0, 1<<15)
	b = encodeAckFrame(b, ack)
	fmt.Println(string(b))
}
