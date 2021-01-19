package qlogcompress

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"math/rand"
	"testing"
	"time"

	"github.com/andybalholm/brotli"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/lucas-clemente/quic-go/qlog"
)

var (
	now = time.Now()
	ack = &wire.AckFrame{
		AckRanges: []wire.AckRange{{10, 20}, {1, 4}},
		DelayTime: time.Second,
	}
)

type bufferedWriteCloser struct {
	*bufio.Writer
	io.Closer
}

func newBufferedWriteCloser(writer *bufio.Writer, closer io.Closer) io.WriteCloser {
	return &bufferedWriteCloser{
		Writer: writer,
		Closer: closer,
	}
}

func (h bufferedWriteCloser) Close() error {
	if err := h.Writer.Flush(); err != nil {
		return err
	}
	return h.Closer.Close()
}

func getQlogger(getWriter func(io.Writer) io.WriteCloser) (logging.ConnectionTracer, *bytes.Buffer) {
	buf := bytes.NewBuffer(make([]byte, 0, 100*1<<20))
	var used bool
	tracer := qlog.NewTracer(func(perspective logging.Perspective, connID []byte) io.WriteCloser {
		if used {
			panic("reuse")
		}
		gz := getWriter(buf)
		return newBufferedWriteCloser(bufio.NewWriter(gz), gz)
	})
	return tracer.TracerForConnection(logging.PerspectiveClient, []byte("foobar")), buf
}

func getHdr() *wire.ExtendedHeader {
	hdr := &wire.ExtendedHeader{
		Header: wire.Header{
			IsLongHeader:    rand.Int()%2 == 0,
			Type:            protocol.PacketTypeHandshake,
			Version:         protocol.VersionNumber(rand.Int()),
			SrcConnectionID: protocol.ConnectionID{1, 2, 3, 4},
			Length:          protocol.ByteCount(rand.Int()),
		},
		KeyPhase:        protocol.KeyPhaseZero,
		PacketNumberLen: 1 + protocol.PacketNumberLen(rand.Int()%4),
		PacketNumber:    protocol.PacketNumber(rand.Int()),
	}
	return hdr
}

func getFrames() []logging.Frame {
	return []logging.Frame{
		&logging.StreamFrame{
			StreamID: protocol.StreamID(rand.Int()),
			Offset:   protocol.ByteCount(rand.Int()),
			Length:   protocol.ByteCount(rand.Int()),
		},
		&logging.MaxDataFrame{MaximumData: protocol.ByteCount(rand.Int())},
	}
}

type getWriterFunc func(io.Writer) io.WriteCloser

func getGzipper(w io.Writer) io.WriteCloser {
	return gzip.NewWriter(w)
}

func getZstder(w io.Writer) io.WriteCloser {
	c, err := zstd.NewWriter(w, zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		panic(err)
	}
	return c
}

func getLz4er(w io.Writer) io.WriteCloser {
	return lz4.NewWriter(w)
}

func getBrotli(w io.Writer) io.WriteCloser {
	return brotli.NewWriter(w)
}

func runBenchmark(N int, gwf getWriterFunc) []byte {
	l, data := getQlogger(gwf)
	for i := 0; i < N; i++ {
		l.SetLossTimer(logging.TimerTypeACK, logging.Encryption0RTT, now)
		l.SentPacket(getHdr(), 1234, ack, getFrames())
	}
	l.Close()
	return data.Bytes()
}

func BenchmarkGzip(b *testing.B) {
	runBenchmark(b.N, getGzipper)
}

func BenchmarkZstd(b *testing.B) {
	runBenchmark(b.N, getZstder)
}

func BenchmarkLz4(b *testing.B) {
	runBenchmark(b.N, getLz4er)
}

func BenchmarkBrotli(b *testing.B) {
	runBenchmark(b.N, getBrotli)
}

func TestCalibrate(t *testing.T) {
	const num = 100
	fmt.Println("gzip:")
	data := runBenchmark(num, getGzipper)
	fmt.Println(len(data))
	fmt.Println("zstd:")
	data = runBenchmark(num, getZstder)
	fmt.Println(len(data))
	fmt.Println("lz4")
	data = runBenchmark(num, getLz4er)
	fmt.Println(len(data))
	fmt.Println("brotli")
	data = runBenchmark(num, getBrotli)
	fmt.Println(len(data))
}
