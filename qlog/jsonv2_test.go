package qlog

import (
	"bytes"
	"encoding/json/jsontext"
	"testing"

	"github.com/quic-go/quic-go/logging"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/francoispqt/gojay"
)

var longHdr = transformLongHeader(&wire.ExtendedHeader{
	PacketNumber: 4242,
	Header: wire.Header{
		Type:             protocol.PacketTypeInitial,
		DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7}),
		SrcConnectionID:  protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		Length:           123,
		Version:          protocol.Version(0xdecafbad),
		Token:            []byte{0xde, 0xad, 0xbe, 0xef},
	},
})

var rst = &logging.ResetStreamFrame{
	StreamID:  1337,
	FinalSize: 424242,
	ErrorCode: 1234,
}

func BenchmarkJSONv2(b *testing.B) {
	buf := bytes.NewBuffer(make([]byte, 0, 1024))
	enc := jsontext.NewEncoder(buf)

	b.Run("packet header", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			longHdr.MarshalJSONv2(enc)
			buf.Reset()
		}
	})

	b.Run("RESET_STREAM frame", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			(frame{rst}).MarshalJSONv2(enc)
			buf.Reset()
		}
	})
}

func BenchmarkGojay(b *testing.B) {
	buf := bytes.NewBuffer(make([]byte, 0, 1024))
	enc := gojay.NewEncoder(buf)

	b.Run("packet header", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			enc.Encode(longHdr)
			buf.Reset()
		}
	})

	b.Run("RESET_STREAM frame", func(b *testing.B) {
		f := frame{rst}
		for i := 0; i < b.N; i++ {
			enc.Encode(f)
			buf.Reset()
		}
	})
}
