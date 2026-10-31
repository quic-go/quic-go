package http3

import (
	"testing"

	"github.com/quic-go/quic-go/http3/qlog"

	"github.com/stretchr/testify/require"
)

func TestQlogHeaderField(t *testing.T) {
	for _, f := range []qlog.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: "text/html"},
		{Name: "x-opaque", Value: "\xff"}, // obs-text is allowed
		{Name: "Content-Type", Value: "text/html", InvalidName: true},
		{Name: "bad name", Value: "ok", InvalidName: true},
		{Name: ":", Value: "ok", InvalidName: true},
		{Name: "x-example", Value: "a\r\nb", InvalidValue: true},
	} {
		require.Equal(t, f, qlogHeaderField(f.Name, f.Value), "%q: %q", f.Name, f.Value)
	}
}
