package http3

import (
	"github.com/lucas-clemente/quic-go/quicvarint"
)

const (
	greaseMaxN = (quicvarint.Max - 0x21) / 0x1f

	// GreaseMax is the largest HTTP/3 greasing value that will fit in a quicvarint.
	// See https://quicwg.org/base-drafts/draft-ietf-quic-http.html#section-6.2.3.
	GreaseMax = 0x1f*greaseMaxN + 0x21
	GreaseMin = 0x1f*0 + 0x21
)

// Grease returns a value that can be used for generating ignored HTTP/3 stream types or frames.
// See https://quicwg.org/base-drafts/draft-ietf-quic-http.html#name-reserved-frame-types
// and https://datatracker.ietf.org/doc/html/draft-nottingham-http-grease-00.
func Grease(n uint64) uint64 {
	if n > greaseMaxN {
		n = greaseMaxN
	}
	return 0x1f*n + 0x21
}
