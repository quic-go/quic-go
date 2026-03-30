//go:build go1.25

package handshake

import qtls "github.com/quic-go/quic-go/internal/qtls"

// quicErrorEvent is a sentinel value that never matches any real event kind.
// Our qtls fork does not define QUICErrorEvent, so this is always -1.
const quicErrorEvent qtls.QUICEventKind = -1

func extractQUICEventError(qtls.QUICEvent) error {
	return nil
}
