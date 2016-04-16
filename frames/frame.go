package frames

import "bytes"

// A Frame in QUIC
type Frame interface {
	Write(b *bytes.Buffer) error
}
