package http3

import (
	"bytes"
	"io"
	"io/ioutil"

	"github.com/lucas-clemente/quic-go/quicvarint"
)

type frame interface{}

func parseNextFrame(r io.Reader) (frame, error) {
	qr := quicvarint.NewReader(r)
	t, err := quicvarint.Read(qr)
	if err != nil {
		return nil, err
	}
	l, err := quicvarint.Read(qr)
	if err != nil {
		return nil, err
	}

	switch FrameType(t) {
	case FrameTypeData:
		return &dataFrame{Length: l}, nil
	case FrameTypeHeaders:
		return &headersFrame{Length: l}, nil
	case FrameTypeSettings:
		return parseSettingsFramePayload(r, l)
	case FrameTypeCancelPush:
		fallthrough
	case FrameTypePushPromise:
		fallthrough
	case FrameTypeGoAway:
		fallthrough
	case FrameTypeMaxPushID:
		fallthrough
	case FrameTypeDuplicatePush:
		fallthrough
	default:
		// skip over unknown frames
		if _, err := io.CopyN(ioutil.Discard, qr, int64(l)); err != nil {
			return nil, err
		}
		return parseNextFrame(qr)
	}
}

type dataFrame struct {
	Length uint64
}

func (f *dataFrame) Write(b *bytes.Buffer) {
	quicvarint.Write(b, 0x0)
	quicvarint.Write(b, f.Length)
}

type headersFrame struct {
	Length uint64
}

func (f *headersFrame) Write(b *bytes.Buffer) {
	quicvarint.Write(b, 0x1)
	quicvarint.Write(b, f.Length)
}
