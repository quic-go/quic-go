package http3

import (
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
		return &dataFrame{len: l}, nil
	case FrameTypeHeaders:
		return &headersFrame{len: l}, nil
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
	len uint64
}

func (f *dataFrame) writeFrame(w quicvarint.Writer) {
	quicvarint.Write(w, 0x0)
	quicvarint.Write(w, f.len)
}

type headersFrame struct {
	len uint64
}

func (f *headersFrame) writeFrame(w quicvarint.Writer) {
	quicvarint.Write(w, 0x1)
	quicvarint.Write(w, f.len)
}
