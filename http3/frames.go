package http3

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/quicvarint"
)

// FrameType is the frame type of a HTTP/3 frame
type FrameType uint64

const (
	// dataFrameType is the type of the DATA frame.
	//
	// See https://quicwg.org/base-drafts/draft-ietf-quic-http.html#name-data
	dataFrameType = 0x00

	// headersFrameType is the type of the HEADERS frame.
	//
	// See https://quicwg.org/base-drafts/draft-ietf-quic-http.html#name-headers
	headersFrameType = 0x01

	// cancelPushFrameType is the type of the CANCEL_PUSH frame.
	//
	// See https://quicwg.org/base-drafts/draft-ietf-quic-http.html#name-cancel_push
	cancelPushFrameType = 0x03

	// settingsFrameType is the type of the SETTINGS frame.
	//
	// See https://quicwg.org/base-drafts/draft-ietf-quic-http.html#name-settings
	settingsFrameType = 0x04

	// pushPromiseFrameType is the type of the PUSH_PROMISE frame.
	//
	// See https://quicwg.org/base-drafts/draft-ietf-quic-http.html#name-push_promise
	pushPromiseFrameType = 0x05

	// goawayFrameType is the type of the GOAWAY frame.
	//
	// See https://quicwg.org/base-drafts/draft-ietf-quic-http.html#name-goaway
	goawayFrameType = 0x07

	// maxPushIDFrameType is the type of the MAX_PUSH_ID frame.
	//
	// See https://quicwg.org/base-drafts/draft-ietf-quic-http.html#name-max_push_id
	maxPushIDFrameType = 0x0d
)

type unknownFrameHandlerFunc func(FrameType) (processed bool, err error)

type frame interface {
	frame()
}

var errHijacked = errors.New("hijacked")

func parseNextFrame(r io.Reader, unknownFrameHandler unknownFrameHandlerFunc) (frame, error) {
	qr := quicvarint.NewReader(r)
	for {
		t, err := quicvarint.Read(qr)
		if err != nil {
			return nil, err
		}
		// Call the unknownFrameHandler for frames not defined in the HTTP/3 spec
		if t > 0xd && unknownFrameHandler != nil {
			hijacked, err := unknownFrameHandler(FrameType(t))
			if err != nil {
				return nil, err
			}
			// If the unknownFrameHandler didn't process the frame, it is our responsibility to skip it.
			if hijacked {
				return nil, errHijacked
			}
			continue
		}
		l, err := quicvarint.Read(qr)
		if err != nil {
			return nil, err
		}

		switch t {
		case dataFrameType:
			return &dataFrame{Length: l}, nil
		case headersFrameType:
			return &headersFrame{Length: l}, nil
		case cancelPushFrameType:
			return parseCancelPushFrame(r, l)
		case settingsFrameType:
			return parseSettingsFrame(r, l)
		case pushPromiseFrameType:
			return parsePushPromiseFrame(r, l)
		case goawayFrameType:
			return parseGoawayFrame(r, l)
		case maxPushIDFrameType:
			return parseMaxPushIDFrame(r, l)
		}

		// Skip over unsupported or reserved frames.
		if err := skipFramePayload(qr, l); err != nil {
			return nil, err
		}
	}
}

type dataFrame struct {
	Length uint64
}

func (f *dataFrame) Write(b *bytes.Buffer) {
	quicvarint.Write(b, dataFrameType)
	quicvarint.Write(b, f.Length)
}

func (f *dataFrame) frame() {}

type headersFrame struct {
	Length uint64
}

func (f *headersFrame) Write(b *bytes.Buffer) {
	quicvarint.Write(b, headersFrameType)
	quicvarint.Write(b, f.Length)
}

func (f *headersFrame) frame() {}

// cancelPushFrame represents the CANCEL_PUSH frame.
//
// See https://quicwg.org/base-drafts/draft-ietf-quic-http.html#name-cancel_push
//
// TODO: currently not implemented.
type cancelPushFrame struct{}

// parseCancelPushFrame parses the cancelPushFrame of size l from r.
func parseCancelPushFrame(r io.Reader, l uint64) (*pushPromiseFrame, error) {
	if err := skipFramePayload(r, l); err != nil {
		return nil, err
	}
	return &pushPromiseFrame{}, nil
}

func (f *cancelPushFrame) frame() {}

const settingDatagram = 0xffd277

type settingsFrame struct {
	Datagram bool
	Other    map[uint64]uint64 // all settings that we don't explicitly recognize
}

func parseSettingsFrame(r io.Reader, l uint64) (*settingsFrame, error) {
	if l > 8*(1<<10) {
		return nil, fmt.Errorf("unexpected size for SETTINGS frame: %d", l)
	}

	b, err := readFramePayload(r, l)
	if err != nil {
		return nil, err
	}

	frame := &settingsFrame{}

	var readDatagram bool
	for b.Len() > 0 {
		id, err := quicvarint.Read(b)
		if err != nil { // should not happen. We allocated the whole frame already.
			return nil, err
		}
		val, err := quicvarint.Read(b)
		if err != nil { // should not happen. We allocated the whole frame already.
			return nil, err
		}

		switch id {
		case settingDatagram:
			if readDatagram {
				return nil, fmt.Errorf("duplicate setting: %d", id)
			}
			readDatagram = true
			if val != 0 && val != 1 {
				return nil, fmt.Errorf("invalid value for H3_DATAGRAM: %d", val)
			}
			frame.Datagram = val == 1
		default:
			if _, ok := frame.Other[id]; ok {
				return nil, fmt.Errorf("duplicate setting: %d", id)
			}
			if frame.Other == nil {
				frame.Other = make(map[uint64]uint64)
			}
			frame.Other[id] = val
		}
	}

	return frame, nil
}

func (f *settingsFrame) Write(b *bytes.Buffer) {
	quicvarint.Write(b, settingsFrameType)
	var l protocol.ByteCount
	for id, val := range f.Other {
		l += quicvarint.Len(id) + quicvarint.Len(val)
	}
	if f.Datagram {
		l += quicvarint.Len(settingDatagram) + quicvarint.Len(1)
	}
	quicvarint.Write(b, uint64(l))
	if f.Datagram {
		quicvarint.Write(b, settingDatagram)
		quicvarint.Write(b, 1)
	}
	for id, val := range f.Other {
		quicvarint.Write(b, id)
		quicvarint.Write(b, val)
	}
}

func (f *settingsFrame) frame() {}

// pushPromiseFrame represents the PUSH_PROMISE frame.
//
// See https://quicwg.org/base-drafts/draft-ietf-quic-http.html#name-push_promise
//
// TODO: currently not implemented.
type pushPromiseFrame struct{}

// parsePushPromiseFrame parses the pushPromiseFrame of size l from r.
func parsePushPromiseFrame(r io.Reader, l uint64) (*pushPromiseFrame, error) {
	if err := skipFramePayload(r, l); err != nil {
		return nil, err
	}
	return &pushPromiseFrame{}, nil
}

func (f *pushPromiseFrame) frame() {}

// goawayFrame represents the GOAWAY frame.
//
// See https://quicwg.org/base-drafts/draft-ietf-quic-http.html#name-goaway
type goawayFrame struct {
	StreamID protocol.StreamID
}

// parseGoawayFrame parses the goawayFrame of size l from r.
func parseGoawayFrame(r io.Reader, l uint64) (*goawayFrame, error) {
	b, err := readFramePayload(r, l)
	if err != nil {
		return nil, err
	}

	streamID, err := quicvarint.Read(b)
	if err != nil {
		return nil, err
	}

	return &goawayFrame{
		StreamID: protocol.StreamID(streamID),
	}, nil
}

// Write encodes the GOAWAY frame to the given buffer.
func (f *goawayFrame) Write(b *bytes.Buffer) {
	quicvarint.Write(b, goawayFrameType)
	quicvarint.Write(b, uint64(quicvarint.Len(uint64(f.StreamID))))
	quicvarint.Write(b, uint64(f.StreamID))
}

func (f *goawayFrame) frame() {}

// maxPushIDFrame represents the MAX_PUSH_ID frame.
//
// See https://quicwg.org/base-drafts/draft-ietf-quic-http.html#name-max_push_id
//
// TODO: parsing is currently not implemented.
type maxPushIDFrame struct{}

// parseMaxPushIDFrame parses the maxPushIDFrame of size l from r.
func parseMaxPushIDFrame(r io.Reader, l uint64) (*maxPushIDFrame, error) {
	if err := skipFramePayload(r, l); err != nil {
		return nil, err
	}
	return &maxPushIDFrame{}, nil
}

func (f *maxPushIDFrame) frame() {}

// readFramePayload reads l fram payload bytes from r.
func readFramePayload(r io.Reader, l uint64) (*bytes.Buffer, error) {
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, io.EOF
		}
		return nil, err
	}
	return bytes.NewBuffer(buf), nil
}

// skipFramePayload discards l frame payload bytes from r.
func skipFramePayload(r io.Reader, l uint64) error {
	_, err := io.CopyN(ioutil.Discard, r, int64(l))
	return err
}
