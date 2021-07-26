package http3

import (
	"bytes"
	"fmt"
	"io"
	"sort"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/quicvarint"
)

const (
	// https://www.ietf.org/archive/id/draft-ietf-masque-h3-datagram-02.html#name-http-settings-parameter
	SettingDatagram = 0xffd276

	// https://datatracker.ietf.org/doc/draft-ietf-masque-h3-datagram/00/
	SettingDatagramDraft00 = 0x276
)

type Setting uint64

func (s Setting) String() string {
	switch s {
	case SettingDatagram:
		return "H3_DATAGRAM"
	default:
		return fmt.Sprintf("H3 setting 0x%x", uint64(s))
	}
}

type Settings map[Setting]uint64

func (s Settings) FrameType() FrameType {
	return FrameTypeSettings
}

func (s Settings) FrameLength() protocol.ByteCount {
	var len protocol.ByteCount
	for id, val := range s {
		len += quicvarint.Len(uint64(id)) + quicvarint.Len(val)
	}
	return len
}

func (s Settings) WriteFrame(w io.Writer) error {
	qw := quicvarint.NewWriter(w)
	quicvarint.Write(qw, uint64(s.FrameType()))
	quicvarint.Write(qw, uint64(s.FrameLength()))
	ids := make([]Setting, 0, len(s))
	for id := range s {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return i < j })
	for _, id := range ids {
		quicvarint.Write(qw, uint64(id))
		quicvarint.Write(qw, s[id])
	}
	return nil
}

func (sp *Settings) UnmarshalFrame(b []byte) error {
	if len(b) > 8*(1<<10) {
		return fmt.Errorf("unexpected size for SETTINGS frame: %d", len(b))
	}
	s := Settings{}
	r := bytes.NewReader(b)
	for r.Len() > 0 {
		id, err := quicvarint.Read(r)
		if err != nil { // should not happen. We allocated the whole frame already.
			return err
		}
		val, err := quicvarint.Read(r)
		if err != nil { // should not happen. We allocated the whole frame already.
			return err
		}

		if _, ok := s[Setting(id)]; ok {
			return fmt.Errorf("duplicate setting: %d", id)
		}
		s[Setting(id)] = val
	}
	*sp = s
	return nil
}

func ReadSettingsFrame(r io.Reader, l uint64) (Settings, error) {
	if l > 8*(1<<10) {
		return nil, fmt.Errorf("unexpected size for SETTINGS frame: %d", l)
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, io.EOF
		}
		return nil, err
	}
	s := Settings{}
	err := s.UnmarshalFrame(buf)
	return s, err
}
