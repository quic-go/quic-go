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

// A Setting represents an individual HTTP/3 setting identifier.
type Setting uint64

func (s Setting) String() string {
	switch s {
	case SettingDatagram:
		return "H3_DATAGRAM"
	default:
		return fmt.Sprintf("H3 setting 0x%x", uint64(s))
	}
}

// Settings represent HTTP/3 settings, which convey configuration parameters that
// affect how endpoints communicate, such as preferences and constraints on peer behavior.
// SETTINGS frames always apply to an entire HTTP/3 connection, never a single stream.
// A SETTINGS frame MUST be sent as the first frame of each control stream by each peer,
// and MUST NOT be sent subsequently.
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

func (s Settings) Write(w quicvarint.Writer) error {
	quicvarint.Write(w, uint64(s.FrameType()))
	quicvarint.Write(w, uint64(s.FrameLength()))
	ids := make([]Setting, 0, len(s))
	for id := range s {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return i < j })
	for _, id := range ids {
		quicvarint.Write(w, uint64(id))
		quicvarint.Write(w, s[id])
	}
	return nil
}

func parseSettingsFramePayload(r io.Reader, len uint64) (Settings, error) {
	if len > 8*(1<<10) {
		return nil, fmt.Errorf("unexpected size for SETTINGS frame: %d", len)
	}
	b := make([]byte, len)
	if _, err := io.ReadFull(r, b); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, io.EOF
		}
		return nil, err
	}
	s := Settings{}
	br := bytes.NewReader(b)
	for br.Len() > 0 {
		id, err := quicvarint.Read(br)
		if err != nil { // should not happen. We allocated the whole frame already.
			return nil, err
		}
		val, err := quicvarint.Read(br)
		if err != nil { // should not happen. We allocated the whole frame already.
			return nil, err
		}

		if _, ok := s[Setting(id)]; ok {
			return nil, fmt.Errorf("duplicate setting: %d", id)
		}
		s[Setting(id)] = val
	}
	return s, nil
}
