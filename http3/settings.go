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
	SettingQPACKMaxTableCapacity SettingID = 0x01
	SettingMaxFieldSectionSize   SettingID = 0x06
	SettingQPACKBlockedStreams   SettingID = 0x07

	// https://www.ietf.org/archive/id/draft-ietf-masque-h3-datagram-02.html#section-10.2
	SettingDatagram SettingID = 0xffd276

	// https://datatracker.ietf.org/doc/draft-ietf-masque-h3-datagram/00/
	SettingDatagramDraft00 SettingID = 0x276

	// https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-01.html#section-7.2
	SettingWebTransport SettingID = 0x2b603742
)

// A SettingID represents an individual HTTP/3 setting identifier.
type SettingID uint64

func (id SettingID) String() string {
	switch id {
	case SettingQPACKMaxTableCapacity:
		return "QPACK_MAX_TABLE_CAPACITY"
	case SettingMaxFieldSectionSize:
		return "MAX_FIELD_SECTION_SIZE"
	case SettingQPACKBlockedStreams:
		return "QPACK_BLOCKED_STREAMS"
	case SettingDatagram:
		return "H3_DATAGRAM"
	case SettingDatagramDraft00:
		return "H3_DATAGRAM (draft 00)"
	case SettingWebTransport:
		return "ENABLE_WEBTRANSPORT"
	default:
		return fmt.Sprintf("%#x", uint64(id))
	}
}

// Settings represent HTTP/3 settings, which convey configuration parameters that
// affect how endpoints communicate, such as preferences and constraints on peer behavior.
// SETTINGS frames always apply to an entire HTTP/3 connection, never a single stream.
// A SETTINGS frame MUST be sent as the first frame of each control stream by each peer,
// and MUST NOT be sent subsequently.
type Settings map[SettingID]uint64

// EnableDatagrams adds the necessary HTTP/3 setting(s) to signal support for the HTTP/3 datagram draft.
func (s Settings) EnableDatagrams() {
	s[SettingDatagram] = 1
	s[SettingDatagramDraft00] = 1 // TODO: remove this when the value for H3_DATAGRAM stabilizes
}

// DatagramsEnabled returns true if any of H3_DATAGRAM setting(s) are set to 1.
func (s Settings) DatagramsEnabled() bool {
	return s[SettingDatagram] == 1 || s[SettingDatagramDraft00] == 1
}

// EnableWebTransport sets ENABLE_WEBTRANSPORT to 1.
func (s Settings) EnableWebTransport() {
	s[SettingWebTransport] = 1
}

// WebTransportEnabled returns true if the ENABLE_WEBTRANSPORT setting is set to 1.
func (s Settings) WebTransportEnabled() bool {
	return s[SettingWebTransport] == 1
}

// ExtendedConnectEnabled returns true if the settings imply support for the extended CONNECT method.
// Currently this is limited to the ENABLE_WEBTRANSPORT setting.
func (s Settings) ExtendedConnectEnabled() bool {
	return s.WebTransportEnabled()
}

// TODO: export the frame handling methods?
func (s Settings) frameType() FrameType {
	return FrameTypeSettings
}

func (s Settings) frameLength() protocol.ByteCount {
	var len protocol.ByteCount
	for id, val := range s {
		len += quicvarint.Len(uint64(id)) + quicvarint.Len(val)
	}
	return len
}

func (s Settings) writeFrame(w quicvarint.Writer) {
	quicvarint.Write(w, uint64(s.frameType()))
	quicvarint.Write(w, uint64(s.frameLength()))
	ids := make([]SettingID, 0, len(s))
	for id := range s {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return i < j })
	for _, id := range ids {
		quicvarint.Write(w, uint64(id))
		quicvarint.Write(w, s[id])
	}
}

func readSettings(fr *FrameReader) (Settings, error) {
	err := fr.Next()
	if err != nil {
		return nil, err
	}
	if fr.Type != FrameTypeSettings {
		return nil, &FrameTypeError{
			Want: FrameTypeSettings,
			Type: fr.Type,
		}
	}
	return parseSettingsFramePayload(fr, uint64(fr.N))
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
		i, err := quicvarint.Read(br)
		if err != nil { // should not happen. We allocated the whole frame already.
			return nil, err
		}
		id := SettingID(i)
		val, err := quicvarint.Read(br)
		if err != nil { // should not happen. We allocated the whole frame already.
			return nil, err
		}
		if _, ok := s[id]; ok {
			return nil, fmt.Errorf("duplicate setting: %d", id)
		}
		switch id {
		case SettingQPACKMaxTableCapacity,
			SettingMaxFieldSectionSize,
			SettingQPACKBlockedStreams:
		case SettingDatagram, SettingDatagramDraft00, SettingWebTransport:
			if val != 0 && val != 1 {
				return nil, fmt.Errorf("invalid value for %s: %d", id, val)
			}
		default:
		}
		s[id] = val
	}
	return s, nil
}
