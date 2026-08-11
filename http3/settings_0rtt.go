package http3

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/quic-go/quic-go/quicvarint"
)

const serverSettingsSessionTicketPrefix = "quic-go h3 settings v1"

type settings = settingsFrame

func settingsForSessionTicket(current *settings) []byte {
	return current.Append([]byte(serverSettingsSessionTicketPrefix))
}

func settingsDataFromSessionTicket(extras [][]byte) ([]byte, bool) {
	prefix := []byte(serverSettingsSessionTicketPrefix)
	for _, extra := range extras {
		if data, ok := bytes.CutPrefix(extra, prefix); ok {
			return data, true
		}
	}
	return nil, false
}

// parseSettingsFromSessionTicket parses a SETTINGS frame that was stored in a session ticket
// by settingsForSessionTicket.
func parseSettingsFromSessionTicket(data []byte) (*settings, error) {
	r := bytes.NewReader(data)
	frameType, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	if frameType != 0x4 {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}
	length, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	if uint64(r.Len()) != length {
		return nil, errors.New("SETTINGS frame length doesn't match")
	}
	return parseSettingsFrame(&countingByteReader{Reader: r}, length, 0, nil)
}

func settingsCompatibleFor0RTT(data []byte, current *settings) bool {
	old, err := parseSettingsFromSessionTicket(data)
	if err != nil {
		return false
	}
	// An unknown setting might belong to an extension that this version no longer supports.
	if len(old.Other) > 0 {
		return false
	}

	if current.MaxFieldSectionSize >= 0 && (old.MaxFieldSectionSize < 0 || old.MaxFieldSectionSize > current.MaxFieldSectionSize) {
		return false
	}
	if old.Datagram && !current.Datagram {
		return false
	}
	if old.ExtendedConnect && !current.ExtendedConnect {
		return false
	}
	return true
}

// settingsCompatibleAfter0RTT says whether the SETTINGS frame that the server sent on a
// resumed connection is compatible with the settings the client assumed when it sent 0-RTT data.
//
// RFC 9114, section 7.2.4.2 requires that a server accepting 0-RTT neither reduces a limit nor
// omits a setting that the client understands and that was previously sent with a non-default
// value. Either is a connection error of type H3_SETTINGS_ERROR.
//
// Settings that we don't recognize are deliberately not considered: the omission rule only
// applies to settings that the client understands, and for the remaining ones there's no way
// to tell whether a changed value is more restrictive.
func settingsCompatibleAfter0RTT(old, current *settings) bool {
	// A missing SETTINGS_MAX_FIELD_SECTION_SIZE means unlimited, so sending a value where there
	// previously was none reduces the limit just as much as sending a smaller value does.
	if current.MaxFieldSectionSize >= 0 &&
		(old.MaxFieldSectionSize < 0 || current.MaxFieldSectionSize < old.MaxFieldSectionSize) {
		return false
	}
	// The value is gone, even though it was previously sent with a non-default value.
	if old.MaxFieldSectionSize >= 0 && current.MaxFieldSectionSize < 0 {
		return false
	}
	if old.Datagram && !current.Datagram {
		return false
	}
	if old.ExtendedConnect && !current.ExtendedConnect {
		return false
	}
	return true
}
