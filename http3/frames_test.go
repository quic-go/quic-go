package http3

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/Noooste/uquic-go"
	mockquic "github.com/Noooste/uquic-go/internal/mocks/quic"
	"github.com/Noooste/uquic-go/quicvarint"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func testFrameParserEOF(t *testing.T, data []byte) {
	t.Helper()
	for i := range data {
		b := make([]byte, i)
		copy(b, data[:i])
		fp := frameParser{r: bytes.NewReader(b)}
		_, err := fp.ParseNext()
		require.Error(t, err)
		require.ErrorIs(t, err, io.EOF)
	}
}

func TestParserReservedFrameType(t *testing.T) {
	for _, ft := range []uint64{0x2, 0x6, 0x8, 0x9} {
		t.Run(fmt.Sprintf("type %#x", ft), func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			conn := mockquic.NewMockEarlyConnection(mockCtrl)
			data := quicvarint.Append(nil, ft)
			data = quicvarint.Append(data, 6)
			data = append(data, []byte("foobar")...)

			conn.EXPECT().CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), gomock.Any())
			fp := frameParser{
				r:    bytes.NewReader(data),
				conn: conn,
			}
			_, err := fp.ParseNext()
			require.Error(t, err)
			require.ErrorContains(t, err, "http3: reserved frame type")
		})
	}
}

func TestParserUnknownFrameType(t *testing.T) {
	data := quicvarint.Append(nil, 0xdead)
	data = quicvarint.Append(data, 6)
	data = append(data, []byte("foobar")...)
	data = quicvarint.Append(data, 0xbeef)
	data = quicvarint.Append(data, 3)
	data = append(data, []byte("baz")...)
	hf := &headersFrame{Length: 3}
	data = hf.Append(data)
	data = append(data, []byte("foo")...)

	r := bytes.NewReader(data)
	fp := frameParser{r: r}
	f, err := fp.ParseNext()
	require.NoError(t, err)
	require.IsType(t, &headersFrame{}, f)
	hf = f.(*headersFrame)
	require.Equal(t, uint64(3), hf.Length)
	payload := make([]byte, 3)
	_, err = io.ReadFull(r, payload)
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), payload)
}

func TestParserHeadersFrame(t *testing.T) {
	data := quicvarint.Append(nil, 1) // type byte
	data = quicvarint.Append(data, 0x1337)
	fp := frameParser{r: bytes.NewReader(data)}

	// incomplete data results in an io.EOF
	testFrameParserEOF(t, data)

	// parse
	f1, err := fp.ParseNext()
	require.NoError(t, err)
	require.IsType(t, &headersFrame{}, f1)
	require.Equal(t, uint64(0x1337), f1.(*headersFrame).Length)

	// write and parse
	fp = frameParser{r: bytes.NewReader(f1.(*headersFrame).Append(nil))}
	f2, err := fp.ParseNext()
	require.NoError(t, err)
	require.Equal(t, f1, f2)
}

func TestDataFrame(t *testing.T) {
	data := quicvarint.Append(nil, 0) // type byte
	data = quicvarint.Append(data, 0x1337)
	fp := frameParser{r: bytes.NewReader(data)}

	// incomplete data results in an io.EOF
	testFrameParserEOF(t, data)

	// parse
	f1, err := fp.ParseNext()
	require.NoError(t, err)
	require.IsType(t, &dataFrame{}, f1)
	require.Equal(t, uint64(0x1337), f1.(*dataFrame).Length)

	// write and parse
	fp = frameParser{r: bytes.NewReader(f1.(*dataFrame).Append(nil))}
	f2, err := fp.ParseNext()
	require.NoError(t, err)
	require.Equal(t, f1, f2)
}

func appendSetting(b []byte, key, value uint64) []byte {
	b = quicvarint.Append(b, key)
	b = quicvarint.Append(b, value)
	return b
}

func TestParserSettingsFrame(t *testing.T) {
	settings := appendSetting(nil, 13, 37)
	settings = appendSetting(settings, 0xdead, 0xbeef)
	data := quicvarint.Append(nil, 4) // type byte
	data = quicvarint.Append(data, uint64(len(settings)))
	data = append(data, settings...)

	// incomplete data results in an io.EOF
	testFrameParserEOF(t, data)

	fp := frameParser{r: bytes.NewReader(data)}
	frame, err := fp.ParseNext()
	require.NoError(t, err)
	require.IsType(t, &settingsFrame{}, frame)
	sf := frame.(*settingsFrame)
	require.Len(t, sf.Other, 2)
	require.Equal(t, uint64(37), sf.Other[uint64(13)])
	require.Equal(t, uint64(0xbeef), sf.Other[uint64(0xdead)])

	// write and parse
	fp = frameParser{r: bytes.NewReader(sf.Append(nil))}
	f2, err := fp.ParseNext()
	require.NoError(t, err)
	require.IsType(t, &settingsFrame{}, f2)
	sf2 := f2.(*settingsFrame)
	require.Len(t, sf2.Other, len(sf.Other))
	require.Equal(t, sf.Other, sf2.Other)
}

func TestParserSettingsFrameDuplicateSettings(t *testing.T) {
	for _, tc := range []struct {
		name string
		num  uint64
		val  uint64
	}{
		{
			name: "other setting",
			num:  13,
			val:  37,
		},
		{
			name: "extended connect",
			num:  settingExtendedConnect,
			val:  1,
		},
		{
			name: "datagram",
			num:  SettingsH3Datagram,
			val:  1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := appendSetting(nil, tc.num, tc.val)
			settings = appendSetting(settings, tc.num, tc.val)
			data := quicvarint.Append(nil, 4) // type byte
			data = quicvarint.Append(data, uint64(len(settings)))
			data = append(data, settings...)
			fp := frameParser{r: bytes.NewReader(data)}
			_, err := fp.ParseNext()
			require.Error(t, err)
			require.EqualError(t, err, fmt.Sprintf("duplicate setting: %d", tc.num))
		})
	}
}

func TestParserSettingsFrameDatagram(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		testParserSettingsFrameDatagram(t, true)
	})
	t.Run("disabled", func(t *testing.T) {
		testParserSettingsFrameDatagram(t, false)
	})
}

func testParserSettingsFrameDatagram(t *testing.T, enabled bool) {
	var settings []byte
	switch enabled {
	case true:
		settings = appendSetting(nil, SettingsH3Datagram, 1)
	case false:
		settings = appendSetting(nil, SettingsH3Datagram, 0)
	}
	data := quicvarint.Append(nil, 4) // type byte
	data = quicvarint.Append(data, uint64(len(settings)))
	data = append(data, settings...)

	fp := frameParser{r: bytes.NewReader(data)}
	f, err := fp.ParseNext()
	require.NoError(t, err)
	require.IsType(t, &settingsFrame{}, f)
	sf := f.(*settingsFrame)
	require.Equal(t, enabled, sf.Datagram)

	fp = frameParser{r: bytes.NewReader(sf.Append(nil))}
	f2, err := fp.ParseNext()
	require.NoError(t, err)
	require.Equal(t, sf, f2)
}

func TestParserSettingsFrameDatagramInvalidValue(t *testing.T) {
	settings := quicvarint.Append(nil, SettingsH3Datagram)
	settings = quicvarint.Append(settings, 1337)
	data := quicvarint.Append(nil, 4) // type byte
	data = quicvarint.Append(data, uint64(len(settings)))
	data = append(data, settings...)
	fp := frameParser{r: bytes.NewReader(data)}
	_, err := fp.ParseNext()
	require.EqualError(t, err, "invalid value for SETTINGS_H3_DATAGRAM: 1337")
}

func TestParserSettingsFrameExtendedConnect(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		testParserSettingsFrameExtendedConnect(t, true)
	})
	t.Run("disabled", func(t *testing.T) {
		testParserSettingsFrameExtendedConnect(t, false)
	})
}

func testParserSettingsFrameExtendedConnect(t *testing.T, enabled bool) {
	var settings []byte
	switch enabled {
	case true:
		settings = appendSetting(nil, settingExtendedConnect, 1)
	case false:
		settings = appendSetting(nil, settingExtendedConnect, 0)
	}
	data := quicvarint.Append(nil, 4) // type byte
	data = quicvarint.Append(data, uint64(len(settings)))
	data = append(data, settings...)

	fp := frameParser{r: bytes.NewReader(data)}
	f, err := fp.ParseNext()
	require.NoError(t, err)
	require.IsType(t, &settingsFrame{}, f)
	sf := f.(*settingsFrame)
	require.Equal(t, enabled, sf.ExtendedConnect)

	fp = frameParser{r: bytes.NewReader(sf.Append(nil))}
	f2, err := fp.ParseNext()
	require.NoError(t, err)
	require.Equal(t, sf, f2)
}

func TestParserSettingsFrameExtendedConnectInvalidValue(t *testing.T) {
	settings := quicvarint.Append(nil, settingExtendedConnect)
	settings = quicvarint.Append(settings, 1337)
	data := quicvarint.Append(nil, 4) // type byte
	data = quicvarint.Append(data, uint64(len(settings)))
	data = append(data, settings...)
	fp := frameParser{r: bytes.NewReader(data)}
	_, err := fp.ParseNext()
	require.EqualError(t, err, "invalid value for SETTINGS_ENABLE_CONNECT_PROTOCOL: 1337")
}

func TestParserGoAwayFrame(t *testing.T) {
	data := quicvarint.Append(nil, 7) // type byte
	data = quicvarint.Append(data, uint64(quicvarint.Len(100)))
	data = quicvarint.Append(data, 100)

	// incomplete data results in an io.EOF
	testFrameParserEOF(t, data)

	fp := frameParser{r: bytes.NewReader(data)}
	f, err := fp.ParseNext()
	require.NoError(t, err)
	require.IsType(t, &goAwayFrame{}, f)
	require.Equal(t, quic.StreamID(100), f.(*goAwayFrame).StreamID)

	// write and parse
	fp = frameParser{r: bytes.NewReader(f.(*goAwayFrame).Append(nil))}
	f2, err := fp.ParseNext()
	require.NoError(t, err)
	require.Equal(t, f, f2)
}

func TestParserHijacking(t *testing.T) {
	t.Run("hijacking", func(t *testing.T) {
		testParserHijacking(t, true)
	})
	t.Run("not hijacking", func(t *testing.T) {
		testParserHijacking(t, false)
	})
}

func testParserHijacking(t *testing.T, hijack bool) {
	b := quicvarint.Append(nil, 1337)
	if hijack {
		b = append(b, "foobar"...)
	} else {
		// if the stream is not hijacked, this will be treated as an unknown frame
		b = quicvarint.Append(b, 11)
		b = append(b, []byte("lorem ipsum")...)
		b = (&dataFrame{Length: 6}).Append(b)
		b = append(b, []byte("foobar")...)
	}

	var called bool
	r := bytes.NewReader(b)
	fp := frameParser{
		r: r,
		unknownFrameHandler: func(ft FrameType, e error) (hijacked bool, err error) {
			called = true
			require.NoError(t, e)
			require.Equal(t, FrameType(1337), ft)
			if !hijack {
				return false, nil
			}
			b := make([]byte, 6)
			_, err = io.ReadFull(r, b)
			require.NoError(t, err)
			require.Equal(t, "foobar", string(b))
			return true, nil
		},
	}
	f, err := fp.ParseNext()
	require.True(t, called)
	if hijack {
		require.ErrorIs(t, err, errHijacked)
		return
	}
	require.NoError(t, err)
	require.IsType(t, &dataFrame{}, f)
	df := f.(*dataFrame)
	require.Equal(t, uint64(6), df.Length)
	payload := make([]byte, 6)
	_, err = io.ReadFull(r, payload)
	require.NoError(t, err)
	require.Equal(t, "foobar", string(payload))
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func TestParserHijackError(t *testing.T) {
	var called bool
	fp := frameParser{
		r: errReader{err: assert.AnError},
		unknownFrameHandler: func(ft FrameType, e error) (hijacked bool, err error) {
			require.EqualError(t, e, assert.AnError.Error())
			require.Zero(t, ft)
			called = true
			return true, nil
		},
	}
	_, err := fp.ParseNext()
	require.ErrorIs(t, err, errHijacked)
	require.True(t, called)
}
