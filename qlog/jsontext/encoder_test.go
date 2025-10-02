package jsontext_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/quic-go/quic-go/qlog/jsontext"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncoderSimpleObject(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	enc := jsontext.NewEncoder(buf)
	enc.WriteToken(jsontext.BeginObject)
	enc.WriteToken(jsontext.String("foo"))
	enc.WriteToken(jsontext.String("bar"))
	enc.WriteToken(jsontext.String("foo2"))
	enc.WriteToken(jsontext.String("bar2"))
	enc.WriteToken(jsontext.EndObject)
	output := buf.String()

	var got map[string]string
	require.NoError(t, json.Unmarshal([]byte(output), &got))
	require.Equal(t, map[string]string{"foo": "bar", "foo2": "bar2"}, got)
}

func TestEncoderArrayInts(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	enc := jsontext.NewEncoder(buf)
	enc.WriteToken(jsontext.BeginArray)
	enc.WriteToken(jsontext.Int(1))
	enc.WriteToken(jsontext.Int(2))
	enc.WriteToken(jsontext.Int(3))
	enc.WriteToken(jsontext.EndArray)
	output := buf.String()

	var got []int
	require.NoError(t, json.Unmarshal([]byte(output), &got))
	require.Equal(t, []int{1, 2, 3}, got)
}

func TestEncoderArrayStrings(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	enc := jsontext.NewEncoder(buf)
	enc.WriteToken(jsontext.BeginArray)
	enc.WriteToken(jsontext.String("one"))
	enc.WriteToken(jsontext.String("two"))
	enc.WriteToken(jsontext.EndArray)
	output := buf.String()

	var got []string
	err := json.Unmarshal([]byte(output), &got)
	require.NoError(t, err)
	require.Equal(t, []string{"one", "two"}, got)
}

func TestEncoderNestedObject(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	enc := jsontext.NewEncoder(buf)
	enc.WriteToken(jsontext.BeginObject)
	enc.WriteToken(jsontext.String("outer"))
	enc.WriteToken(jsontext.BeginObject)
	enc.WriteToken(jsontext.String("inner"))
	enc.WriteToken(jsontext.String("value"))
	enc.WriteToken(jsontext.EndObject)
	enc.WriteToken(jsontext.EndObject)
	output := buf.String()

	var got map[string]map[string]string
	require.NoError(t, json.Unmarshal([]byte(output), &got))
	require.Equal(t, map[string]map[string]string{"outer": {"inner": "value"}}, got)
}

func TestEncoderNumbersAndBool(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	enc := jsontext.NewEncoder(buf)
	enc.WriteToken(jsontext.BeginObject)
	enc.WriteToken(jsontext.String("int"))
	enc.WriteToken(jsontext.Int(42))
	enc.WriteToken(jsontext.String("uint"))
	enc.WriteToken(jsontext.Uint(100))
	enc.WriteToken(jsontext.String("float"))
	enc.WriteToken(jsontext.Float(3.14))
	enc.WriteToken(jsontext.String("true"))
	enc.WriteToken(jsontext.True)
	enc.WriteToken(jsontext.String("false"))
	enc.WriteToken(jsontext.False)
	enc.WriteToken(jsontext.EndObject)
	output := buf.String()

	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(output), &got))
	require.Equal(t, map[string]any{
		"int":   float64(42), // json.Unmarshal decodes numbers as float64
		"uint":  float64(100),
		"float": 3.14,
		"true":  true,
		"false": false,
	}, got)
}

func TestEncoderEmptyObject(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	enc := jsontext.NewEncoder(buf)
	enc.WriteToken(jsontext.BeginObject)
	enc.WriteToken(jsontext.EndObject)
	output := buf.String()

	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(output), &got))
	require.Equal(t, map[string]any{}, got)
}

func TestEncoderEmptyArray(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	enc := jsontext.NewEncoder(buf)
	enc.WriteToken(jsontext.BeginArray)
	enc.WriteToken(jsontext.EndArray)
	output := buf.String()

	var got []any
	require.NoError(t, json.Unmarshal([]byte(output), &got))
	require.Equal(t, []any{}, got)
}

func TestEncoderEscapedStrings(t *testing.T) {
	t.Run("no escapes", func(t *testing.T) {
		testEncoderEscapedStrings(t, "simplekey", "simplevalue")
	})

	t.Run("basic escapes", func(t *testing.T) {
		key := `key"\/`
		value := `value"\/`
		testEncoderEscapedStrings(t, key, value)
	})

	t.Run("control characters", func(t *testing.T) {
		key := "key\b\f\n\r\t"
		value := "value\b\f\n\r\t"
		testEncoderEscapedStrings(t, key, value)
	})

	t.Run("unicode low", func(t *testing.T) {
		key := "key\u0007\u001f"
		value := "value\u0007\u001f"
		testEncoderEscapedStrings(t, key, value)
	})

	t.Run("mixed all", func(t *testing.T) {
		key := `key"\\\/\b\f\n\r\t\u0007\u001f`
		value := `value"\\\/\b\f\n\r\t\u0007\u001f`
		testEncoderEscapedStrings(t, key, value)
	})
}

func testEncoderEscapedStrings(t *testing.T, key, value string) {
	buf := bytes.NewBuffer(nil)
	enc := jsontext.NewEncoder(buf)
	enc.WriteToken(jsontext.BeginObject)
	enc.WriteToken(jsontext.String(key))
	enc.WriteToken(jsontext.String(value))
	enc.WriteToken(jsontext.EndObject)
	output := buf.String()

	var got map[string]string
	err := json.Unmarshal([]byte(output), &got)
	require.NoError(t, err)
	expected := map[string]string{key: value}
	require.Equal(t, expected, got)
}

func encodeValue(t *testing.T, enc *jsontext.Encoder, v any) {
	switch val := v.(type) {
	case map[string]any:
		require.NoError(t, enc.WriteToken(jsontext.BeginObject))
		for k, vv := range val {
			require.NoError(t, enc.WriteToken(jsontext.String(k)))
			encodeValue(t, enc, vv)
		}
		require.NoError(t, enc.WriteToken(jsontext.EndObject))
	case []any:
		require.NoError(t, enc.WriteToken(jsontext.BeginArray))
		for _, vv := range val {
			encodeValue(t, enc, vv)
		}
		require.NoError(t, enc.WriteToken(jsontext.EndArray))
	case string:
		require.NoError(t, enc.WriteToken(jsontext.String(val)))
	case int64:
		require.NoError(t, enc.WriteToken(jsontext.Int(val)))
	case uint64:
		require.NoError(t, enc.WriteToken(jsontext.Uint(val)))
	case float64:
		require.NoError(t, enc.WriteToken(jsontext.Float(val)))
	case bool:
		require.NoError(t, enc.WriteToken(jsontext.Bool(val)))
	default:
		require.FailNowf(t, "unsupported type", "unsupported type: %T", v)
	}
}

type errorWriter struct {
	N int
}

func (w *errorWriter) Write(p []byte) (int, error) {
	n := min(len(p), w.N)
	w.N -= n
	if w.N <= 0 {
		return n, assert.AnError
	}
	return n, nil
}

func TestEncoderComprehensive(t *testing.T) {
	// encodes an object with all token types and nested structures
	encode := func(enc *jsontext.Encoder) error {
		if err := enc.WriteToken(jsontext.BeginObject); err != nil {
			return err
		}

		if err := enc.WriteToken(jsontext.String("simple")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("value")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("escaped")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(`"quoted\"string"`)); err != nil {
			return err
		}

		if err := enc.WriteToken(jsontext.String("int")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Int(-42)); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("uint")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Uint(100)); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("float")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Float(3.14)); err != nil {
			return err
		}

		if err := enc.WriteToken(jsontext.String("true")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.True); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("false")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.False); err != nil {
			return err
		}

		if err := enc.WriteToken(jsontext.String("array")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.BeginArray); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("item1")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Int(1)); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.EndArray); err != nil {
			return err
		}

		if err := enc.WriteToken(jsontext.String("nested")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.BeginObject); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.EndObject); err != nil {
			return err
		}

		if err := enc.WriteToken(jsontext.EndObject); err != nil {
			return err
		}
		return nil
	}

	buf := bytes.NewBuffer(nil)
	enc := jsontext.NewEncoder(buf)
	require.NoError(t, encode(enc))

	for i := range buf.Len() {
		enc := jsontext.NewEncoder(&errorWriter{N: i})
		require.ErrorIs(t, encode(enc), assert.AnError)
	}
}

func FuzzEncoder(f *testing.F) {
	f.Add("simple", int64(42), uint64(100), 3.14, true)
	f.Add(`esc"aped\string`, int64(-1), uint64(0), 0.0, false)
	f.Add("\b\f\n\r\t\u001f", int64(0), uint64(1), 1.23e-4, true)
	f.Add("", int64(9223372036854775807), uint64(18446744073709551615), -3.14, false)

	f.Fuzz(func(t *testing.T, s string, i int64, u uint64, fl float64, b bool) {
		expected := map[string]any{
			"string": s,
			"int":    float64(i), // json decodes to float64
			"uint":   float64(u),
			"float":  fl,
			"bool":   b,
			"array":  []any{s, float64(i), fl},
			"object": map[string]any{s: fl},
		}

		var stdlibBuf, ourBuf bytes.Buffer

		// only attempt to handle inputs that the standard library can handle
		stdlibEnc := json.NewEncoder(&stdlibBuf)
		require.NoError(t, stdlibEnc.Encode(expected))
		if !json.Valid(stdlibBuf.Bytes()) {
			return
		}

		// then encode using the jsontext encoder
		enc := jsontext.NewEncoder(&ourBuf)
		encodeValue(t, enc, expected)

		output := ourBuf.Bytes()
		require.Truef(t, json.Valid(output), "produced invalid JSON: %s", output)

		var got any
		require.NoError(t, json.Unmarshal(output, &got))
		require.JSONEq(t, ourBuf.String(), stdlibBuf.String())
	})
}
