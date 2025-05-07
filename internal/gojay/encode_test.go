package gojay

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

type TestWriterError string

func (t TestWriterError) Write(b []byte) (int, error) {
	return 0, errors.New("Test Error")
}

func TestAppendBytes(t *testing.T) {
	b := []byte(``)
	enc := NewEncoder(nil)
	enc.buf = b
	enc.AppendBytes([]byte(`true`))
	assert.Equal(t, string(enc.buf), `true`, "string(enc.buf) should equal to true")
}

func TestAppendByte(t *testing.T) {
	b := []byte(``)
	enc := NewEncoder(nil)
	enc.buf = b
	enc.AppendByte(1)
	assert.Equal(t, enc.buf[0], uint8(0x1), "b[0] should equal to 1")
}

func TestAppendString(t *testing.T) {
	b := []byte(``)
	enc := NewEncoder(nil)
	enc.buf = b
	enc.AppendString("true")
	assert.Equal(t, string(enc.buf), `"true"`, "string(enc.buf) should equal to true")
}

func TestBuf(t *testing.T) {
	b := []byte(`test`)
	enc := NewEncoder(nil)
	enc.buf = b
	assert.Equal(t, b, enc.Buf(), "enc.Buf() should equal to b")
}
