package fjson

import (
	"bytes"
	"strconv"
)

const (
	comma       = ','
	startObject = '{'
	endObject   = '}'
	startArray  = '['
	endArray    = ']'
	colon       = ':'
	quote       = '"'
)

type Encoder struct {
	w               *bytes.Buffer
	pos             []bool
	lastWriteWasKey bool
	buf             []byte
}

func NewEncoder(w *bytes.Buffer) *Encoder {
	return &Encoder{
		w:   w,
		buf: make([]byte, 0, 32), // for encoding numbers
		pos: make([]bool, 0, 4),  // preallocate. An object with less than 4 levels won't cause any allocs now
	}
}

func (e *Encoder) maybeWriteComma() {
	if !e.lastWriteWasKey && e.pos[len(e.pos)-1] {
		e.w.WriteByte(comma)
	}
}

func (e *Encoder) wroteEntity() {
	e.pos[len(e.pos)-1] = true
	e.lastWriteWasKey = false
}

func (e *Encoder) StartObject() {
	if len(e.pos) > 0 {
		e.maybeWriteComma()
	}
	e.w.WriteByte(startObject)
	e.pos = append(e.pos, false)
}

func (e *Encoder) EndObject() {
	e.w.WriteByte(endObject)
	e.pos = e.pos[:len(e.pos)-1]
	if len(e.pos) > 0 {
		e.wroteEntity()
	}
}

func (e *Encoder) StartArray() {
	if len(e.pos) > 0 {
		e.maybeWriteComma()
	}
	e.w.WriteByte(startArray)
	e.pos = append(e.pos, false)
}

func (e *Encoder) EndArray() {
	e.w.WriteByte(endArray)
	e.pos = e.pos[:len(e.pos)-1]
	if len(e.pos) > 0 {
		e.wroteEntity()
	}
}

func (e *Encoder) WriteBool(b bool) {
	e.maybeWriteComma()
	if b {
		e.w.WriteString("true")
	} else {
		e.w.WriteString("false")
	}
	e.wroteEntity()
}

func (e *Encoder) WriteNull() {
	e.maybeWriteComma()
	e.w.WriteString("null")
	e.wroteEntity()
}

func (e *Encoder) WriteUint64(v uint64) {
	e.maybeWriteComma()
	e.buf = strconv.AppendUint(e.buf, v, 10)
	e.w.Write(e.buf)
	e.buf = e.buf[:0]
	e.wroteEntity()
}
func (e *Encoder) WriteUint32(v uint32) { e.WriteUint64(uint64(v)) }
func (e *Encoder) WriteUint16(v uint16) { e.WriteUint64(uint64(v)) }
func (e *Encoder) WriteUint8(v uint16)  { e.WriteUint64(uint64(v)) }
func (e *Encoder) WriteUint(v uint)     { e.WriteUint64(uint64(v)) }

func (e *Encoder) WriteInt64(v int64) {
	e.maybeWriteComma()
	e.buf = strconv.AppendInt(e.buf, v, 10)
	e.w.Write(e.buf)
	e.buf = e.buf[:0]
	e.wroteEntity()
}
func (e *Encoder) WriteInt32(v int32) { e.WriteInt64(int64(v)) }
func (e *Encoder) WriteInt16(v int16) { e.WriteInt64(int64(v)) }
func (e *Encoder) WriteInt8(v int16)  { e.WriteInt64(int64(v)) }
func (e *Encoder) WriteInt(v int)     { e.WriteInt64(int64(v)) }

func (e *Encoder) WriteFloat(v float64) {
	e.maybeWriteComma()
	e.buf = strconv.AppendFloat(e.buf, v, 'f', -1, 64)
	e.w.Write(e.buf)
	e.buf = e.buf[:0]
	e.wroteEntity()
}

// WriteKeyRaw writes s as a key.
// It doesn't not perform any escaping. It is the caller's responsibility to ensure that s is a valid JSON string.
func (e *Encoder) WriteKeyRaw(s string) {
	e.maybeWriteComma()
	e.writeStringRaw(s)
	e.w.WriteByte(colon)
	e.lastWriteWasKey = true
}

// WriteStringRaw writes a string.
// It doesn't not perform any escaping. It is the caller's responsibility to ensure that s is a valid JSON string.
func (e *Encoder) WriteStringRaw(s string) {
	e.maybeWriteComma()
	e.writeStringRaw(s)
	e.wroteEntity()
}

func (e *Encoder) writeStringRaw(s string) {
	e.w.WriteByte(quote)
	e.w.WriteString(s)
	e.w.WriteByte(quote)
}
