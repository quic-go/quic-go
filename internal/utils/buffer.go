package utils

import (
	"io"
)

// A ByteWriter combines the io.Writer and io.ByteWriter interface
type ByteWriter interface {
	io.ByteWriter
	io.Writer
}

// The Buffer implements the ByteWriter interface.
// It is supposed to be used with pre-allocated slices.
// It does not grow the underlying slice.
// Every write that exceeds the capacity will panic.
type Buffer struct {
	buf []byte
}

var _ ByteWriter = &Buffer{}

// NewBuffer creates a new Buffer
func NewBuffer(buf []byte) *Buffer {
	return &Buffer{buf}
}

func (b *Buffer) grow(n int) int {
	offset := len(b.buf)
	b.buf = b.buf[:offset+n]
	return offset
}

// WriteByte appends the byte c to the buffer.
// The returned error is always nil.
// If the write exceeds the buffer's capacity, WriteByte will panic.
func (b *Buffer) WriteByte(c byte) error {
	offset := b.grow(1)
	b.buf[offset] = c
	return nil
}

// Write appends the contents of p to the buffer.
// The return value n is the length of p; err is always nil.
// If the write exceeds the buffer's capacity, Write will panic with ErrTooLarge.
func (b *Buffer) Write(p []byte) (int, error) {
	offset := b.grow(len(p))
	copy(b.buf[offset:], p)
	return len(p), nil
}

// Len returns the length of the buffer.
func (b *Buffer) Len() int {
	return len(b.buf)
}

// Bytes returns a slice of length b.Len() holding the the buffer.
func (b *Buffer) Bytes() []byte {
	return b.buf
}

// String returns the contents of the buffer as a string.
func (b *Buffer) String() string {
	return string(b.buf)
}
