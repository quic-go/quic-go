package utils

import (
	"errors"
	"io"
)

// RingBuffer is a ring buffer
type RingBuffer interface {
	Write(p []byte, offset uint64) error
	Read(n uint64) ([]byte, uint64, error)
	Clear(n uint64) error
	Len() uint64
}

type ringBuffer struct {
	data   []byte
	length uint64

	readPosition  uint64
	writePosition uint64
	writeCapacity uint64 // remaining number of bytes that can be written
}

// NewRingBuffer creates a new ring buffer
func NewRingBuffer(length uint64) RingBuffer {
	return &ringBuffer{
		data:          make([]byte, length, length),
		length:        length,
		writeCapacity: length,
	}
}

// Writes copies the bytes of p into the buffer, if there's enough space
// it doesn't do any partial writes. If there's not enough space, it returns an io.EOF
func (b *ringBuffer) Write(p []byte, offset uint64) error {
	len := uint64(len(p))
	if len+offset > b.writeCapacity {
		return io.EOF
	}

	writePosition := b.writePosition + offset

	if writePosition+len < b.length {
		copy(b.data[writePosition:], p)
	} else {
		copy(b.data[writePosition:b.length], p[:b.length-writePosition])
		copy(b.data, p[b.length-writePosition:])
	}

	b.writePosition = (writePosition + len) % b.length
	b.writeCapacity -= len
	return nil
}

// Read tries to read n bytes
// when reaching the end of the internal byte slice, it returns all bytes until the end, but no eror. It should then be called again to get the rest of the data
func (b *ringBuffer) Read(n uint64) ([]byte, uint64, error) {
	var data []byte
	var err error
	var bytesRead uint64

	diff := b.writePosition - b.readPosition
	if n <= diff {
		bytesRead = n
	}

	if n >= diff {
		bytesRead = diff
		err = io.EOF
	}

	if b.readPosition+bytesRead > b.length {
		bytesRead = b.length - b.readPosition
	}

	data = b.data[b.readPosition : b.readPosition+bytesRead]
	b.readPosition += bytesRead
	return data, bytesRead, err
}

// Clear marks n bytes as being actually processed and allows us to overwrite them
func (b *ringBuffer) Clear(n uint64) error {
	if b.writeCapacity+n > b.length {
		return errors.New("Can't clear that much space")
	}

	b.writeCapacity += n
	return nil
}

// Len gets the length of the underlying byte-slice
func (b *ringBuffer) Len() uint64 {
	return b.length
}
