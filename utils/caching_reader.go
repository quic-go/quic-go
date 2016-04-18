package utils

import "bytes"

// CachingReader wraps a reader and saves all data it reads
type CachingReader struct {
	buf bytes.Buffer
	r   ReadStream
}

// NewCachingReader returns a new CachingReader
func NewCachingReader(r ReadStream) *CachingReader {
	return &CachingReader{r: r}
}

// Read implements io.Reader
func (r *CachingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.buf.Write(p[:n])
	return n, err
}

// ReadByte implements io.ByteReader
func (r *CachingReader) ReadByte() (byte, error) {
	b, err := r.r.ReadByte()
	if err == nil {
		r.buf.WriteByte(b)
	}
	return b, err
}

// Get the data cached
func (r *CachingReader) Get() []byte {
	return r.buf.Bytes()
}
