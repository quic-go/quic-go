package gojay

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecoderBorrowFromPoolSetBuffSize(t *testing.T) {
	dec := borrowDecoder(nil, 512)
	assert.Len(t, dec.data, 512, "data buffer should be of len 512")
}

func TestDecoderNewPool(t *testing.T) {
	dec := newDecoderPool()
	assert.IsType(t, &Decoder{}, dec, "dec should be a *Decoder")
}
