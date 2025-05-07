package gojay

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeStreamDecodePooledDecoderError(t *testing.T) {
	// we override the pool chan
	dec := Stream.NewDecoder(nil)
	dec.Release()
	defer func() {
		err := recover()
		assert.NotNil(t, err, "err shouldnt be nil")
		assert.IsType(t, InvalidUsagePooledDecoderError(""), err, "err should be of type InvalidUsagePooledDecoderError")
	}()
	var v = 0
	dec.Decode(&v)
	// make sure it fails if this is called
	assert.True(t, false, "should not be called as decoder should have panicked")
}

func TestDecodeStreamDecodePooledDecoderError1(t *testing.T) {
	// we override the pool chan
	dec := Stream.NewDecoder(nil)
	dec.Release()
	defer func() {
		err := recover()
		assert.NotNil(t, err, "err shouldnt be nil")
		assert.IsType(t, InvalidUsagePooledDecoderError(""), err, "err should be of type InvalidUsagePooledDecoderError")
	}()
	var v = testSliceStrings{}
	dec.DecodeArray(&v)
	// make sure they are the same
	assert.True(t, false, "should not be called as decoder should have panicked")
}

func TestDecodeStreamDecodePooledDecoderError2(t *testing.T) {
	// we override the pool chan
	dec := Stream.NewDecoder(nil)
	dec.Release()
	defer func() {
		err := recover()
		assert.NotNil(t, err, "err shouldnt be nil")
		assert.IsType(t, InvalidUsagePooledDecoderError(""), err, "err should be of type InvalidUsagePooledDecoderError")
		assert.Equal(t, "Invalid usage of pooled decoder", err.(InvalidUsagePooledDecoderError).Error(), "err should be of type InvalidUsagePooledDecoderError")
	}()
	var v = TestObj{}
	dec.DecodeObject(&v)
	// make sure they are the same
	assert.True(t, false, "should not be called as decoder should have panicked")
}

func TestStreamDecoderNewPool(t *testing.T) {
	dec := newStreamDecoderPool()
	assert.IsType(t, &StreamDecoder{}, dec, "dec should be a *StreamDecoder")
}
