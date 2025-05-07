package gojay

import (
	"strings"
	"testing"

	"fmt"
	"math"

	"github.com/stretchr/testify/assert"
)

func TestEncoderNumberEncodeAPI(t *testing.T) {
	t.Run("encoder-int", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := NewEncoder(builder)
		err := enc.EncodeInt(1)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`1`,
			builder.String(),
			"Result of marshalling is different as the one expected")
	})
	t.Run("encode-int64", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := NewEncoder(builder)
		err := enc.EncodeInt64(math.MaxInt64)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			fmt.Sprintf("%d", math.MaxInt64),
			builder.String(),
			"Result of marshalling is different as the one expected")
	})
	t.Run("encode-uint64", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := NewEncoder(builder)
		err := enc.EncodeUint64(uint64(math.MaxUint64))
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			fmt.Sprintf("%d", uint64(math.MaxUint64)),
			builder.String(),
			"Result of marshalling is different as the one expected")
	})
	t.Run("encode-float64", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := NewEncoder(builder)
		err := enc.EncodeFloat(float64(1.1))
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`1.1`,
			builder.String(),
			"Result of marshalling is different as the one expected")
	})
	t.Run("encode-float32", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := NewEncoder(builder)
		err := enc.EncodeFloat32(float32(1.12))
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`1.12`,
			builder.String(),
			"Result of marshalling is different as the one expected")

	})
}

func TestEncoderNumberEncodeAPIErrors(t *testing.T) {
	t.Run("encode-int-pool-error", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := NewEncoder(builder)
		enc.isPooled = 1
		defer func() {
			err := recover()
			assert.NotNil(t, err, "err should not be nil")
			assert.IsType(t, InvalidUsagePooledEncoderError(""), err, "err should be of type InvalidUsagePooledEncoderError")
		}()
		_ = enc.EncodeInt(1)
		assert.True(t, false, "should not be called as encoder should have panicked")
	})
	t.Run("encode-int-write-error", func(t *testing.T) {
		w := TestWriterError("")
		enc := NewEncoder(w)
		err := enc.EncodeInt(1)
		assert.NotNil(t, err, "err should not be nil")
		assert.Equal(t, "Test Error", err.Error(), "err should be of type InvalidUsagePooledEncoderError")
	})
	t.Run("encode-int64-pool-error", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := NewEncoder(builder)
		enc.isPooled = 1
		defer func() {
			err := recover()
			assert.NotNil(t, err, "err should not be nil")
			assert.IsType(t, InvalidUsagePooledEncoderError(""), err, "err should be of type InvalidUsagePooledEncoderError")
		}()
		_ = enc.EncodeInt64(1)
		assert.True(t, false, "should not be called as encoder should have panicked")
	})
	t.Run("encode-int64-write-error", func(t *testing.T) {
		w := TestWriterError("")
		enc := NewEncoder(w)
		err := enc.EncodeInt64(1)
		assert.NotNil(t, err, "err should not be nil")
		assert.Equal(t, "Test Error", err.Error(), "err should be of type InvalidUsagePooledEncoderError")

	})
	t.Run("encode-uint64-pool-error", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := NewEncoder(builder)
		enc.isPooled = 1
		defer func() {
			err := recover()
			assert.NotNil(t, err, "err should not be nil")
			assert.IsType(t, InvalidUsagePooledEncoderError(""), err, "err should be of type InvalidUsagePooledEncoderError")
		}()
		_ = enc.EncodeUint64(1)
		assert.True(t, false, "should not be called as encoder should have panicked")
	})
	t.Run("encode-unt64-write-error", func(t *testing.T) {
		w := TestWriterError("")
		enc := NewEncoder(w)
		err := enc.EncodeUint64(1)
		assert.NotNil(t, err, "err should not be nil")
		assert.Equal(t, "Test Error", err.Error(), "err should be of type InvalidUsagePooledEncoderError")

	})
	t.Run("encode-float64-pool-error", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := NewEncoder(builder)
		enc.isPooled = 1
		defer func() {
			err := recover()
			assert.NotNil(t, err, "err should not be nil")
			assert.IsType(t, InvalidUsagePooledEncoderError(""), err, "err should be of type InvalidUsagePooledEncoderError")
		}()
		_ = enc.EncodeFloat(1.1)
		assert.True(t, false, "should not be called as encoder should have panicked")
	})
	t.Run("encode-float64-write-error", func(t *testing.T) {
		w := TestWriterError("")
		enc := NewEncoder(w)
		err := enc.EncodeFloat(1.1)
		assert.NotNil(t, err, "err should not be nil")
		assert.Equal(t, "Test Error", err.Error(), "err should be of type InvalidUsagePooledEncoderError")
	})
	t.Run("encode-float32-pool-error", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := NewEncoder(builder)
		enc.isPooled = 1
		defer func() {
			err := recover()
			assert.NotNil(t, err, "err should not be nil")
			assert.IsType(t, InvalidUsagePooledEncoderError(""), err, "err should be of type InvalidUsagePooledEncoderError")
		}()
		_ = enc.EncodeFloat32(float32(1.1))
		assert.True(t, false, "should not be called as encoder should have panicked")
	})
	t.Run("encode-float32-write-error", func(t *testing.T) {
		w := TestWriterError("")
		enc := NewEncoder(w)
		err := enc.EncodeFloat32(float32(1.1))
		assert.NotNil(t, err, "err should not be nil")
		assert.Equal(t, "Test Error", err.Error(), "err should be of type InvalidUsagePooledEncoderError")
	})
}

func TestEncoderNumberMarshalAPI(t *testing.T) {
	t.Run("int", func(t *testing.T) {
		r, err := Marshal(1)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`1`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
	t.Run("int64", func(t *testing.T) {
		r, err := Marshal(int64(1))
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`1`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
	t.Run("int32", func(t *testing.T) {
		r, err := Marshal(int32(1))
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`1`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
	t.Run("int16", func(t *testing.T) {
		r, err := Marshal(int16(1))
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`1`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
	t.Run("int8", func(t *testing.T) {
		r, err := Marshal(int8(1))
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`1`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
	t.Run("uint64", func(t *testing.T) {
		r, err := Marshal(uint64(1))
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`1`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
	t.Run("uint32", func(t *testing.T) {
		r, err := Marshal(uint32(1))
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`1`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
	t.Run("uint16", func(t *testing.T) {
		r, err := Marshal(uint16(1))
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`1`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
	t.Run("uint8", func(t *testing.T) {
		r, err := Marshal(uint8(1))
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`1`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
	t.Run("float64", func(t *testing.T) {
		r, err := Marshal(1.1)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`1.1`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
}

func TestAddNumberFunc(t *testing.T) {
	t.Run("int64-key", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := BorrowEncoder(builder)
		enc.writeByte('{')
		enc.AddInt64Key("test", 10)
		_, err := enc.Write()
		assert.Nil(t, err, "err should be nil")
		assert.Equal(t, `{"test":10`, builder.String(), `builder.String() should be equal to {"test":10"`)
	})
	t.Run("int64-key-2", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := BorrowEncoder(builder)
		enc.writeBytes([]byte(`{"test":1`))
		enc.AddInt64Key("test", 10)
		_, err := enc.Write()
		assert.Nil(t, err, "err should be nil")
		assert.Equal(t, `{"test":1,"test":10`, builder.String(), `builder.String() should be equal to {"test":10"`)
	})

	t.Run("int64-key-omit-empty", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := BorrowEncoder(builder)
		enc.writeByte('{')
		enc.AddInt64KeyOmitEmpty("test", 10)
		_, err := enc.Write()
		assert.Nil(t, err, "err should be nil")
		assert.Equal(t, `{"test":10`, builder.String(), `builder.String() should be equal to {"test":10"`)
	})
	t.Run("int64-key-omit-empty-2", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := BorrowEncoder(builder)
		enc.writeBytes([]byte(`{"test":1`))
		enc.AddInt64KeyOmitEmpty("test", 10)
		_, err := enc.Write()
		assert.Nil(t, err, "err should be nil")
		assert.Equal(t, `{"test":1,"test":10`, builder.String(), `builder.String() should be equal to {"test":10"`)
	})
	t.Run("int64-key-omit-empty-3", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := BorrowEncoder(builder)
		enc.writeByte('{')
		enc.AddInt64KeyOmitEmpty("test", 0)
		_, err := enc.Write()
		assert.Nil(t, err, "err should be nil")
		assert.Equal(t, `{`, builder.String(), `builder.String() should be equal to {"test":10"`)
	})
	t.Run("int64", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := BorrowEncoder(builder)
		enc.writeByte('[')
		enc.AddInt64(10)
		_, err := enc.Write()
		assert.Nil(t, err, "err should be nil")
		assert.Equal(t, `[10`, builder.String(), `builder.String() should be equal to {"test":10"`)
	})
	t.Run("int64-2", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := BorrowEncoder(builder)
		enc.writeBytes([]byte(`[1`))
		enc.AddInt64(10)
		_, err := enc.Write()
		assert.Nil(t, err, "err should be nil")
		assert.Equal(t, `[1,10`, builder.String(), `builder.String() should be equal to {"test":10"`)
	})

	t.Run("int64-omit-empty", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := BorrowEncoder(builder)
		enc.writeByte('[')
		enc.AddInt64OmitEmpty(10)
		_, err := enc.Write()
		assert.Nil(t, err, "err should be nil")
		assert.Equal(t, `[10`, builder.String(), `builder.String() should be equal to {"test":10"`)
	})
	t.Run("int64-omit-empty-2", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := BorrowEncoder(builder)
		enc.writeBytes([]byte(`[1`))
		enc.AddInt64OmitEmpty(10)
		_, err := enc.Write()
		assert.Nil(t, err, "err should be nil")
		assert.Equal(t, `[1,10`, builder.String(), `builder.String() should be equal to {"test":10"`)
	})
	t.Run("int64-omit-empty-3", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := BorrowEncoder(builder)
		enc.writeByte('[')
		enc.AddInt64OmitEmpty(0)
		_, err := enc.Write()
		assert.Nil(t, err, "err should be nil")
		assert.Equal(t, `[`, builder.String(), `builder.String() should be equal to {"test":10"`)
	})
}

func TestEncodeUint64(t *testing.T) {
	builder := &strings.Builder{}
	enc := BorrowEncoder(builder)
	err := enc.Encode(uint64(145509))
	assert.Nil(t, err, "err should be nil")
	assert.Equal(t, "145509", builder.String(), "builder.String() should be 145509")
}

func TestUint64Add(t *testing.T) {
	t.Run("uint64-key", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := BorrowEncoder(builder)
		enc.writeByte('{')
		enc.AddUint64Key("test", 10)
		_, err := enc.Write()
		assert.Nil(t, err, "err should be nil")
		assert.Equal(t, `{"test":10`, builder.String(), `builder.String() should be equal to {"test":10"`)
	})
	t.Run("uint64-key-2", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := BorrowEncoder(builder)
		enc.writeBytes([]byte(`{"test":1`))
		enc.AddUint64Key("test", 10)
		_, err := enc.Write()
		assert.Nil(t, err, "err should be nil")
		assert.Equal(t, `{"test":1,"test":10`, builder.String(), `builder.String() should be equal to {"test":10"`)
	})

	t.Run("uint64-key-omit-empty", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := BorrowEncoder(builder)
		enc.writeByte('{')
		enc.AddUint64KeyOmitEmpty("test", 10)
		_, err := enc.Write()
		assert.Nil(t, err, "err should be nil")
		assert.Equal(t, `{"test":10`, builder.String(), `builder.String() should be equal to {"test":10"`)
	})
	t.Run("uint64-key-omit-empty-2", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := BorrowEncoder(builder)
		enc.writeBytes([]byte(`{"test":1`))
		enc.AddUint64KeyOmitEmpty("test", 10)
		_, err := enc.Write()
		assert.Nil(t, err, "err should be nil")
		assert.Equal(t, `{"test":1,"test":10`, builder.String(), `builder.String() should be equal to {"test":10"`)
	})
	t.Run("uint64-key-omit-empty-3", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := BorrowEncoder(builder)
		enc.writeByte('{')
		enc.AddUint64KeyOmitEmpty("test", 0)
		_, err := enc.Write()
		assert.Nil(t, err, "err should be nil")
		assert.Equal(t, `{`, builder.String(), `builder.String() should be equal to {"test":10"`)
	})
	t.Run("uint64", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := BorrowEncoder(builder)
		enc.writeByte('[')
		enc.AddUint64(10)
		_, err := enc.Write()
		assert.Nil(t, err, "err should be nil")
		assert.Equal(t, `[10`, builder.String(), `builder.String() should be equal to {"test":10"`)
	})
	t.Run("uint64-2", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := BorrowEncoder(builder)
		enc.writeBytes([]byte(`[1`))
		enc.AddUint64(10)
		_, err := enc.Write()
		assert.Nil(t, err, "err should be nil")
		assert.Equal(t, `[1,10`, builder.String(), `builder.String() should be equal to {"test":10"`)
	})

	t.Run("uint64-omit-empty", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := BorrowEncoder(builder)
		enc.writeByte('[')
		enc.AddUint64OmitEmpty(10)
		_, err := enc.Write()
		assert.Nil(t, err, "err should be nil")
		assert.Equal(t, `[10`, builder.String(), `builder.String() should be equal to {"test":10"`)
	})
	t.Run("uint64-omit-empty-2", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := BorrowEncoder(builder)
		enc.writeBytes([]byte(`[1`))
		enc.AddUint64OmitEmpty(10)
		_, err := enc.Write()
		assert.Nil(t, err, "err should be nil")
		assert.Equal(t, `[1,10`, builder.String(), `builder.String() should be equal to {"test":10"`)
	})
	t.Run("uint64-omit-empty-3", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := BorrowEncoder(builder)
		enc.writeByte('[')
		enc.AddUint64OmitEmpty(0)
		_, err := enc.Write()
		assert.Nil(t, err, "err should be nil")
		assert.Equal(t, `[`, builder.String(), `builder.String() should be equal to {"test":10"`)
	})
}
