package gojay

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func (r *Request) MarshalJSONObject(enc *Encoder) {
	enc.AddStringKey("id", r.id)
	enc.AddStringKey("method", r.method)
	enc.AddEmbeddedJSONKey("params", &r.params)
	params2 := EmbeddedJSON([]byte(``))
	enc.AddEmbeddedJSONKeyOmitEmpty("params2", &params2)
	params3 := EmbeddedJSON([]byte(`"test"`))
	enc.AddEmbeddedJSONKeyOmitEmpty("params3", &params3)
	enc.AddIntKey("more", r.more)
}

func (r *Request) IsNil() bool {
	return r == nil
}

type EmbeddedJSONArr []EmbeddedJSON

func (ear EmbeddedJSONArr) MarshalJSONArray(enc *Encoder) {
	for _, e := range ear {
		enc.AddEmbeddedJSON(&e)
	}
}

func (ear EmbeddedJSONArr) IsNil() bool {
	return len(ear) == 0
}

type EmbeddedJSONOmitEmptyArr []EmbeddedJSON

func (ear EmbeddedJSONOmitEmptyArr) MarshalJSONArray(enc *Encoder) {
	for _, e := range ear {
		enc.AddEmbeddedJSONOmitEmpty(&e)
	}
}

func (ear EmbeddedJSONOmitEmptyArr) IsNil() bool {
	return len(ear) == 0
}

func TestEncodingEmbeddedJSON(t *testing.T) {
	t.Run("basic-embedded-json", func(t *testing.T) {
		ej := EmbeddedJSON([]byte(`"test"`))
		b := &strings.Builder{}
		enc := BorrowEncoder(b)
		err := enc.Encode(&ej)
		assert.Nil(t, err, "err should be nil")
		assert.Equal(t, b.String(), `"test"`, "b should be equal to content of EmbeddedJSON")
	})
	t.Run("basic-embedded-json-marshal-api", func(t *testing.T) {
		ej := EmbeddedJSON([]byte(`"test"`))
		b, err := Marshal(&ej)
		assert.Nil(t, err, "err should be nil")
		assert.Equal(t, string(b), `"test"`, "b should be equal to content of EmbeddedJSON")
	})
	t.Run("object-embedded-json", func(t *testing.T) {
		req := Request{
			id:     "test",
			method: "GET",
			params: EmbeddedJSON([]byte(`"test"`)),
		}
		b := &strings.Builder{}
		enc := BorrowEncoder(b)
		err := enc.EncodeObject(&req)
		assert.Nil(t, err, "err should be nil")
		assert.Equal(
			t,
			b.String(),
			`{"id":"test","method":"GET","params":"test","params3":"test","more":0}`,
			"b should be equal to content of EmbeddedJSON",
		)
	})
	t.Run("array-embedded-json", func(t *testing.T) {
		ear := EmbeddedJSONArr{
			[]byte(`"test"`),
			[]byte(`{"test":"test"}`),
		}
		b := &strings.Builder{}
		enc := BorrowEncoder(b)
		err := enc.EncodeArray(ear)
		assert.Nil(t, err, "err should be nil")
		assert.Equal(
			t,
			b.String(),
			`["test",{"test":"test"}]`,
			"b should be equal to content of EmbeddedJSON",
		)
	})
	t.Run("array-embedded-json-omit-empty", func(t *testing.T) {
		ear := EmbeddedJSONOmitEmptyArr{
			[]byte(`"test"`),
			[]byte(``),
			[]byte(`{"test":"test"}`),
			[]byte(``),
			[]byte(`{"test":"test"}`),
		}
		b := &strings.Builder{}
		enc := BorrowEncoder(b)
		err := enc.EncodeArray(ear)
		assert.Nil(t, err, "err should be nil")
		assert.Equal(
			t,
			b.String(),
			`["test",{"test":"test"},{"test":"test"}]`,
			"b should be equal to content of EmbeddedJSON",
		)
	})
	t.Run("write-error", func(t *testing.T) {
		w := TestWriterError("")
		v := EmbeddedJSON([]byte(`"test"`))
		enc := NewEncoder(w)
		err := enc.EncodeEmbeddedJSON(&v)
		assert.NotNil(t, err, "Error should not be nil")
		assert.Equal(t, "Test Error", err.Error(), "err.Error() should be 'Test Error'")
	})
	t.Run("pool-error", func(t *testing.T) {
		v := EmbeddedJSON([]byte(`"test"`))
		enc := BorrowEncoder(nil)
		enc.isPooled = 1
		defer func() {
			err := recover()
			assert.NotNil(t, err, "err shouldnt be nil")
			assert.IsType(t, InvalidUsagePooledEncoderError(""), err, "err should be of type InvalidUsagePooledEncoderError")
			assert.Equal(t, "Invalid usage of pooled encoder", err.(InvalidUsagePooledEncoderError).Error(), "err should be of type InvalidUsagePooledDecoderError")
		}()
		_ = enc.EncodeEmbeddedJSON(&v)
		assert.True(t, false, "should not be called as it should have panicked")
	})
}
