package gojay

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type Request struct {
	id     string
	method string
	params EmbeddedJSON
	more   int
}

func (r *Request) UnmarshalJSONObject(dec *Decoder, key string) error {
	switch key {
	case "id":
		return dec.AddString(&r.id)
	case "method":
		return dec.AddString(&r.method)
	case "params":
		return dec.AddEmbeddedJSON(&r.params)
	case "more":
		dec.AddInt(&r.more)
	}
	return nil
}

func (r *Request) NKeys() int {
	return 4
}

func TestDecodeEmbeddedJSONUnmarshalAPI(t *testing.T) {
	testCases := []struct {
		name             string
		json             []byte
		expectedEmbedded string
		err              bool
	}{
		{
			name:             "decode-basic-string",
			json:             []byte(`{"id":"someid","method":"getmydata","params":"raw data", "more":123}`),
			expectedEmbedded: `"raw data"`,
		},
		{
			name:             "decode-basic-int",
			json:             []byte(`{"id":"someid","method":"getmydata","params":12345, "more":123}`),
			expectedEmbedded: `12345`,
		},
		{
			name:             "decode-basic-int",
			json:             []byte(`{"id":"someid","method":"getmydata","params":true, "more":123}`),
			expectedEmbedded: `true`,
		},
		{
			name:             "decode-basic-int",
			json:             []byte(`{"id":"someid","method":"getmydata","params": false, "more":123}`),
			expectedEmbedded: `false`,
		},
		{
			name:             "decode-basic-int",
			json:             []byte(`{"id":"someid","method":"getmydata","params":null, "more":123}`),
			expectedEmbedded: `null`,
		},
		{
			name:             "decode-basic-object",
			json:             []byte(`{"id":"someid","method":"getmydata","params":{"example":"of raw data"}, "more":123}`),
			expectedEmbedded: `{"example":"of raw data"}`,
		},
		{
			name:             "decode-basic-object",
			json:             []byte(`{"id":"someid","method":"getmydata","params":[1,2,3], "more":123}`),
			expectedEmbedded: `[1,2,3]`,
		},
		{
			name:             "decode-null-err",
			json:             []byte(`{"id":"someid","method":"getmydata","params":nil, "more":123}`),
			expectedEmbedded: ``,
			err:              true,
		},
		{
			name:             "decode-bool-false-err",
			json:             []byte(`{"id":"someid","method":"getmydata","params":faulse, "more":123}`),
			expectedEmbedded: ``,
			err:              true,
		},
		{
			name:             "decode-bool-true-err",
			json:             []byte(`{"id":"someid","method":"getmydata","params":trou, "more":123}`),
			expectedEmbedded: ``,
			err:              true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			req := &Request{}
			err := Unmarshal(testCase.json, req)
			t.Log(req)
			t.Log(string(req.params))
			if testCase.err {
				assert.NotNil(t, err, "err should not be nil")
			} else {
				assert.Nil(t, err, "err should be nil")
			}
			assert.Equal(t, testCase.expectedEmbedded, string(req.params), "r.params should be equal to expectedEmbeddedResult")
		})
	}
}

func TestDecodeEmbeddedJSONDecodeAPI(t *testing.T) {
	testCases := []struct {
		name             string
		json             []byte
		expectedEmbedded string
	}{
		{
			name:             "decode-basic-string",
			json:             []byte(`{"id":"someid","method":"getmydata","params":"raw data", "more":123}`),
			expectedEmbedded: `"raw data"`,
		},
		{
			name:             "decode-basic-int",
			json:             []byte(`{"id":"someid","method":"getmydata","params":12345, "more":123}`),
			expectedEmbedded: `12345`,
		},
		{
			name:             "decode-basic-int",
			json:             []byte(`{"id":"someid","method":"getmydata","params":true, "more":123}`),
			expectedEmbedded: `true`,
		},
		{
			name:             "decode-basic-int",
			json:             []byte(`{"id":"someid","method":"getmydata","params": false, "more":123}`),
			expectedEmbedded: `false`,
		},
		{
			name:             "decode-basic-int",
			json:             []byte(`{"id":"someid","method":"getmydata","params":null, "more":123}`),
			expectedEmbedded: `null`,
		},
		{
			name:             "decode-basic-object",
			json:             []byte(`{"id":"someid","method":"getmydata","params":{"example":"of raw data"}, "more":123}`),
			expectedEmbedded: `{"example":"of raw data"}`,
		},
		{
			name:             "decode-basic-object",
			json:             []byte(`{"id":"someid","method":"getmydata","params":[1,2,3], "more":123}`),
			expectedEmbedded: `[1,2,3]`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ej := EmbeddedJSON([]byte{})
			dec := BorrowDecoder(bytes.NewReader(testCase.json))
			err := dec.Decode(&ej)
			assert.Nil(t, err, "err should be nil")
			assert.Equal(t, string(testCase.json), string(ej), "r.params should be equal to expectedEmbeddedResult")
		})
	}
}

func TestDecodeEmbeededJSONNil(t *testing.T) {
	dec := BorrowDecoder(strings.NewReader(`"bar"`))
	var ej *EmbeddedJSON
	err := dec.decodeEmbeddedJSON(ej)
	assert.NotNil(t, err, `err should not be nil a nil pointer is given`)
	assert.IsType(t, InvalidUnmarshalError(""), err, `err should not be of type InvalidUnmarshalError`)
}

func TestDecodeEmbeededJSONNil2(t *testing.T) {
	dec := BorrowDecoder(strings.NewReader(`"bar"`))
	var ej *EmbeddedJSON
	err := dec.AddEmbeddedJSON(ej)
	assert.NotNil(t, err, `err should not be nil a nil pointer is given`)
	assert.IsType(t, InvalidUnmarshalError(""), err, `err should not be of type InvalidUnmarshalError`)
}
