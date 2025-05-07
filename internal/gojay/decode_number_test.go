package gojay

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeNumberExra(t *testing.T) {
	t.Run("skip-number-err", func(t *testing.T) {
		dec := NewDecoder(strings.NewReader("123456afzfz343"))
		_, err := dec.skipNumber()
		assert.NotNil(t, err, "err should not be nil")
		assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
	})
	t.Run("get-exponent-err", func(t *testing.T) {
		v := 0
		dec := NewDecoder(strings.NewReader("1.2Ea"))
		err := dec.Decode(&v)
		assert.NotNil(t, err, "err should not be nil")
		assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
	})
}
