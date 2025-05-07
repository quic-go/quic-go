package gojay

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestEncodeTime(t *testing.T) {
	testCases := []struct {
		name         string
		tt           string
		format       string
		expectedJSON string
		err          bool
	}{
		{
			name:         "basic",
			tt:           "2018-02-01",
			format:       "2006-01-02",
			expectedJSON: `"2018-02-01"`,
			err:          false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			b := strings.Builder{}
			tt, err := time.Parse(testCase.format, testCase.tt)
			assert.Nil(t, err)
			enc := NewEncoder(&b)
			err = enc.EncodeTime(&tt, testCase.format)
			if !testCase.err {
				assert.Nil(t, err)
				assert.Equal(t, testCase.expectedJSON, b.String())
			}
		})
	}
	t.Run("encode-time-pool-error", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := NewEncoder(builder)
		enc.isPooled = 1
		defer func() {
			err := recover()
			assert.NotNil(t, err, "err should not be nil")
			assert.IsType(t, InvalidUsagePooledEncoderError(""), err, "err should be of type InvalidUsagePooledEncoderError")
		}()
		_ = enc.EncodeTime(&time.Time{}, "")
		assert.True(t, false, "should not be called as encoder should have panicked")
	})
	t.Run("write-error", func(t *testing.T) {
		w := TestWriterError("")
		enc := BorrowEncoder(w)
		defer enc.Release()
		err := enc.EncodeTime(&time.Time{}, "")
		assert.NotNil(t, err, "err should not be nil")
	})
}

func TestAddTimeKey(t *testing.T) {
	testCases := []struct {
		name         string
		tt           string
		format       string
		expectedJSON string
		baseJSON     string
		err          bool
	}{
		{
			name:         "basic",
			tt:           "2018-02-01",
			format:       "2006-01-02",
			baseJSON:     "{",
			expectedJSON: `{"test":"2018-02-01"`,
			err:          false,
		},
		{
			name:         "basic",
			tt:           "2018-02-01",
			format:       "2006-01-02",
			baseJSON:     `{""`,
			expectedJSON: `{"","test":"2018-02-01"`,
			err:          false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			b := strings.Builder{}
			tt, err := time.Parse(testCase.format, testCase.tt)
			assert.Nil(t, err)
			enc := NewEncoder(&b)
			enc.writeString(testCase.baseJSON)
			enc.AddTimeKey("test", &tt, testCase.format)
			enc.Write()
			if !testCase.err {
				assert.Nil(t, err)
				assert.Equal(t, testCase.expectedJSON, b.String())
			}
		})
	}
}

func TestAddTime(t *testing.T) {
	testCases := []struct {
		name         string
		tt           string
		format       string
		expectedJSON string
		baseJSON     string
		err          bool
	}{
		{
			name:         "basic",
			tt:           "2018-02-01",
			format:       "2006-01-02",
			baseJSON:     "[",
			expectedJSON: `["2018-02-01"`,
			err:          false,
		},
		{
			name:         "basic",
			tt:           "2018-02-01",
			format:       "2006-01-02",
			baseJSON:     "[",
			expectedJSON: `["2018-02-01"`,
			err:          false,
		},
		{
			name:         "basic",
			tt:           "2018-02-01",
			format:       "2006-01-02",
			baseJSON:     `[""`,
			expectedJSON: `["","2018-02-01"`,
			err:          false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			b := strings.Builder{}
			tt, err := time.Parse(testCase.format, testCase.tt)
			assert.Nil(t, err)
			enc := NewEncoder(&b)
			enc.writeString(testCase.baseJSON)
			enc.AddTime(&tt, testCase.format)
			enc.Write()
			if !testCase.err {
				assert.Nil(t, err)
				assert.Equal(t, testCase.expectedJSON, b.String())
			}
		})
	}
}
