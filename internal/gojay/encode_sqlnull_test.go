package gojay

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Null String
func TestEncoceSQLNullString(t *testing.T) {
	testCases := []struct {
		name           string
		sqlNullString  sql.NullString
		expectedResult string
		err            bool
	}{
		{
			name: "it should encode a null string",
			sqlNullString: sql.NullString{
				String: "foo bar",
			},
			expectedResult: `"foo bar"`,
		},
		{
			name: "it should return an err as the string is invalid",
			sqlNullString: sql.NullString{
				String: "foo \t bar",
			},
			expectedResult: `"foo \t bar"`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var b strings.Builder
			enc := NewEncoder(&b)
			err := enc.EncodeSQLNullString(&testCase.sqlNullString)
			if testCase.err {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, testCase.expectedResult, b.String())
			}
		})
	}

	t.Run(
		"should panic as the encoder is pooled",
		func(t *testing.T) {
			builder := &strings.Builder{}
			enc := NewEncoder(builder)
			enc.isPooled = 1
			defer func() {
				err := recover()
				assert.NotNil(t, err, "err should not be nil")
				assert.IsType(t, InvalidUsagePooledEncoderError(""), err, "err should be of type InvalidUsagePooledEncoderError")
			}()
			_ = enc.EncodeSQLNullString(&sql.NullString{})
			assert.True(t, false, "should not be called as encoder should have panicked")
		},
	)

	t.Run(
		"should return an error as the writer encounters an error",
		func(t *testing.T) {
			builder := TestWriterError("")
			enc := NewEncoder(builder)
			err := enc.EncodeSQLNullString(&sql.NullString{})
			assert.NotNil(t, err)
		},
	)
}

func TestAddSQLNullStringKey(t *testing.T) {
	t.Run(
		"AddSQLNullStringKey",
		func(t *testing.T) {
			testCases := []struct {
				name           string
				sqlNullString  sql.NullString
				baseJSON       string
				expectedResult string
				err            bool
			}{
				{
					name: "it should encode a null string",
					sqlNullString: sql.NullString{
						String: "foo bar",
					},
					baseJSON:       "{",
					expectedResult: `{"foo":"foo bar"`,
				},
				{
					name: "it should encode a null string",
					sqlNullString: sql.NullString{
						String: "foo \t bar",
					},
					baseJSON:       "{",
					expectedResult: `{"foo":"foo \t bar"`,
				},
				{
					name: "it should encode a null string",
					sqlNullString: sql.NullString{
						String: "foo \t bar",
					},
					baseJSON:       "{",
					expectedResult: `{"foo":"foo \t bar"`,
				},
			}

			for _, testCase := range testCases {
				t.Run(testCase.name, func(t *testing.T) {
					var b strings.Builder
					enc := NewEncoder(&b)
					enc.writeString(testCase.baseJSON)
					enc.AddSQLNullStringKey("foo", &testCase.sqlNullString)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b.String())

					var b2 strings.Builder
					enc = NewEncoder(&b2)
					enc.writeString(testCase.baseJSON)
					enc.SQLNullStringKey("foo", &testCase.sqlNullString)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b2.String())
				})
			}
		},
	)
	t.Run(
		"AddSQLNullStringKeyOmitEmpty, is should encode a sql.NullString",
		func(t *testing.T) {
			testCases := []struct {
				name           string
				sqlNullString  sql.NullString
				baseJSON       string
				expectedResult string
				err            bool
			}{
				{
					name: "it should encode a null string",
					sqlNullString: sql.NullString{
						String: "foo bar",
						Valid:  true,
					},
					baseJSON:       "{",
					expectedResult: `{"foo":"foo bar"`,
				},
				{
					name: "it should not encode anything as null string is invalid",
					sqlNullString: sql.NullString{
						String: "foo \t bar",
						Valid:  false,
					},
					baseJSON:       "{",
					expectedResult: `{`,
				},
			}

			for _, testCase := range testCases {
				t.Run(testCase.name, func(t *testing.T) {
					var b strings.Builder
					enc := NewEncoder(&b)
					enc.writeString(testCase.baseJSON)
					enc.AddSQLNullStringKeyOmitEmpty("foo", &testCase.sqlNullString)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b.String())

					var b2 strings.Builder
					enc = NewEncoder(&b2)
					enc.writeString(testCase.baseJSON)
					enc.SQLNullStringKeyOmitEmpty("foo", &testCase.sqlNullString)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b2.String())
				})
			}
		},
	)
}

func TestAddSQLNullString(t *testing.T) {
	t.Run(
		"AddSQLNullString",
		func(t *testing.T) {
			testCases := []struct {
				name           string
				sqlNullString  sql.NullString
				baseJSON       string
				expectedResult string
				err            bool
			}{
				{
					name: "it should encode a null string",
					sqlNullString: sql.NullString{
						String: "foo bar",
					},
					baseJSON:       "[",
					expectedResult: `["foo bar"`,
				},
				{
					name: "it should encode a null string",
					sqlNullString: sql.NullString{
						String: "foo \t bar",
					},
					baseJSON:       "[",
					expectedResult: `["foo \t bar"`,
				},
				{
					name: "it should encode a null string",
					sqlNullString: sql.NullString{
						String: "foo \t bar",
					},
					baseJSON:       "[",
					expectedResult: `["foo \t bar"`,
				},
			}

			for _, testCase := range testCases {
				t.Run(testCase.name, func(t *testing.T) {
					var b strings.Builder
					enc := NewEncoder(&b)
					enc.writeString(testCase.baseJSON)
					enc.AddSQLNullString(&testCase.sqlNullString)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b.String())

					var b2 strings.Builder
					enc = NewEncoder(&b2)
					enc.writeString(testCase.baseJSON)
					enc.SQLNullString(&testCase.sqlNullString)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b2.String())
				})
			}
		},
	)
	t.Run(
		"AddSQLNullStringKeyOmitEmpty, is should encode a sql.NullString",
		func(t *testing.T) {
			testCases := []struct {
				name           string
				sqlNullString  sql.NullString
				baseJSON       string
				expectedResult string
				err            bool
			}{
				{
					name: "it should encode a null string",
					sqlNullString: sql.NullString{
						String: "foo bar",
						Valid:  true,
					},
					baseJSON:       "[",
					expectedResult: `["foo bar"`,
				},
				{
					name: "it should not encode anything as null string is invalid",
					sqlNullString: sql.NullString{
						String: "foo \t bar",
						Valid:  false,
					},
					baseJSON:       "[",
					expectedResult: `[`,
				},
			}

			for _, testCase := range testCases {
				t.Run(testCase.name, func(t *testing.T) {
					var b strings.Builder
					enc := NewEncoder(&b)
					enc.writeString(testCase.baseJSON)
					enc.AddSQLNullStringOmitEmpty(&testCase.sqlNullString)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b.String())

					var b2 strings.Builder
					enc = NewEncoder(&b2)
					enc.writeString(testCase.baseJSON)
					enc.SQLNullStringOmitEmpty(&testCase.sqlNullString)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b2.String())
				})
			}
		},
	)
}

// NullInt64
func TestEncoceSQLNullInt64(t *testing.T) {
	testCases := []struct {
		name           string
		sqlNullInt64   sql.NullInt64
		expectedResult string
		err            bool
	}{
		{
			name: "it should encode a null string",
			sqlNullInt64: sql.NullInt64{
				Int64: int64(1),
			},
			expectedResult: `1`,
		},
		{
			name: "it should return an err as the string is invalid",
			sqlNullInt64: sql.NullInt64{
				Int64: int64(2),
			},
			expectedResult: `2`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var b strings.Builder
			enc := NewEncoder(&b)
			err := enc.EncodeSQLNullInt64(&testCase.sqlNullInt64)
			if testCase.err {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, testCase.expectedResult, b.String())
			}
		})
	}
	t.Run(
		"should panic as the encoder is pooled",
		func(t *testing.T) {
			builder := &strings.Builder{}
			enc := NewEncoder(builder)
			enc.isPooled = 1
			defer func() {
				err := recover()
				assert.NotNil(t, err, "err should not be nil")
				assert.IsType(t, InvalidUsagePooledEncoderError(""), err, "err should be of type InvalidUsagePooledEncoderError")
			}()
			_ = enc.EncodeSQLNullInt64(&sql.NullInt64{})
			assert.True(t, false, "should not be called as encoder should have panicked")
		},
	)
	t.Run(
		"should return an error as the writer encounters an error",
		func(t *testing.T) {
			builder := TestWriterError("")
			enc := NewEncoder(builder)
			err := enc.EncodeSQLNullInt64(&sql.NullInt64{})
			assert.NotNil(t, err)
		},
	)
}

func TestAddSQLNullInt64Key(t *testing.T) {
	t.Run(
		"AddSQLNullInt64Key",
		func(t *testing.T) {
			testCases := []struct {
				name           string
				sqlNullInt64   sql.NullInt64
				baseJSON       string
				expectedResult string
				err            bool
			}{
				{
					name: "it should encode a null string",
					sqlNullInt64: sql.NullInt64{
						Int64: 1,
					},
					baseJSON:       "{",
					expectedResult: `{"foo":1`,
				},
				{
					name: "it should encode a null string",
					sqlNullInt64: sql.NullInt64{
						Int64: 2,
					},
					baseJSON:       "{",
					expectedResult: `{"foo":2`,
				},
				{
					name: "it should encode a null string",
					sqlNullInt64: sql.NullInt64{
						Int64: 2,
					},
					baseJSON:       "{",
					expectedResult: `{"foo":2`,
				},
			}

			for _, testCase := range testCases {
				t.Run(testCase.name, func(t *testing.T) {
					var b strings.Builder
					enc := NewEncoder(&b)
					enc.writeString(testCase.baseJSON)
					enc.AddSQLNullInt64Key("foo", &testCase.sqlNullInt64)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b.String())

					var b2 strings.Builder
					enc = NewEncoder(&b2)
					enc.writeString(testCase.baseJSON)
					enc.SQLNullInt64Key("foo", &testCase.sqlNullInt64)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b2.String())
				})
			}
		},
	)
	t.Run(
		"AddSQLNullInt64KeyOmitEmpty, is should encode a sql.NullInt64",
		func(t *testing.T) {
			testCases := []struct {
				name           string
				sqlNullInt64   sql.NullInt64
				baseJSON       string
				expectedResult string
				err            bool
			}{
				{
					name: "it should encode a null string",
					sqlNullInt64: sql.NullInt64{
						Int64: 1,
						Valid: true,
					},
					baseJSON:       "{",
					expectedResult: `{"foo":1`,
				},
				{
					name: "it should not encode anything as null string is invalid",
					sqlNullInt64: sql.NullInt64{
						Int64: 2,
						Valid: false,
					},
					baseJSON:       "{",
					expectedResult: `{`,
				},
			}

			for _, testCase := range testCases {
				t.Run(testCase.name, func(t *testing.T) {
					var b strings.Builder
					enc := NewEncoder(&b)
					enc.writeString(testCase.baseJSON)
					enc.AddSQLNullInt64KeyOmitEmpty("foo", &testCase.sqlNullInt64)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b.String())

					var b2 strings.Builder
					enc = NewEncoder(&b2)
					enc.writeString(testCase.baseJSON)
					enc.SQLNullInt64KeyOmitEmpty("foo", &testCase.sqlNullInt64)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b2.String())
				})
			}
		},
	)
}

func TestAddSQLNullInt64(t *testing.T) {
	t.Run(
		"AddSQLNullInt64",
		func(t *testing.T) {
			testCases := []struct {
				name           string
				sqlNullInt64   sql.NullInt64
				baseJSON       string
				expectedResult string
				err            bool
			}{
				{
					name: "it should encode a null string",
					sqlNullInt64: sql.NullInt64{
						Int64: 1,
					},
					baseJSON:       "[",
					expectedResult: `[1`,
				},
				{
					name: "it should encode a null string",
					sqlNullInt64: sql.NullInt64{
						Int64: 2,
					},
					baseJSON:       "[",
					expectedResult: `[2`,
				},
				{
					name: "it should encode a null string",
					sqlNullInt64: sql.NullInt64{
						Int64: 2,
					},
					baseJSON:       "[",
					expectedResult: `[2`,
				},
			}

			for _, testCase := range testCases {
				t.Run(testCase.name, func(t *testing.T) {
					var b strings.Builder
					enc := NewEncoder(&b)
					enc.writeString(testCase.baseJSON)
					enc.AddSQLNullInt64(&testCase.sqlNullInt64)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b.String())

					var b2 strings.Builder
					enc = NewEncoder(&b2)
					enc.writeString(testCase.baseJSON)
					enc.SQLNullInt64(&testCase.sqlNullInt64)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b2.String())
				})
			}
		},
	)
	t.Run(
		"AddSQLNullInt64KeyOmitEmpty, is should encode a sql.NullInt64",
		func(t *testing.T) {
			testCases := []struct {
				name           string
				sqlNullInt64   sql.NullInt64
				baseJSON       string
				expectedResult string
				err            bool
			}{
				{
					name: "it should encode a null string",
					sqlNullInt64: sql.NullInt64{
						Int64: 2,
						Valid: true,
					},
					baseJSON:       "[",
					expectedResult: `[2`,
				},
				{
					name: "it should not encode anything as null string is invalid",
					sqlNullInt64: sql.NullInt64{
						Int64: 2,
						Valid: false,
					},
					baseJSON:       "[",
					expectedResult: `[`,
				},
			}

			for _, testCase := range testCases {
				t.Run(testCase.name, func(t *testing.T) {
					var b strings.Builder
					enc := NewEncoder(&b)
					enc.writeString(testCase.baseJSON)
					enc.AddSQLNullInt64OmitEmpty(&testCase.sqlNullInt64)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b.String())

					var b2 strings.Builder
					enc = NewEncoder(&b2)
					enc.writeString(testCase.baseJSON)
					enc.SQLNullInt64OmitEmpty(&testCase.sqlNullInt64)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b2.String())
				})
			}
		},
	)
}

// NullFloat64
func TestEncoceSQLNullFloat64(t *testing.T) {
	testCases := []struct {
		name           string
		sqlNullFloat64 sql.NullFloat64
		expectedResult string
		err            bool
	}{
		{
			name: "it should encode a null string",
			sqlNullFloat64: sql.NullFloat64{
				Float64: float64(1),
			},
			expectedResult: `1`,
		},
		{
			name: "it should return an err as the string is invalid",
			sqlNullFloat64: sql.NullFloat64{
				Float64: float64(2),
			},
			expectedResult: `2`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var b strings.Builder
			enc := NewEncoder(&b)
			err := enc.EncodeSQLNullFloat64(&testCase.sqlNullFloat64)
			if testCase.err {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, testCase.expectedResult, b.String())
			}
		})
	}
	t.Run(
		"should panic as the encoder is pooled",
		func(t *testing.T) {
			builder := &strings.Builder{}
			enc := NewEncoder(builder)
			enc.isPooled = 1
			defer func() {
				err := recover()
				assert.NotNil(t, err, "err should not be nil")
				assert.IsType(t, InvalidUsagePooledEncoderError(""), err, "err should be of type InvalidUsagePooledEncoderError")
			}()
			_ = enc.EncodeSQLNullFloat64(&sql.NullFloat64{})
			assert.True(t, false, "should not be called as encoder should have panicked")
		},
	)

	t.Run(
		"should return an error as the writer encounters an error",
		func(t *testing.T) {
			builder := TestWriterError("")
			enc := NewEncoder(builder)
			err := enc.EncodeSQLNullFloat64(&sql.NullFloat64{})
			assert.NotNil(t, err)
		},
	)
}

func TestAddSQLNullFloat64Key(t *testing.T) {
	t.Run(
		"AddSQLNullFloat64Key",
		func(t *testing.T) {
			testCases := []struct {
				name           string
				sqlNullFloat64 sql.NullFloat64
				baseJSON       string
				expectedResult string
				err            bool
			}{
				{
					name: "it should encode a null string",
					sqlNullFloat64: sql.NullFloat64{
						Float64: 1,
					},
					baseJSON:       "{",
					expectedResult: `{"foo":1`,
				},
				{
					name: "it should encode a null string",
					sqlNullFloat64: sql.NullFloat64{
						Float64: 2,
					},
					baseJSON:       "{",
					expectedResult: `{"foo":2`,
				},
				{
					name: "it should encode a null string",
					sqlNullFloat64: sql.NullFloat64{
						Float64: 2,
					},
					baseJSON:       "{",
					expectedResult: `{"foo":2`,
				},
			}

			for _, testCase := range testCases {
				t.Run(testCase.name, func(t *testing.T) {
					var b strings.Builder
					enc := NewEncoder(&b)
					enc.writeString(testCase.baseJSON)
					enc.AddSQLNullFloat64Key("foo", &testCase.sqlNullFloat64)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b.String())

					var b2 strings.Builder
					enc = NewEncoder(&b2)
					enc.writeString(testCase.baseJSON)
					enc.SQLNullFloat64Key("foo", &testCase.sqlNullFloat64)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b2.String())
				})
			}
		},
	)
	t.Run(
		"AddSQLNullFloat64KeyOmitEmpty, is should encode a sql.NullFloat64",
		func(t *testing.T) {
			testCases := []struct {
				name           string
				sqlNullFloat64 sql.NullFloat64
				baseJSON       string
				expectedResult string
				err            bool
			}{
				{
					name: "it should encode a null string",
					sqlNullFloat64: sql.NullFloat64{
						Float64: 1,
						Valid:   true,
					},
					baseJSON:       "{",
					expectedResult: `{"foo":1`,
				},
				{
					name: "it should not encode anything as null string is invalid",
					sqlNullFloat64: sql.NullFloat64{
						Float64: 2,
						Valid:   false,
					},
					baseJSON:       "{",
					expectedResult: `{`,
				},
			}

			for _, testCase := range testCases {
				t.Run(testCase.name, func(t *testing.T) {
					var b strings.Builder
					enc := NewEncoder(&b)
					enc.writeString(testCase.baseJSON)
					enc.AddSQLNullFloat64KeyOmitEmpty("foo", &testCase.sqlNullFloat64)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b.String())

					var b2 strings.Builder
					enc = NewEncoder(&b2)
					enc.writeString(testCase.baseJSON)
					enc.SQLNullFloat64KeyOmitEmpty("foo", &testCase.sqlNullFloat64)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b2.String())
				})
			}
		},
	)
}

func TestAddSQLNullFloat64(t *testing.T) {
	t.Run(
		"AddSQLNullFloat64",
		func(t *testing.T) {
			testCases := []struct {
				name           string
				sqlNullFloat64 sql.NullFloat64
				baseJSON       string
				expectedResult string
				err            bool
			}{
				{
					name: "it should encode a null string",
					sqlNullFloat64: sql.NullFloat64{
						Float64: 1,
					},
					baseJSON:       "[",
					expectedResult: `[1`,
				},
				{
					name: "it should encode a null string",
					sqlNullFloat64: sql.NullFloat64{
						Float64: 2,
					},
					baseJSON:       "[",
					expectedResult: `[2`,
				},
				{
					name: "it should encode a null string",
					sqlNullFloat64: sql.NullFloat64{
						Float64: 2,
					},
					baseJSON:       "[",
					expectedResult: `[2`,
				},
			}

			for _, testCase := range testCases {
				t.Run(testCase.name, func(t *testing.T) {
					var b strings.Builder
					enc := NewEncoder(&b)
					enc.writeString(testCase.baseJSON)
					enc.AddSQLNullFloat64(&testCase.sqlNullFloat64)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b.String())

					var b2 strings.Builder
					enc = NewEncoder(&b2)
					enc.writeString(testCase.baseJSON)
					enc.SQLNullFloat64(&testCase.sqlNullFloat64)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b2.String())
				})
			}
		},
	)
	t.Run(
		"AddSQLNullFloat64KeyOmitEmpty, is should encode a sql.NullFloat64",
		func(t *testing.T) {
			testCases := []struct {
				name           string
				sqlNullFloat64 sql.NullFloat64
				baseJSON       string
				expectedResult string
				err            bool
			}{
				{
					name: "it should encode a null string",
					sqlNullFloat64: sql.NullFloat64{
						Float64: 2,
						Valid:   true,
					},
					baseJSON:       "[",
					expectedResult: `[2`,
				},
				{
					name: "it should not encode anything as null string is invalid",
					sqlNullFloat64: sql.NullFloat64{
						Float64: 2,
						Valid:   false,
					},
					baseJSON:       "[",
					expectedResult: `[`,
				},
			}

			for _, testCase := range testCases {
				t.Run(testCase.name, func(t *testing.T) {
					var b strings.Builder
					enc := NewEncoder(&b)
					enc.writeString(testCase.baseJSON)
					enc.AddSQLNullFloat64OmitEmpty(&testCase.sqlNullFloat64)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b.String())

					var b2 strings.Builder
					enc = NewEncoder(&b2)
					enc.writeString(testCase.baseJSON)
					enc.SQLNullFloat64OmitEmpty(&testCase.sqlNullFloat64)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b2.String())
				})
			}
		},
	)
}

// NullBool
func TestEncoceSQLNullBool(t *testing.T) {
	testCases := []struct {
		name           string
		sqlNullBool    sql.NullBool
		expectedResult string
		err            bool
	}{
		{
			name: "it should encode a null string",
			sqlNullBool: sql.NullBool{
				Bool: true,
			},
			expectedResult: `true`,
		},
		{
			name: "it should return an err as the string is invalid",
			sqlNullBool: sql.NullBool{
				Bool: false,
			},
			expectedResult: `false`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var b strings.Builder
			enc := NewEncoder(&b)
			err := enc.EncodeSQLNullBool(&testCase.sqlNullBool)
			if testCase.err {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, testCase.expectedResult, b.String())
			}
		})
	}
	t.Run(
		"should panic as the encoder is pooled",
		func(t *testing.T) {
			builder := &strings.Builder{}
			enc := NewEncoder(builder)
			enc.isPooled = 1
			defer func() {
				err := recover()
				assert.NotNil(t, err, "err should not be nil")
				assert.IsType(t, InvalidUsagePooledEncoderError(""), err, "err should be of type InvalidUsagePooledEncoderError")
			}()
			_ = enc.EncodeSQLNullBool(&sql.NullBool{})
			assert.True(t, false, "should not be called as encoder should have panicked")
		},
	)

	t.Run(
		"should return an error as the writer encounters an error",
		func(t *testing.T) {
			builder := TestWriterError("")
			enc := NewEncoder(builder)
			err := enc.EncodeSQLNullBool(&sql.NullBool{})
			assert.NotNil(t, err)
		},
	)
}

func TestAddSQLNullBoolKey(t *testing.T) {
	t.Run(
		"AddSQLNullBoolKey",
		func(t *testing.T) {
			testCases := []struct {
				name           string
				sqlNullBool    sql.NullBool
				baseJSON       string
				expectedResult string
				err            bool
			}{
				{
					name: "it should encode a null string",
					sqlNullBool: sql.NullBool{
						Bool: true,
					},
					baseJSON:       "{",
					expectedResult: `{"foo":true`,
				},
				{
					name: "it should encode a null string",
					sqlNullBool: sql.NullBool{
						Bool: false,
					},
					baseJSON:       "{",
					expectedResult: `{"foo":false`,
				},
				{
					name: "it should encode a null string",
					sqlNullBool: sql.NullBool{
						Bool: true,
					},
					baseJSON:       "{",
					expectedResult: `{"foo":true`,
				},
			}

			for _, testCase := range testCases {
				t.Run(testCase.name, func(t *testing.T) {
					var b strings.Builder
					enc := NewEncoder(&b)
					enc.writeString(testCase.baseJSON)
					enc.AddSQLNullBoolKey("foo", &testCase.sqlNullBool)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b.String())

					var b2 strings.Builder
					enc = NewEncoder(&b2)
					enc.writeString(testCase.baseJSON)
					enc.SQLNullBoolKey("foo", &testCase.sqlNullBool)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b2.String())
				})
			}
		},
	)
	t.Run(
		"AddSQLNullBoolKeyOmitEmpty, is should encode a sql.NullBool",
		func(t *testing.T) {
			testCases := []struct {
				name           string
				sqlNullBool    sql.NullBool
				baseJSON       string
				expectedResult string
				err            bool
			}{
				{
					name: "it should encode a null string",
					sqlNullBool: sql.NullBool{
						Bool:  true,
						Valid: true,
					},
					baseJSON:       "{",
					expectedResult: `{"foo":true`,
				},
				{
					name: "it should not encode anything as null string is invalid",
					sqlNullBool: sql.NullBool{
						Bool:  true,
						Valid: false,
					},
					baseJSON:       "{",
					expectedResult: `{`,
				},
			}

			for _, testCase := range testCases {
				t.Run(testCase.name, func(t *testing.T) {
					var b strings.Builder
					enc := NewEncoder(&b)
					enc.writeString(testCase.baseJSON)
					enc.AddSQLNullBoolKeyOmitEmpty("foo", &testCase.sqlNullBool)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b.String())

					var b2 strings.Builder
					enc = NewEncoder(&b2)
					enc.writeString(testCase.baseJSON)
					enc.SQLNullBoolKeyOmitEmpty("foo", &testCase.sqlNullBool)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b2.String())
				})
			}
		},
	)
}

func TestAddSQLNullBool(t *testing.T) {
	t.Run(
		"AddSQLNullBool",
		func(t *testing.T) {
			testCases := []struct {
				name           string
				sqlNullBool    sql.NullBool
				baseJSON       string
				expectedResult string
				err            bool
			}{
				{
					name: "it should encode a null string",
					sqlNullBool: sql.NullBool{
						Bool: true,
					},
					baseJSON:       "[",
					expectedResult: `[true`,
				},
				{
					name: "it should encode a null string",
					sqlNullBool: sql.NullBool{
						Bool: true,
					},
					baseJSON:       "[",
					expectedResult: `[true`,
				},
				{
					name: "it should encode a null string",
					sqlNullBool: sql.NullBool{
						Bool: false,
					},
					baseJSON:       "[",
					expectedResult: `[false`,
				},
			}

			for _, testCase := range testCases {
				t.Run(testCase.name, func(t *testing.T) {
					var b strings.Builder
					enc := NewEncoder(&b)
					enc.writeString(testCase.baseJSON)
					enc.AddSQLNullBool(&testCase.sqlNullBool)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b.String())

					var b2 strings.Builder
					enc = NewEncoder(&b2)
					enc.writeString(testCase.baseJSON)
					enc.SQLNullBool(&testCase.sqlNullBool)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b2.String())
				})
			}
		},
	)
	t.Run(
		"AddSQLNullBoolKeyOmitEmpty, is should encode a sql.NullBool",
		func(t *testing.T) {
			testCases := []struct {
				name           string
				sqlNullBool    sql.NullBool
				baseJSON       string
				expectedResult string
				err            bool
			}{
				{
					name: "it should encode a null string",
					sqlNullBool: sql.NullBool{
						Bool:  true,
						Valid: true,
					},
					baseJSON:       "[",
					expectedResult: `[true`,
				},
				{
					name: "it should not encode anything as null string is invalid",
					sqlNullBool: sql.NullBool{
						Bool:  true,
						Valid: false,
					},
					baseJSON:       "[",
					expectedResult: `[`,
				},
			}

			for _, testCase := range testCases {
				t.Run(testCase.name, func(t *testing.T) {
					var b strings.Builder
					enc := NewEncoder(&b)
					enc.writeString(testCase.baseJSON)
					enc.AddSQLNullBoolOmitEmpty(&testCase.sqlNullBool)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b.String())

					var b2 strings.Builder
					enc = NewEncoder(&b2)
					enc.writeString(testCase.baseJSON)
					enc.SQLNullBoolOmitEmpty(&testCase.sqlNullBool)
					enc.Write()
					assert.Equal(t, testCase.expectedResult, b2.String())
				})
			}
		},
	)
}

func TestEncoderSQLNullStringEmpty(t *testing.T) {
	var testCases = []struct {
		name         string
		baseJSON     string
		expectedJSON string
	}{
		{
			name:         "basic 1st elem",
			baseJSON:     "[",
			expectedJSON: `[null,"bar"`,
		},
		{
			name:         "basic 2nd elem",
			baseJSON:     `["test"`,
			expectedJSON: `["test",null,"bar"`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var b strings.Builder
			var enc = NewEncoder(&b)
			enc.writeString(testCase.baseJSON)
			enc.AddSQLNullStringNullEmpty(&sql.NullString{"", true})
			enc.SQLNullStringNullEmpty(&sql.NullString{"bar", true})
			enc.Write()
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
}

func TestEncoderSQLNullStringKeyNullEmpty(t *testing.T) {
	var testCases = []struct {
		name         string
		baseJSON     string
		expectedJSON string
	}{
		{
			name:         "basic 1st elem",
			baseJSON:     "{",
			expectedJSON: `{"foo":null,"bar":"bar"`,
		},
		{
			name:         "basic 2nd elem",
			baseJSON:     `{"test":"test"`,
			expectedJSON: `{"test":"test","foo":null,"bar":"bar"`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var b strings.Builder
			var enc = NewEncoder(&b)
			enc.writeString(testCase.baseJSON)
			enc.SQLNullStringKeyNullEmpty("foo", &sql.NullString{"", true})
			enc.SQLNullStringKeyNullEmpty("bar", &sql.NullString{"bar", true})
			enc.Write()
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
}

func TestEncoderSQLNullBoolEmpty(t *testing.T) {
	var testCases = []struct {
		name         string
		baseJSON     string
		expectedJSON string
	}{
		{
			name:         "basic 1st elem",
			baseJSON:     "[",
			expectedJSON: `[null,true`,
		},
		{
			name:         "basic 2nd elem",
			baseJSON:     `["test"`,
			expectedJSON: `["test",null,true`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var b strings.Builder
			var enc = NewEncoder(&b)
			enc.writeString(testCase.baseJSON)
			enc.SQLNullBoolNullEmpty(&sql.NullBool{false, true})
			enc.SQLNullBoolNullEmpty(&sql.NullBool{true, true})
			enc.Write()
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
}

func TestEncoderSQLNullBoolKeyNullEmpty(t *testing.T) {
	var testCases = []struct {
		name         string
		baseJSON     string
		expectedJSON string
	}{
		{
			name:         "basic 1st elem",
			baseJSON:     "{",
			expectedJSON: `{"foo":null,"bar":true`,
		},
		{
			name:         "basic 2nd elem",
			baseJSON:     `{"test":"test"`,
			expectedJSON: `{"test":"test","foo":null,"bar":true`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var b strings.Builder
			var enc = NewEncoder(&b)
			enc.writeString(testCase.baseJSON)
			enc.AddSQLNullBoolKeyNullEmpty("foo", &sql.NullBool{false, true})
			enc.SQLNullBoolKeyNullEmpty("bar", &sql.NullBool{true, true})
			enc.Write()
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
}

func TestEncoderSQLNullInt64Empty(t *testing.T) {
	var testCases = []struct {
		name         string
		baseJSON     string
		expectedJSON string
	}{
		{
			name:         "basic 1st elem",
			baseJSON:     "[",
			expectedJSON: `[null,1`,
		},
		{
			name:         "basic 2nd elem",
			baseJSON:     `["test"`,
			expectedJSON: `["test",null,1`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var b strings.Builder
			var enc = NewEncoder(&b)
			enc.writeString(testCase.baseJSON)
			enc.AddSQLNullInt64NullEmpty(&sql.NullInt64{0, true})
			enc.SQLNullInt64NullEmpty(&sql.NullInt64{1, true})
			enc.Write()
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
}

func TestEncoderSQLNullInt64KeyNullEmpty(t *testing.T) {
	var testCases = []struct {
		name         string
		baseJSON     string
		expectedJSON string
	}{
		{
			name:         "basic 1st elem",
			baseJSON:     "{",
			expectedJSON: `{"foo":null,"bar":1`,
		},
		{
			name:         "basic 2nd elem",
			baseJSON:     `{"test":"test"`,
			expectedJSON: `{"test":"test","foo":null,"bar":1`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var b strings.Builder
			var enc = NewEncoder(&b)
			enc.writeString(testCase.baseJSON)
			enc.AddSQLNullInt64KeyNullEmpty("foo", &sql.NullInt64{0, true})
			enc.SQLNullInt64KeyNullEmpty("bar", &sql.NullInt64{1, true})
			enc.Write()
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
}

func TestEncoderSQLNullFloat64Empty(t *testing.T) {
	var testCases = []struct {
		name         string
		baseJSON     string
		expectedJSON string
	}{
		{
			name:         "basic 1st elem",
			baseJSON:     "[",
			expectedJSON: `[null,1`,
		},
		{
			name:         "basic 2nd elem",
			baseJSON:     `["test"`,
			expectedJSON: `["test",null,1`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var b strings.Builder
			var enc = NewEncoder(&b)
			enc.writeString(testCase.baseJSON)
			enc.AddSQLNullFloat64NullEmpty(&sql.NullFloat64{0, true})
			enc.SQLNullFloat64NullEmpty(&sql.NullFloat64{1, true})
			enc.Write()
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
}

func TestEncoderSQLNullFloat64KeyNullEmpty(t *testing.T) {
	var testCases = []struct {
		name         string
		baseJSON     string
		expectedJSON string
	}{
		{
			name:         "basic 1st elem",
			baseJSON:     "{",
			expectedJSON: `{"foo":null,"bar":1`,
		},
		{
			name:         "basic 2nd elem",
			baseJSON:     `{"test":"test"`,
			expectedJSON: `{"test":"test","foo":null,"bar":1`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var b strings.Builder
			var enc = NewEncoder(&b)
			enc.writeString(testCase.baseJSON)
			enc.AddSQLNullFloat64KeyNullEmpty("foo", &sql.NullFloat64{0, true})
			enc.SQLNullFloat64KeyNullEmpty("bar", &sql.NullFloat64{1, true})
			enc.Write()
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
}
