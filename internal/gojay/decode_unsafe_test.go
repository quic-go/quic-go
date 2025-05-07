package gojay

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnmarshalUnsafeAllTypes(t *testing.T) {
	testCases := []struct {
		name         string
		v            interface{}
		d            []byte
		expectations func(err error, v interface{}, t *testing.T)
	}{
		{
			v:    new(string),
			d:    []byte(`"test string"`),
			name: "test decode string",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*string)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, "test string", *vt, "v must be equal to 1")
			},
		},
		{
			v:    new(string),
			d:    []byte(`null`),
			name: "test decode string null",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*string)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, "", *vt, "v must be equal to 1")
			},
		},
		{
			v:    new(int),
			d:    []byte(`1`),
			name: "test decode int",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*int)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, 1, *vt, "v must be equal to 1")
			},
		},
		{
			v:    new(int8),
			d:    []byte(`1`),
			name: "test decode int8",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*int8)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, int8(1), *vt, "v must be equal to 1")
			},
		},
		{
			v:    new(int16),
			d:    []byte(`1`),
			name: "test decode int16",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*int16)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, int16(1), *vt, "v must be equal to 1")
			},
		},
		{
			v:    new(int32),
			d:    []byte(`1`),
			name: "test decode int32",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*int32)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, int32(1), *vt, "v must be equal to 1")
			},
		},
		{
			v:    new(int64),
			d:    []byte(`1`),
			name: "test decode int64",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*int64)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, int64(1), *vt, "v must be equal to 1")
			},
		},
		{
			v:    new(uint64),
			d:    []byte(`1`),
			name: "test decode uint64",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*uint64)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, uint64(1), *vt, "v must be equal to 1")
			},
		},
		{
			v:    new(uint64),
			d:    []byte(`-1`),
			name: "test decode uint64 negative",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*uint64)
				assert.NotNil(t, err, "err must not be nil")
				assert.Equal(t, uint64(0), *vt, "v must be equal to 1")
			},
		},
		{
			v:    new(int32),
			d:    []byte(`1`),
			name: "test decode int32",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*int32)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, int32(1), *vt, "v must be equal to 1")
			},
		},
		{
			v:    new(uint32),
			d:    []byte(`1`),
			name: "test decode uint32",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*uint32)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, uint32(1), *vt, "v must be equal to 1")
			},
		},
		{
			v:    new(uint32),
			d:    []byte(`-1`),
			name: "test decode uint32 negative",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*uint32)
				assert.NotNil(t, err, "err must not be nil")
				assert.Equal(t, uint32(0), *vt, "v must be equal to 1")
			},
		},
		{
			v:    new(uint8),
			d:    []byte(`1`),
			name: "test decode int8",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*uint8)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, uint8(1), *vt, "v must be equal to 1")
			},
		},
		{
			v:    new(uint16),
			d:    []byte(`1`),
			name: "test decode uint16",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*uint16)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, uint16(1), *vt, "v must be equal to 1")
			},
		},
		{
			v:    new(float64),
			d:    []byte(`1.15`),
			name: "test decode float64",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*float64)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, float64(1.15), *vt, "v must be equal to 1")
			},
		},
		{
			v:    new(float64),
			d:    []byte(`null`),
			name: "test decode float64 null",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*float64)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, float64(0), *vt, "v must be equal to 1")
			},
		},
		{
			v:    new(float32),
			d:    []byte(`1.15`),
			name: "test decode float64",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*float32)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, float32(1.15), *vt, "v must be equal to 1")
			},
		},
		{
			v:    new(bool),
			d:    []byte(`true`),
			name: "test decode bool true",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*bool)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, true, *vt, "v must be equal to 1")
			},
		},
		{
			v:    new(bool),
			d:    []byte(`false`),
			name: "test decode bool false",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*bool)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, false, *vt, "v must be equal to 1")
			},
		},
		{
			v:    new(bool),
			d:    []byte(`null`),
			name: "test decode bool null",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*bool)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, false, *vt, "v must be equal to 1")
			},
		},
		{
			v:    new(testDecodeObj),
			d:    []byte(`{"test":"test"}`),
			name: "test decode object",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*testDecodeObj)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, "test", vt.test, "v.test must be equal to 'test'")
			},
		},
		{
			v:    new(testDecodeObj),
			d:    []byte(`{"test":null}`),
			name: "test decode object null key",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*testDecodeObj)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, "", vt.test, "v.test must be equal to 'test'")
			},
		},
		{
			v:    new(testDecodeObj),
			d:    []byte(`null`),
			name: "test decode object null",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*testDecodeObj)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, "", vt.test, "v.test must be equal to 'test'")
			},
		},
		{
			v:    new(testDecodeSlice),
			d:    []byte(`[{"test":"test"}]`),
			name: "test decode slice",
			expectations: func(err error, v interface{}, t *testing.T) {
				vtPtr := v.(*testDecodeSlice)
				vt := *vtPtr
				assert.Nil(t, err, "err must be nil")
				assert.Len(t, vt, 1, "len of vt must be 1")
				assert.Equal(t, "test", vt[0].test, "vt[0].test must be equal to 'test'")
			},
		},
		{
			v:    new(testDecodeSlice),
			d:    []byte(`[{"test":"test"},{"test":"test2"}]`),
			name: "test decode slice",
			expectations: func(err error, v interface{}, t *testing.T) {
				vtPtr := v.(*testDecodeSlice)
				vt := *vtPtr
				assert.Nil(t, err, "err must be nil")
				assert.Len(t, vt, 2, "len of vt must be 2")
				assert.Equal(t, "test", vt[0].test, "vt[0].test must be equal to 'test'")
				assert.Equal(t, "test2", vt[1].test, "vt[1].test must be equal to 'test2'")
			},
		},
		{
			v:    new(struct{}),
			d:    []byte(`{"test":"test"}`),
			name: "test decode invalid type",
			expectations: func(err error, v interface{}, t *testing.T) {
				assert.NotNil(t, err, "err must not be nil")
				assert.IsType(t, InvalidUnmarshalError(""), err, "err must be of type InvalidUnmarshalError")
				assert.Equal(t, fmt.Sprintf(invalidUnmarshalErrorMsg, v), err.Error(), "err message should be equal to invalidUnmarshalErrorMsg")
			},
		},
		{
			v:    new(int),
			d:    []byte(`1a2`),
			name: "test decode invalid json",
			expectations: func(err error, v interface{}, t *testing.T) {
				assert.NotNil(t, err, "err must not be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err must be of type InvalidJSONError")
			},
		},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(*testing.T) {
			err := Unsafe.Unmarshal(testCase.d, testCase.v)
			testCase.expectations(err, testCase.v, t)
		})
	}
}

func TestUnmarshalUnsafeObjects(t *testing.T) {
	testCases := []struct {
		name         string
		v            UnmarshalerJSONObject
		d            []byte
		expectations func(err error, v interface{}, t *testing.T)
	}{
		{
			v:    new(testDecodeObj),
			d:    []byte(`{"test":"test"}`),
			name: "test decode object",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*testDecodeObj)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, "test", vt.test, "v.test must be equal to 'test'")
			},
		},
		{
			v:    new(testDecodeObj),
			d:    []byte(`{"test":null}`),
			name: "test decode object null key",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*testDecodeObj)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, "", vt.test, "v.test must be equal to 'test'")
			},
		},
		{
			v:    new(testDecodeObj),
			d:    []byte(`null`),
			name: "test decode object null",
			expectations: func(err error, v interface{}, t *testing.T) {
				vt := v.(*testDecodeObj)
				assert.Nil(t, err, "err must be nil")
				assert.Equal(t, "", vt.test, "v.test must be equal to 'test'")
			},
		},
		{
			v:    new(testDecodeObj),
			d:    []byte(`invalid json`),
			name: "test decode object null",
			expectations: func(err error, v interface{}, t *testing.T) {
				assert.NotNil(t, err, "err must not be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err must be of type InvalidJSONError")
			},
		},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(*testing.T) {
			err := Unsafe.UnmarshalJSONObject(testCase.d, testCase.v)
			testCase.expectations(err, testCase.v, t)
		})
	}
}

func TestUnmarshalUnsafeArrays(t *testing.T) {
	testCases := []struct {
		name         string
		v            UnmarshalerJSONArray
		d            []byte
		expectations func(err error, v interface{}, t *testing.T)
	}{
		{
			v:    new(testDecodeSlice),
			d:    []byte(`[{"test":"test"}]`),
			name: "test decode slice",
			expectations: func(err error, v interface{}, t *testing.T) {
				vtPtr := v.(*testDecodeSlice)
				vt := *vtPtr
				assert.Nil(t, err, "err must be nil")
				assert.Len(t, vt, 1, "len of vt must be 1")
				assert.Equal(t, "test", vt[0].test, "vt[0].test must be equal to 'test'")
			},
		},
		{
			v:    new(testDecodeSlice),
			d:    []byte(`[{"test":"test"},{"test":"test2"}]`),
			name: "test decode slice",
			expectations: func(err error, v interface{}, t *testing.T) {
				vtPtr := v.(*testDecodeSlice)
				vt := *vtPtr
				assert.Nil(t, err, "err must be nil")
				assert.Len(t, vt, 2, "len of vt must be 2")
				assert.Equal(t, "test", vt[0].test, "vt[0].test must be equal to 'test'")
				assert.Equal(t, "test2", vt[1].test, "vt[1].test must be equal to 'test2'")
			},
		},
		{
			v:    new(testDecodeSlice),
			d:    []byte(`invalid json`),
			name: "test decode object null",
			expectations: func(err error, v interface{}, t *testing.T) {
				assert.NotNil(t, err, "err must not be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err must be of type InvalidJSONError")
			},
		},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(*testing.T) {
			err := Unsafe.UnmarshalJSONArray(testCase.d, testCase.v)
			testCase.expectations(err, testCase.v, t)
		})
	}
}
