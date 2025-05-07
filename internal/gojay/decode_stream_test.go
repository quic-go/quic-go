package gojay

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Basic Behaviour Tests
//
func TestDecoderImplementsContext(t *testing.T) {
	var dec interface{} = &StreamDecoder{}
	_ = dec.(context.Context)
}

func TestDecodeStreamNoReader(t *testing.T) {
	dec := Stream.NewDecoder(nil)
	dec.done = make(chan struct{}, 1)
	testChan := ChannelStreamObjects(make(chan *TestObj))
	go dec.DecodeStream(&testChan)

	select {
	case <-dec.Done():
		assert.NotNil(t, dec.Err(), "dec.Err() should not be nil")
		assert.Equal(t, "No reader given to decode stream", dec.Err().Error(), "dec.Err().Error() should not be 'No reader given to decode stream'")
	case <-testChan:
		assert.True(t, false, "should not be called as decoder should not return error right away")
	}
}

//  Table Tests

// Objects

type StreamTestObject struct {
	name         string
	streamReader *StreamReader
	expectations func(error, []*TestObj, *testing.T)
}

func TestStreamDecodingObjectsParallel(t *testing.T) {
	var tests = []StreamTestObject{
		{
			name: "Stream objects",
			streamReader: &StreamReader{
				readChan: make(chan string),
				done:     make(chan struct{}),
				data: `
					{"test":246,"test2":-246,"test3":"string"}
					{"test":247,"test2":248,"test3":"string"}
					{"test":777,"test2":456,"test3":"string"}
					{"test":777,"test2":456,"test3":"string"}
					{"test":777,"test2":456,"test3":"string"}
					{"test":777,"test2":456,"test3":"string"}
				`,
			},
			expectations: func(err error, result []*TestObj, t *testing.T) {
				assert.Nil(t, err, "err should be nil")

				assert.Equal(t, 246, result[0].test, "v[0].test should be equal to 246")
				assert.Equal(t, -246, result[0].test2, "v[0].test2 should be equal to -247")
				assert.Equal(t, "string", result[0].test3, "v[0].test3 should be equal to \"string\"")

				assert.Equal(t, 247, result[1].test, "result[1].test should be equal to 246")
				assert.Equal(t, 248, result[1].test2, "result[1].test2 should be equal to 248")
				assert.Equal(t, "string", result[1].test3, "result[1].test3 should be equal to \"string\"")

				assert.Equal(t, 777, result[2].test, "result[2].test should be equal to 777")
				assert.Equal(t, 456, result[2].test2, "result[2].test2 should be equal to 456")
				assert.Equal(t, "string", result[2].test3, "result[2].test3 should be equal to \"string\"")

				assert.Equal(t, 777, result[3].test, "result[3].test should be equal to 777")
				assert.Equal(t, 456, result[3].test2, "result[3].test2 should be equal to 456")
				assert.Equal(t, "string", result[3].test3, "result[3].test3 should be equal to \"string\"")

				assert.Equal(t, 777, result[4].test, "result[4].test should be equal to 777")
				assert.Equal(t, 456, result[4].test2, "result[4].test2 should be equal to 456")
				assert.Equal(t, "string", result[4].test3, "result[4].test3 should be equal to \"string\"")

				assert.Equal(t, 777, result[5].test, "result[5].test should be equal to 777")
				assert.Equal(t, 456, result[5].test2, "result[5].test2 should be equal to 456")
				assert.Equal(t, "string", result[5].test3, "result[5].test3 should be equal to \"string\"")
			},
		},
		{
			name: "Stream test objects with null values",
			streamReader: &StreamReader{
				readChan: make(chan string),
				done:     make(chan struct{}),
				data: `
					{"test":246,"test2":-246,"test3":"string"}
					{"test":247,"test2":248,"test3":"string"}
					null
					{"test":777,"test2":456,"test3":"string"}
					{"test":777,"test2":456,"test3":"string"}
					{"test":777,"test2":456,"test3":"string"}
				`,
			},
			expectations: func(err error, result []*TestObj, t *testing.T) {
				assert.Nil(t, err, "err should be nil")

				assert.Equal(t, 246, result[0].test, "v[0].test should be equal to 246")
				assert.Equal(t, -246, result[0].test2, "v[0].test2 should be equal to -247")
				assert.Equal(t, "string", result[0].test3, "v[0].test3 should be equal to \"string\"")

				assert.Equal(t, 247, result[1].test, "result[1].test should be equal to 246")
				assert.Equal(t, 248, result[1].test2, "result[1].test2 should be equal to 248")
				assert.Equal(t, "string", result[1].test3, "result[1].test3 should be equal to \"string\"")

				assert.Equal(t, 0, result[2].test, "result[2].test should be equal to 0 as input is null")
				assert.Equal(t, 0, result[2].test2, "result[2].test2 should be equal to 0 as input is null")
				assert.Equal(t, "", result[2].test3, "result[2].test3 should be equal to \"\" as input is null")

				assert.Equal(t, 777, result[3].test, "result[3].test should be equal to 777")
				assert.Equal(t, 456, result[3].test2, "result[3].test2 should be equal to 456")
				assert.Equal(t, "string", result[3].test3, "result[3].test3 should be equal to \"string\"")

				assert.Equal(t, 777, result[4].test, "result[4].test should be equal to 777")
				assert.Equal(t, 456, result[4].test2, "result[4].test2 should be equal to 456")
				assert.Equal(t, "string", result[4].test3, "result[4].test3 should be equal to \"string\"")

				assert.Equal(t, 777, result[5].test, "result[5].test should be equal to 777")
				assert.Equal(t, 456, result[5].test2, "result[5].test2 should be equal to 456")
				assert.Equal(t, "string", result[5].test3, "result[5].test3 should be equal to \"string\"")
			},
		},
		{
			name: "Stream test starting with null values",
			streamReader: &StreamReader{
				readChan: make(chan string),
				done:     make(chan struct{}),
				data: `
					null
					{"test":246,"test2":-246,"test3":"string"}
					{"test":247,"test2":248,"test3":"string"}
				`,
			},
			expectations: func(err error, result []*TestObj, t *testing.T) {
				assert.Nil(t, err, "err should be nil")
				assert.Equal(t, 0, result[0].test, "result[0].test should be equal to 0 as input is null")
				assert.Equal(t, 0, result[0].test2, "result[0].test2 should be equal to 0 as input is null")
				assert.Equal(t, "", result[0].test3, "result[0].test3 should be equal to \"\" as input is null")

				assert.Equal(t, 246, result[1].test, "v[1].test should be equal to 246")
				assert.Equal(t, -246, result[1].test2, "v[1].test2 should be equal to -247")
				assert.Equal(t, "string", result[1].test3, "v[1].test3 should be equal to \"string\"")

				assert.Equal(t, 247, result[2].test, "result[2].test should be equal to 246")
				assert.Equal(t, 248, result[2].test2, "result[2].test2 should be equal to 248")
				assert.Equal(t, "string", result[2].test3, "result[2].test3 should be equal to \"string\"")
			},
		},
		{
			name: "Stream test invalid JSON",
			streamReader: &StreamReader{
				readChan: make(chan string),
				done:     make(chan struct{}),
				data: `
					invalid json
					{"test":246,"test2":-246,"test3":"string"}
					{"test":247,"test2":248,"test3":"string"}
				`,
			},
			expectations: func(err error, result []*TestObj, t *testing.T) {
				assert.NotNil(t, err, "err is not nil as JSON is invalid")
				assert.IsType(t, InvalidJSONError(""), err, "err is of type InvalidJSONError")
				assert.Equal(t, "Invalid JSON, wrong char 'i' found at position 6", err.Error(), "err message is Invalid JSON")
			},
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			runStreamTestCaseObjects(t, testCase)
		})
	}
}

func runStreamTestCaseObjects(t *testing.T, testCase StreamTestObject) {
	// create our channel which will receive our objects
	testChan := ChannelStreamObjects(make(chan *TestObj))
	dec := Stream.NewDecoder(testCase.streamReader)
	// start decoding (will block the goroutine until something is written to the ReadWriter)
	go dec.DecodeStream(&testChan)
	// start writing to the ReadWriter
	go testCase.streamReader.Write()
	// prepare our result
	result := []*TestObj{}
loop:
	for {
		select {
		case v := <-testChan:
			result = append(result, v)
		case <-dec.Done():
			break loop
		}
	}
	testCase.expectations(dec.Err(), result, t)
}

type ChannelStreamObjects chan *TestObj

func (c *ChannelStreamObjects) UnmarshalStream(dec *StreamDecoder) error {
	obj := &TestObj{}
	if err := dec.AddObject(obj); err != nil {
		return err
	}
	*c <- obj
	return nil
}

// Strings
type StreamTestString struct {
	name         string
	streamReader *StreamReader
	expectations func(error, []*string, *testing.T)
}

func TestStreamDecodingStringsParallel(t *testing.T) {
	var tests = []StreamTestString{
		{
			name: "Stream strings basic",
			streamReader: &StreamReader{
				readChan: make(chan string),
				done:     make(chan struct{}),
				data: `
					"hello"
					"world"
					"!"
				`,
			},
			expectations: func(err error, result []*string, t *testing.T) {
				assert.Nil(t, err, "err should be nil")

				assert.Equal(t, "hello", *result[0], "v[0] should be equal to 'hello'")
				assert.Equal(t, "world", *result[1], "v[1] should be equal to 'world'")
				assert.Equal(t, "!", *result[2], "v[2] should be equal to '!'")
			},
		},
		{
			name: "Stream strings with null",
			streamReader: &StreamReader{
				readChan: make(chan string),
				done:     make(chan struct{}),
				data: `
					"hello"
					null
					"!"
				`,
			},
			expectations: func(err error, result []*string, t *testing.T) {
				assert.Nil(t, err, "err should be nil")

				assert.Equal(t, "hello", *result[0], "v[0] should be equal to 'hello'")
				assert.Equal(t, "", *result[1], "v[1] should be equal to ''")
				assert.Equal(t, "!", *result[2], "v[2] should be equal to '!'")
			},
		},
		{
			name: "Stream strings invalid JSON",
			streamReader: &StreamReader{
				readChan: make(chan string),
				done:     make(chan struct{}),
				data: `
					"hello"
					world
					"!"
				`,
			},
			expectations: func(err error, result []*string, t *testing.T) {
				assert.NotNil(t, err, "err should not be nil")

				assert.IsType(t, InvalidJSONError(""), err, "err is of type InvalidJSONError")
				assert.Equal(t, "Invalid JSON, wrong char 'w' found at position 6", err.Error(), "err message is Invalid JSON")
			},
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			runStreamTestCaseStrings(t, testCase)
		})
	}
}

func runStreamTestCaseStrings(t *testing.T, testCase StreamTestString) {
	// create our channel which will receive our objects
	testChan := ChannelStreamStrings(make(chan *string))
	dec := Stream.NewDecoder(testCase.streamReader)
	// start decoding (will block the goroutine until something is written to the ReadWriter)
	go dec.DecodeStream(testChan)
	// start writing to the ReadWriter
	go testCase.streamReader.Write()
	// prepare our result
	result := []*string{}
loop:
	for {
		select {
		case v := <-testChan:
			result = append(result, v)
		case <-dec.Done():
			break loop
		}
	}
	testCase.expectations(dec.Err(), result, t)
}

func TestStreamDecodingErr(t *testing.T) {
	testChan := ChannelStreamStrings(make(chan *string))
	dec := Stream.NewDecoder(&StreamReaderErr{})
	// start decoding (will block the goroutine until something is written to the ReadWriter)
	go dec.DecodeStream(testChan)
	select {
	case <-dec.Done():
		assert.NotNil(t, dec.Err(), "dec.Err() should not be nil")
	case <-testChan:
		assert.True(t, false, "should not be called")
	}

}

type ChannelStreamStrings chan *string

func (c ChannelStreamStrings) UnmarshalStream(dec *StreamDecoder) error {
	str := ""
	if err := dec.AddString(&str); err != nil {
		return err
	}
	c <- &str
	return nil
}

// StreamReader mocks a stream reading chunks of data
type StreamReader struct {
	writeCounter int
	readChan     chan string
	done         chan struct{}
	data         string
}

func (r *StreamReader) Write() {
	l := len(r.data)
	t := 4
	chunkSize := l / t
	carry := 0
	lastWrite := 0
	for r.writeCounter < t {
		time.Sleep(time.Duration(r.writeCounter*100) * time.Millisecond)
		currentChunkStart := (chunkSize) * r.writeCounter
		lastWrite = currentChunkStart + chunkSize
		r.readChan <- r.data[currentChunkStart:lastWrite]
		carry = l - lastWrite
		r.writeCounter++
	}
	if carry > 0 {
		r.readChan <- r.data[lastWrite:]
	}
	r.done <- struct{}{}
}

func (r *StreamReader) Read(b []byte) (int, error) {
	select {
	case v := <-r.readChan:
		n := copy(b, v)
		return n, nil
	case <-r.done:
		return 0, io.EOF
	}
}

type StreamReaderErr struct{}

func (r *StreamReaderErr) Read(b []byte) (int, error) {
	return 0, errors.New("Test Error")
}

// Deadline test
func TestStreamDecodingDeadline(t *testing.T) {
	dec := Stream.NewDecoder(&StreamReader{})
	now := time.Now()
	dec.SetDeadline(now)
	deadline, _ := dec.Deadline()
	assert.Equal(t, now.String(), deadline.String(), "dec.now and now should be equal")
	assert.Equal(t, now.String(), dec.deadline.String(), "dec.now and now should be equal")
}

func TestStreamDecodingDeadlineNotSet(t *testing.T) {
	dec := Stream.NewDecoder(&StreamReader{})
	_, isSet := dec.Deadline()
	assert.Equal(t, false, isSet, "isSet should be false as deadline is not set")
}

// this test is only relevant for coverage
func TestStreamDecodingValue(t *testing.T) {
	dec := Stream.NewDecoder(&StreamReader{})
	v := dec.Value("")
	assert.Nil(t, v, "v should be nil")
}

func TestStreamDecodingErrNotSet(t *testing.T) {
	dec := Stream.NewDecoder(&StreamReader{})
	assert.Nil(t, dec.Err(), "dec.Err should be nim")
}

func TestStreamDecodingPoolError(t *testing.T) {
	dec := Stream.BorrowDecoder(nil)
	dec.Release()
	defer func() {
		err := recover()
		assert.NotNil(t, err, "err shouldnt be nil")
		assert.IsType(t, InvalidUsagePooledDecoderError(""), err, "err should be of type InvalidUsagePooledEncoderError")
		assert.Equal(t, "Invalid usage of pooled decoder", err.(InvalidUsagePooledDecoderError).Error(), "err should be of type InvalidUsagePooledDecoderError")
	}()
	testChan := ChannelStreamStrings(make(chan *string))
	_ = dec.DecodeStream(testChan)
	assert.True(t, false, "should not be called as it should have panicked")
}
