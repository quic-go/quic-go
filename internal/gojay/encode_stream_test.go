package gojay

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type StreamChanObject chan *testObject

func (s StreamChanObject) MarshalStream(enc *StreamEncoder) {
	select {
	case <-enc.Done():
		return
	case o := <-s:
		enc.AddObject(o)
	}
}

type StreamChanSlice chan *TestEncodingArrStrings

func (s StreamChanSlice) MarshalStream(enc *StreamEncoder) {
	select {
	case <-enc.Done():
		return
	case o := <-s:
		enc.AddArray(o)
	}
}

type StreamChanString chan string

func (s StreamChanString) MarshalStream(enc *StreamEncoder) {
	select {
	case <-enc.Done():
		return
	case o := <-s:
		enc.AddString(o)
	}
}

type StreamChanInt chan int

func (s StreamChanInt) MarshalStream(enc *StreamEncoder) {
	select {
	case <-enc.Done():
		return
	case o := <-s:
		enc.AddInt(o)
	}
}

type StreamChanFloat chan float64

func (s StreamChanFloat) MarshalStream(enc *StreamEncoder) {
	select {
	case <-enc.Done():
		return
	case o := <-s:
		enc.AddFloat(o)
	}
}

type StreamChanError chan *testObject

func (s StreamChanError) MarshalStream(enc *StreamEncoder) {
	select {
	case <-enc.Done():
		return
	case <-s:
		enc.AddInterface(struct{}{})
	}
}

// TestWriter to assert result
type TestWriter struct {
	nWrite *int
	target int
	enc    *StreamEncoder
	result [][]byte
	mux    *sync.RWMutex
}

func (w *TestWriter) Write(b []byte) (int, error) {
	if len(b) > 0 {
		w.mux.Lock()
		w.result = append(w.result, b)
		if len(w.result) == w.target {
			w.enc.Cancel(nil)
		}
		w.mux.Unlock()
	}
	return len(b), nil
}

func feedStreamNil(s chan *testObject, target int) {
	for i := 0; i < target; i++ {
		s <- nil
	}
}

func feedStream(s chan *testObject, target int) {
	for i := 0; i < target; i++ {
		s <- &testObject{}
	}
}

func feedStreamSlices(s chan *TestEncodingArrStrings, target int) {
	for i := 0; i < target; i++ {
		s <- &TestEncodingArrStrings{"test", "test2"}
	}
}

func feedStreamStrings(s chan string, target int) {
	for i := 0; i < target; i++ {
		s <- "hello"
	}
}

func feedStreamInt(s chan int, target int) {
	for i := 0; i < target; i++ {
		s <- i
	}
}

func feedStreamFloat(s chan float64, target int) {
	for i := 0; i < target; i++ {
		s <- float64(i)
	}
}

func TestEncodeStream(t *testing.T) {
	t.Run("single-consumer-object", func(t *testing.T) {
		expectedStr :=
			`{"testStr":"","testInt":0,"testInt64":0,"testInt32":0,"testInt16":0,"testInt8":0,"testUint64":0,"testUint32":0,"testUint16":0,"testUint8":0,"testFloat64":0,"testFloat32":0,"testBool":false}
`
		// create our writer
		w := &TestWriter{target: 100, mux: &sync.RWMutex{}}
		enc := Stream.NewEncoder(w).LineDelimited()
		w.enc = enc
		s := StreamChanObject(make(chan *testObject))
		go enc.EncodeStream(s)
		go feedStream(s, 100)
		select {
		case <-enc.Done():
			assert.Nil(t, enc.Err(), "enc.Err() should be nil")
			assert.Len(t, w.result, 100, "w.result should be 100")
			for _, b := range w.result {
				assert.Equal(t, expectedStr, string(b), "every byte buffer should be equal to expected string")
			}
		}
	})

	t.Run("single-consumer-slice", func(t *testing.T) {
		expectedStr :=
			`["test","test2"]
`
		// create our writer
		w := &TestWriter{target: 100, mux: &sync.RWMutex{}}
		enc := Stream.NewEncoder(w).LineDelimited()
		w.enc = enc
		s := StreamChanSlice(make(chan *TestEncodingArrStrings))
		go enc.EncodeStream(s)
		go feedStreamSlices(s, 100)
		select {
		case <-enc.Done():
			assert.Nil(t, enc.Err(), "enc.Err() should be nil")
			assert.Len(t, w.result, 100, "w.result should be 100")
			for _, b := range w.result {
				assert.Equal(t, expectedStr, string(b), "every byte buffer should be equal to expected string")
			}
		}
	})

	t.Run("single-consumer-string", func(t *testing.T) {
		expectedStr :=
			`"hello"
`
		// create our writer
		w := &TestWriter{target: 100, mux: &sync.RWMutex{}}
		enc := Stream.NewEncoder(w).LineDelimited()
		w.enc = enc
		s := StreamChanString(make(chan string))
		go enc.EncodeStream(s)
		go feedStreamStrings(s, 100)
		select {
		case <-enc.Done():
			assert.Nil(t, enc.Err(), "enc.Err() should be nil")
			assert.Len(t, w.result, 100, "w.result should be 100")
			for _, b := range w.result {
				assert.Equal(t, expectedStr, string(b), "every byte buffer should be equal to expected string")
			}
		}
	})

	t.Run("single-consumer-object-nil-value", func(t *testing.T) {
		expectedStr := ``
		// create our writer
		w := &TestWriter{target: 100, mux: &sync.RWMutex{}}
		enc := Stream.NewEncoder(w).LineDelimited()
		w.enc = enc
		s := StreamChanObject(make(chan *testObject))
		go enc.EncodeStream(s)
		go feedStreamNil(s, 100)
		select {
		case <-enc.Done():
			assert.Nil(t, enc.Err(), "enc.Err() should be nil")
			assert.Nil(t, enc.Err(), "enc.Err() should not be nil")
			for _, b := range w.result {
				assert.Equal(t, expectedStr, string(b), "every byte buffer should be equal to expected string")
			}
		}
	})

	t.Run("single-consumer-int", func(t *testing.T) {
		// create our writer
		w := &TestWriter{target: 100, mux: &sync.RWMutex{}}
		enc := Stream.NewEncoder(w).LineDelimited()
		w.enc = enc
		s := StreamChanInt(make(chan int))
		go enc.EncodeStream(s)
		go feedStreamInt(s, 100)
		select {
		case <-enc.Done():
			assert.Nil(t, enc.Err(), "enc.Err() should be nil")
			assert.Len(t, w.result, 100, "w.result should be 100")
		}
	})

	t.Run("single-consumer-float", func(t *testing.T) {
		// create our writer
		w := &TestWriter{target: 100, mux: &sync.RWMutex{}}
		enc := Stream.NewEncoder(w).LineDelimited()
		w.enc = enc
		s := StreamChanFloat(make(chan float64))
		go enc.EncodeStream(s)
		go feedStreamFloat(s, 100)
		select {
		case <-enc.Done():
			assert.Nil(t, enc.Err(), "enc.Err() should be nil")
			assert.Len(t, w.result, 100, "w.result should be 100")
		}
	})

	t.Run("single-consumer-marshal-error", func(t *testing.T) {
		// create our writer
		w := &TestWriter{target: 100, mux: &sync.RWMutex{}}
		enc := Stream.NewEncoder(w).LineDelimited()
		w.enc = enc
		s := StreamChanError(make(chan *testObject))
		go enc.EncodeStream(s)
		go feedStream(s, 100)
		select {
		case <-enc.Done():
			assert.NotNil(t, enc.Err(), "enc.Err() should not be nil")
		}
	})

	t.Run("single-consumer-write-error", func(t *testing.T) {
		// create our writer
		w := TestWriterError("")
		enc := Stream.NewEncoder(w).LineDelimited()
		s := StreamChanObject(make(chan *testObject))
		go enc.EncodeStream(s)
		go feedStream(s, 100)
		select {
		case <-enc.Done():
			assert.NotNil(t, enc.Err(), "enc.Err() should not be nil")
		}
	})

	t.Run("multiple-consumer-object-comma-delimited", func(t *testing.T) {
		expectedStr :=
			`{"testStr":"","testInt":0,"testInt64":0,"testInt32":0,"testInt16":0,"testInt8":0,"testUint64":0,"testUint32":0,"testUint16":0,"testUint8":0,"testFloat64":0,"testFloat32":0,"testBool":false},`
		// create our writer
		w := &TestWriter{target: 5000, mux: &sync.RWMutex{}}
		enc := Stream.BorrowEncoder(w).NConsumer(50).CommaDelimited()
		w.enc = enc
		s := StreamChanObject(make(chan *testObject))
		go enc.EncodeStream(s)
		go feedStream(s, 5000)
		select {
		case <-enc.Done():
			assert.Nil(t, enc.Err(), "enc.Err() should be nil")
			assert.Len(t, w.result, 5000, "w.result should be 100")
			for _, b := range w.result {
				assert.Equal(t, expectedStr, string(b), "every byte buffer should be equal to expected string")
			}
		}
	})

	t.Run("multiple-consumer-object-line-delimited", func(t *testing.T) {
		expectedStr :=
			`{"testStr":"","testInt":0,"testInt64":0,"testInt32":0,"testInt16":0,"testInt8":0,"testUint64":0,"testUint32":0,"testUint16":0,"testUint8":0,"testFloat64":0,"testFloat32":0,"testBool":false}
`
		// create our writer
		w := &TestWriter{target: 5000, mux: &sync.RWMutex{}}
		enc := Stream.NewEncoder(w).NConsumer(50).LineDelimited()
		w.enc = enc
		s := StreamChanObject(make(chan *testObject))
		go feedStream(s, 5000)
		go enc.EncodeStream(s)
		select {
		case <-enc.Done():
			assert.Nil(t, enc.Err(), "enc.Err() should be nil")
			assert.Len(t, w.result, 5000, "w.result should be 100")
			for _, b := range w.result {
				assert.Equal(t, expectedStr, string(b), "every byte buffer should be equal to expected string")
			}
		}
	})

	t.Run("multiple-consumer-object-chan-closed", func(t *testing.T) {
		// create our writer
		w := &TestWriter{target: 5000, mux: &sync.RWMutex{}}
		enc := Stream.NewEncoder(w).NConsumer(50).LineDelimited()
		w.enc = enc
		s := StreamChanObject(make(chan *testObject))
		close(enc.done)
		go feedStream(s, 5000)
		go enc.EncodeStream(s)
		select {
		case <-enc.Done():
			assert.Nil(t, enc.Err(), "enc.Err() should be nil")
			assert.Len(t, w.result, 0, "w.result should be 0")
		}
	})

	t.Run("encoder-deadline", func(t *testing.T) {
		enc := Stream.NewEncoder(os.Stdout)
		now := time.Now()
		enc.SetDeadline(now)
		d, _ := enc.Deadline()
		assert.Equal(t, now, d, "deadline should be the one just set")
	})

	t.Run("encoder-deadline-unset", func(t *testing.T) {
		enc := Stream.NewEncoder(os.Stdout)
		d, _ := enc.Deadline()
		assert.Equal(t, time.Time{}, d, "deadline should be the one just set")
	})

	// just for coverage
	t.Run("encoder-context-value", func(t *testing.T) {
		enc := Stream.NewEncoder(os.Stdout)
		assert.Nil(t, enc.Value(""), "enc.Value should be nil")
	})
}
