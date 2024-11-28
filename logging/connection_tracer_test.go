package logging_test

import (
	"errors"
	"testing"

	"github.com/quic-go/quic-go/logging"
	"github.com/stretchr/testify/require"
)

func TestConnectionTracerMultiplexing(t *testing.T) {
	var err1, err2 error
	t1 := &logging.ConnectionTracer{ClosedConnection: func(e error) { err1 = e }}
	t2 := &logging.ConnectionTracer{ClosedConnection: func(e error) { err2 = e }}
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	e := errors.New("test err")
	tracer.ClosedConnection(e)
	require.Equal(t, e, err1)
	require.Equal(t, e, err2)
}
