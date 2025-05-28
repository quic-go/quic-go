package logging_test

import (
	"testing"

	"github.com/Noooste/quic-go/logging"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnectionTracerMultiplexing(t *testing.T) {
	var err1, err2 error
	t1 := &logging.ConnectionTracer{ClosedConnection: func(e error) { err1 = e }}
	t2 := &logging.ConnectionTracer{ClosedConnection: func(e error) { err2 = e }}
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	tracer.ClosedConnection(assert.AnError)
	require.Equal(t, assert.AnError, err1)
	require.Equal(t, assert.AnError, err2)
}
