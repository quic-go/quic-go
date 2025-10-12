package qlog

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/stretchr/testify/require"
)

func TestQLOGDIRSet(t *testing.T) {
	tmpDir := t.TempDir()

	connID := quic.ConnectionIDFromBytes([]byte{1, 2, 3, 4})
	qlogDir := filepath.Join(tmpDir, "qlogs")
	t.Setenv("QLOGDIR", qlogDir)

	tracer := DefaultConnectionTracer(context.Background(), true, connID)
	require.NotNil(t, tracer)

	// adding and closing a producer makes the tracer close the file
	recorder := tracer.AddProducer()
	recorder.Close()

	_, err := os.Stat(qlogDir)
	qlogDirCreated := !os.IsNotExist(err)
	require.True(t, qlogDirCreated)

	entries, err := os.ReadDir(qlogDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	data, err := os.ReadFile(filepath.Join(qlogDir, entries[0].Name()))
	require.NoError(t, err)

	require.Contains(t, string(data), EventSchema)
	require.Contains(t, string(data), qlog.EventSchema)
}
