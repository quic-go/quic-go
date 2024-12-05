package qlog

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestQLOGDIRSet(t *testing.T) {
	tmpDir := t.TempDir()

	connID, _ := protocol.GenerateConnectionIDForInitial()
	qlogDir := filepath.Join(tmpDir, "qlogs")
	t.Setenv("QLOGDIR", qlogDir)

	tracer := DefaultConnectionTracer(context.Background(), protocol.PerspectiveClient, connID)
	require.NotNil(t, tracer)
	tracer.Close()

	_, err := os.Stat(qlogDir)
	qlogDirCreated := !os.IsNotExist(err)
	require.True(t, qlogDirCreated)

	childs, err := os.ReadDir(qlogDir)
	require.NoError(t, err)
	require.Len(t, childs, 1)
}

func TestQLOGDIRNotSet(t *testing.T) {
	connID, _ := protocol.GenerateConnectionIDForInitial()
	t.Setenv("QLOGDIR", "")

	tracer := DefaultConnectionTracer(context.Background(), protocol.PerspectiveClient, connID)
	require.Nil(t, tracer)
}
