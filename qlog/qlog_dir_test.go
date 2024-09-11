package qlog

import (
	"context"
	"os"
	"path"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/logging"
	"github.com/stretchr/testify/require"
)

var (
	originalQlogDirValue string
	tempTestDirPath      string
	ctx                  = context.Background()
	perspective          = logging.PerspectiveClient
)

func setup(t *testing.T) {
	originalQlogDirValue = os.Getenv("QLOGDIR")
	var err error
	tempTestDirPath, err = os.MkdirTemp("", "temp_test_dir")
	require.NoError(t, err)
}

func cleanup(t *testing.T) {
	require.NoError(t, os.Setenv("QLOGDIR", originalQlogDirValue))
	require.NoError(t, os.RemoveAll(tempTestDirPath))
}

func TestEnvironmentVariableIsSet(t *testing.T) {
	setup(t)
	defer cleanup(t)

	connID, _ := protocol.GenerateConnectionIDForInitial()
	qlogDir := path.Join(tempTestDirPath, "qlogs")
	err := os.Setenv("QLOGDIR", qlogDir)
	require.NoError(t, err)

	tracer := DefaultConnectionTracer(ctx, perspective, connID)
	require.NotNil(t, tracer)
	tracer.Close()

	_, err = os.Stat(qlogDir)
	qlogDirCreated := !os.IsNotExist(err)
	require.True(t, qlogDirCreated)

	childs, err := os.ReadDir(qlogDir)
	require.NoError(t, err)
	require.Len(t, childs, 1)
}

func TestEnvironmentVariableIsNotSet(t *testing.T) {
	setup(t)
	defer cleanup(t)

	connID, _ := protocol.GenerateConnectionIDForInitial()
	err := os.Setenv("QLOGDIR", "")
	require.NoError(t, err)

	tracer := DefaultConnectionTracer(ctx, perspective, connID)
	require.Nil(t, tracer)
}
