package self_test

import (
	"context"
	"os"
	"path"
	"regexp"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"

	"github.com/stretchr/testify/require"
)

func TestQlogDirEnvironmentVariable(t *testing.T) {
	tempDir := t.TempDir()
	qlogDir := path.Join(tempDir, "qlogs")
	t.Setenv("QLOGDIR", qlogDir)

	serverStopped := make(chan struct{})
	server, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		&quic.Config{
			Tracer: qlog.DefaultConnectionTracer,
		},
	)
	require.NoError(t, err)

	go func() {
		defer close(serverStopped)
		for {
			if _, err := server.Accept(context.Background()); err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		server.Addr(),
		getTLSClientConfig(),
		&quic.Config{
			Tracer: qlog.DefaultConnectionTracer,
		},
	)
	require.NoError(t, err)
	conn.CloseWithError(0, "")
	server.Close()
	<-serverStopped

	_, err = os.Stat(qlogDir)
	qlogDirCreated := !os.IsNotExist(err)
	require.True(t, qlogDirCreated)

	childs, err := os.ReadDir(qlogDir)
	require.NoError(t, err)
	require.Len(t, childs, 2)

	odcids := make([]string, 0, 2)
	vantagePoints := make([]string, 0, 2)
	qlogFileNameRegexp := regexp.MustCompile(`^([0-f]+)_(client|server).sqlog$`)

	for _, child := range childs {
		matches := qlogFileNameRegexp.FindStringSubmatch(child.Name())
		require.Len(t, matches, 3)
		odcids = append(odcids, matches[1])
		vantagePoints = append(vantagePoints, matches[2])
	}

	require.Equal(t, odcids[0], odcids[1])
	require.Contains(t, vantagePoints, "client")
	require.Contains(t, vantagePoints, "server")
}
