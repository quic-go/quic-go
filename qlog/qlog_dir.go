package qlog

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"
)

// lazyWriteCloser creates the qlog file when the first log line is written.
// This means that creating the qlog (there's no guarantee how long the syscalls will take)
// won't block the connection, since qlogs are serialized from a separate Go routine,
// that takes events from a buffered channel (size: eventChanSize).
type lazyWriteCloser struct {
	createFile    func() (*os.File, error)
	createFileErr error
	io.WriteCloser
}

func (w *lazyWriteCloser) init() error {
	if w.createFileErr != nil {
		return w.createFileErr
	}
	if w.createFile == nil {
		return nil
	}
	f, err := w.createFile()
	if err != nil {
		w.createFileErr = err
		return err
	}
	w.createFile = nil
	w.WriteCloser = utils.NewBufferedWriteCloser(bufio.NewWriter(f), f)
	return nil
}

func (w *lazyWriteCloser) Write(b []byte) (int, error) {
	if err := w.init(); err != nil {
		return 0, err
	}
	return w.WriteCloser.Write(b)
}

func (w *lazyWriteCloser) Close() error {
	if err := w.init(); err != nil {
		return err
	}
	return w.WriteCloser.Close()
}

// DefaultTracer creates a qlog file in the qlog directory specified by the QLOGDIR environment variable.
// Deprecated: use DefaultConnectionTracer instead.
func DefaultTracer(ctx context.Context, p logging.Perspective, connID logging.ConnectionID) *logging.ConnectionTracer {
	return DefaultConnectionTracer(ctx, p, connID)
}

// DefaultConnectionTracer creates a qlog file in the qlog directory specified by the QLOGDIR environment variable.
// File names are <odcid>_<perspective>.qlog.
// Returns nil if QLOGDIR is not set.
func DefaultConnectionTracer(_ context.Context, p logging.Perspective, connID logging.ConnectionID) *logging.ConnectionTracer {
	var label string
	switch p {
	case logging.PerspectiveClient:
		label = "client"
	case logging.PerspectiveServer:
		label = "server"
	}
	return qlogDirTracer(p, connID, label)
}

// qlogDirTracer creates a qlog file in the qlog directory specified by the QLOGDIR environment variable.
// File names are <odcid>_<label>.qlog.
// Returns nil if QLOGDIR is not set.
func qlogDirTracer(p logging.Perspective, connID logging.ConnectionID, label string) *logging.ConnectionTracer {
	qlogDir := os.Getenv("QLOGDIR")
	if qlogDir == "" {
		return nil
	}
	return NewConnectionTracer(&lazyWriteCloser{createFile: func() (*os.File, error) {
		if _, err := os.Stat(qlogDir); os.IsNotExist(err) {
			if err := os.MkdirAll(qlogDir, 0o755); err != nil {
				return nil, fmt.Errorf("failed to create qlog dir %s: %v", qlogDir, err)
			}
		}
		path := fmt.Sprintf("%s/%s_%s.qlog", strings.TrimRight(qlogDir, "/"), connID, label)
		f, err := os.Create(path)
		if err != nil {
			return nil, fmt.Errorf("failed to create qlog file %s: %s", path, err.Error())
		}
		return f, nil
	}}, p, connID)
}
