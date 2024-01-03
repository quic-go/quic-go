package qlog

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"
)

// QlogDir contains the value of the QLOGDIR environment variable.
// If it is the empty string ("") no qlog output is written.
var QlogDir string

func init() {
	QlogDir = os.Getenv("QLOGDIR")
	if QlogDir != "" {
		if _, err := os.Stat(QlogDir); os.IsNotExist(err) {
			if err := os.MkdirAll(QlogDir, 0o755); err != nil {
				log.Fatalf("failed to create qlog dir %s: %v", QlogDir, err)
			}
		}
	}
}

// DefaultTracer creates a qlog file in the qlog directory specified by the QLOGDIR environment variable.
// File names are <odcid>_<perspective>.qlog.
// Returns nil if QLOGDIR is not set.
func DefaultTracer(_ context.Context, p logging.Perspective, connID logging.ConnectionID) *logging.ConnectionTracer {
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
	if QlogDir == "" {
		return nil
	}
	path := fmt.Sprintf("%s/%s_%s.qlog", strings.TrimRight(QlogDir, "/"), connID, label)
	f, err := os.Create(path)
	if err != nil {
		log.Printf("Failed to create qlog file %s: %s", path, err.Error())
		return nil
	}
	return NewConnectionTracer(utils.NewBufferedWriteCloser(bufio.NewWriter(f), f), p, connID)
}
