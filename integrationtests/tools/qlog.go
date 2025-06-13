package tools

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/Noooste/uquic-go"
	"github.com/Noooste/uquic-go/internal/utils"
	"github.com/Noooste/uquic-go/logging"
	"github.com/Noooste/uquic-go/qlog"
)

func QlogTracer(logger io.Writer) *logging.Tracer {
	filename := fmt.Sprintf("log_%s_transport.qlog", time.Now().Format("2006-01-02T15:04:05"))
	fmt.Fprintf(logger, "Creating %s.\n", filename)
	f, err := os.Create(filename)
	if err != nil {
		log.Fatalf("failed to create qlog file: %s", err)
		return nil
	}
	bw := bufio.NewWriter(f)
	return qlog.NewTracer(utils.NewBufferedWriteCloser(bw, f))
}

func NewQlogConnectionTracer(logger io.Writer) func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
	return func(_ context.Context, p logging.Perspective, connID quic.ConnectionID) *logging.ConnectionTracer {
		filename := fmt.Sprintf("log_%s_%s.qlog", connID, p.String())
		fmt.Fprintf(logger, "Creating %s.\n", filename)
		f, err := os.Create(filename)
		if err != nil {
			log.Fatalf("failed to create qlog file: %s", err)
			return nil
		}
		bw := bufio.NewWriter(f)
		return qlog.NewConnectionTracer(utils.NewBufferedWriteCloser(bw, f), p, connID)
	}
}
