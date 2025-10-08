package tools

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlogwriter"
)

func QlogTracer(logger io.Writer) qlogwriter.Trace {
	filename := fmt.Sprintf("log_%s_transport.qlog", time.Now().Format("2006-01-02T15:04:05"))
	fmt.Fprintf(logger, "Creating %s.\n", filename)
	f, err := os.Create(filename)
	if err != nil {
		log.Fatalf("failed to create qlog file: %s", err)
		return nil
	}
	bw := bufio.NewWriter(f)
	fileSeq := qlogwriter.NewFileSeq(utils.NewBufferedWriteCloser(bw, f))
	go fileSeq.Run()
	return fileSeq
}

func NewQlogConnectionTracer(logger io.Writer) func(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
	return func(_ context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
		pers := "server"
		if isClient {
			pers = "client"
		}
		filename := fmt.Sprintf("log_%s_%s.qlog", connID, pers)
		fmt.Fprintf(logger, "Creating %s.\n", filename)
		f, err := os.Create(filename)
		if err != nil {
			log.Fatalf("failed to create qlog file: %s", err)
			return nil
		}
		fileSeq := qlogwriter.NewConnectionFileSeq(utils.NewBufferedWriteCloser(bufio.NewWriter(f), f), isClient, connID)
		go fileSeq.Run()
		return fileSeq
	}
}
