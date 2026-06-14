package self_test

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingCC is a CongestionController that records how many times each method was called.
type recordingCC struct {
	onPacketSentCalls  atomic.Int32
	onPacketAckedCalls atomic.Int32
	canSendCalls       atomic.Int32
}

func (c *recordingCC) OnPacketSent(_ time.Time, _ quic.ByteCount, _ quic.PacketNumber, _ quic.ByteCount, _ bool) {
	c.onPacketSentCalls.Add(1)
}

func (c *recordingCC) CanSend(_ quic.ByteCount) bool {
	c.canSendCalls.Add(1)
	return true
}

func (c *recordingCC) OnPacketAcked(_ quic.PacketNumber, _ quic.ByteCount, _ quic.ByteCount, _ time.Time) {
	c.onPacketAckedCalls.Add(1)
}

func (c *recordingCC) OnCongestionEvent(_ quic.PacketNumber, _ quic.ByteCount, _ quic.ByteCount) {}

func (c *recordingCC) OnRetransmissionTimeout(_ bool) {}

func (c *recordingCC) SetMaxDatagramSize(_ quic.ByteCount) {}

func TestCustomCongestionController(t *testing.T) {
	var cc recordingCC

	ln, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		str, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		io.Copy(str, str) //nolint:errcheck
		str.Close()       //nolint:errcheck
		// Let the client close it.
		<-conn.Context().Done()
	}()

	conn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		ln.Addr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{CongestionController: func() quic.CongestionController { return &cc }}),
	)
	require.NoError(t, err)

	str, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)

	data := GeneratePRData(32 * 1024)
	_, err = str.Write(data)
	require.NoError(t, err)
	require.NoError(t, str.Close())

	got, err := io.ReadAll(str)
	require.NoError(t, err)
	assert.Equal(t, data, got)

	conn.CloseWithError(0, "")
	<-serverDone

	assert.Greater(t, cc.onPacketSentCalls.Load(), int32(0), "OnPacketSent should have been called")
	assert.Greater(t, cc.onPacketAckedCalls.Load(), int32(0), "OnPacketAcked should have been called")
	assert.Greater(t, cc.canSendCalls.Load(), int32(0), "CanSend should have been called")
}

func TestDefaultCongestionController(t *testing.T) {
	ln, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		str, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		io.Copy(str, str) //nolint:errcheck
		str.Close()       //nolint:errcheck
		<-conn.Context().Done()
	}()

	conn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		ln.Addr(),
		getTLSClientConfig(),
		getQuicConfig(nil), // nil CC = use default NewReno
	)
	require.NoError(t, err)

	str, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)

	data := GeneratePRData(32 * 1024)
	_, err = str.Write(data)
	require.NoError(t, err)
	require.NoError(t, str.Close())

	got, err := io.ReadAll(str)
	require.NoError(t, err)
	assert.Equal(t, data, got)

	conn.CloseWithError(0, "")
	<-serverDone
}
