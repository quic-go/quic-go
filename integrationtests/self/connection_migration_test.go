package self_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

func TestConnectionMigration(t *testing.T) {
	var serverEvents events.Recorder
	ln, err := quic.ListenAddr("localhost:0", getTLSConfig(), getQuicConfig(&quic.Config{Tracer: newTracer(&serverEvents)}))
	require.NoError(t, err)
	defer ln.Close()

	tr1 := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	defer tr1.Close()
	tr2 := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	defer tr2.Close()

	var packetsPath1, packetsPath2 atomic.Int64

	const rtt = 5 * time.Millisecond
	proxy := quicproxy.Proxy{
		Conn:       newUDPConnLocalhost(t),
		ServerAddr: ln.Addr().(*net.UDPAddr),
		DelayPacket: func(dir quicproxy.Direction, from, to net.Addr, _ []byte) time.Duration {
			var port int
			switch dir {
			case quicproxy.DirectionIncoming:
				port = from.(*net.UDPAddr).Port
			case quicproxy.DirectionOutgoing:
				port = to.(*net.UDPAddr).Port
			}
			switch port {
			case tr1.Conn.LocalAddr().(*net.UDPAddr).Port:
				packetsPath1.Add(1)
			case tr2.Conn.LocalAddr().(*net.UDPAddr).Port:
				packetsPath2.Add(1)
			default:
				fmt.Println("address not found", from)
			}
			return rtt / 2
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var clientEvents events.Recorder
	conn, err := tr1.Dial(ctx, proxy.LocalAddr(), getTLSClientConfig(), getQuicConfig(&quic.Config{Tracer: newTracer(&clientEvents)}))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	// probeTuples returns the tuples of the packets sent and received with a PATH_CHALLENGE,
	// starting at the given event index.
	probeTuples := func(r *events.Recorder, since int) []string {
		var tuples []string
		for _, ev := range r.Events()[since:] {
			switch e := ev.(type) {
			case qlog.PacketSent:
				if hasFrame[*qlog.PathChallengeFrame](e.Frames) {
					tuples = append(tuples, e.Tuple)
				}
			case qlog.PacketReceived:
				if hasFrame[*qlog.PathChallengeFrame](e.Frames) {
					tuples = append(tuples, e.Tuple)
				}
			}
		}
		return slices.Compact(tuples)
	}
	// sentTuples returns the tuples of the packets sent, starting at the given event index.
	sentTuples := func(since int) []string {
		var tuples []string
		for _, ev := range clientEvents.Events()[since:] {
			if e, ok := ev.(qlog.PacketSent); ok {
				tuples = append(tuples, e.Tuple)
			}
		}
		return slices.Compact(tuples)
	}
	// assignedTuples returns the TupleIDs of all tuple_assigned events.
	assignedTuples := func(r *events.Recorder) []string {
		var tuples []string
		for _, ev := range r.Events(qlog.TupleAssigned{}) {
			tuples = append(tuples, ev.(qlog.TupleAssigned).TupleID)
		}
		return tuples
	}

	sconn, err := ln.Accept(ctx)
	require.NoError(t, err)
	defer sconn.CloseWithError(0, "")

	sendAndReceiveFile := func(t *testing.T) {
		t.Helper()
		str, err := conn.OpenUniStream()
		require.NoError(t, err)

		errChan := make(chan error, 1)
		go func() {
			defer close(errChan)
			sstr, err := sconn.AcceptUniStream(ctx)
			if err != nil {
				errChan <- fmt.Errorf("accepting stream: %w", err)
				return
			}
			data, err := io.ReadAll(sstr)
			if err != nil {
				errChan <- fmt.Errorf("reading stream data: %w", err)
				return
			}
			if !bytes.Equal(data, PRData) {
				errChan <- errors.New("unexpected data")
			}
		}()

		_, err = str.Write(PRData)
		require.NoError(t, err)
		require.NoError(t, str.Close())

		select {
		case err := <-errChan:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for data")
		}
	}

	sendAndReceiveFile(t) // stream 2
	require.NotZero(t, packetsPath1.Load())
	require.Zero(t, packetsPath2.Load())

	// probing the path causes a few packets to be sent on path 2
	path, err := conn.AddPath(tr2)
	require.NoError(t, err)
	require.ErrorIs(t, path.Switch(), quic.ErrPathNotValidated)
	n, ns := len(clientEvents.Events()), len(serverEvents.Events())
	require.NoError(t, path.Probe(ctx))
	require.Less(t, int(packetsPath2.Load()), 5)

	// the new path is assigned a new tuple, which is used for probing
	require.Equal(t, []string{"1"}, assignedTuples(&clientEvents))
	require.Equal(t, []string{"1"}, probeTuples(&clientEvents, n))
	require.Equal(t, []string{"0"}, assignedTuples(&serverEvents))
	require.Equal(t, []string{"0"}, probeTuples(&serverEvents, ns))

	time.Sleep(3 * rtt) // the client responds to the server's PATH_CHALLENGE after Probe returns

	// the client responded to the server's PATH_CHALLENGE on the new path
	var responseTuples []string
	for _, ev := range clientEvents.Events()[n:] {
		if e, ok := ev.(qlog.PacketSent); ok && hasFrame[*qlog.PathResponseFrame](e.Frames) {
			responseTuples = append(responseTuples, e.Tuple)
		}
	}
	require.Equal(t, []string{"1"}, slices.Compact(responseTuples))

	// make sure that no more packets are sent on path 2 before switching to the path
	c2 := packetsPath2.Load()
	sendAndReceiveFile(t) // stream 6
	require.Equal(t, packetsPath2.Load(), c2)

	time.Sleep(3 * rtt) // wait for ACKs

	// now switch and make sure that no packets are sent on path 1
	n = len(clientEvents.Events())
	require.NoError(t, path.Switch())
	sendAndReceiveFile(t) // stream 10
	// the old path is assigned its own tuple, and the default tuple now refers to the new path
	require.Equal(t, []string{"1", "0", ""}, assignedTuples(&clientEvents))
	require.Equal(t, []string{""}, sentTuples(n))
	// The server switches when it receives the stream data on the new path.
	// Late packets from the old path might cause it to probe the old path again afterwards.
	require.Eventually(t, func() bool {
		tuples := assignedTuples(&serverEvents)
		return len(tuples) >= 2 && slices.Equal([]string{"0", ""}, tuples[:2])
	}, time.Second, 5*time.Millisecond)
	c1 := packetsPath1.Load()
	require.Equal(t, c1, packetsPath1.Load())
	require.Greater(t, packetsPath2.Load(), c2)
	require.Equal(t, tr2.Conn.LocalAddr(), conn.LocalAddr())

	// switch back to the handshake path
	time.Sleep(3 * rtt) // wait for ACKs
	c1BeforeSwitch := packetsPath1.Load()
	c2BeforeSwitch := packetsPath2.Load()
	path2, err := conn.AddPath(tr1)
	require.NoError(t, err)
	n, ns = len(clientEvents.Events()), len(serverEvents.Events())
	require.NoError(t, path2.Probe(ctx))
	// the handshake path was assigned its tuple when switching away from it
	require.Equal(t, []string{"0"}, probeTuples(&clientEvents, n))
	require.Len(t, assignedTuples(&clientEvents), 3)
	// for the server, the old address is a new path
	require.Equal(t, []string{"1"}, probeTuples(&serverEvents, ns))
	time.Sleep(3 * rtt) // wait for ACKs
	n = len(clientEvents.Events())
	require.NoError(t, path2.Switch())
	sendAndReceiveFile(t) // stream 14
	require.Equal(t, []string{"1", "0", "", "1", ""}, assignedTuples(&clientEvents))
	require.Equal(t, []string{""}, sentTuples(n))
	require.Eventually(t, func() bool {
		return slices.Equal([]string{"0", "", "1", ""}, assignedTuples(&serverEvents))
	}, time.Second, 5*time.Millisecond)
	require.Greater(t, packetsPath1.Load(), c1BeforeSwitch)
	// some path probing might have happened
	require.Less(t, int(packetsPath2.Load()-c2BeforeSwitch), 20)
	require.Equal(t, tr1.Conn.LocalAddr(), conn.LocalAddr())
}

func hasFrame[T any](frames []qlog.Frame) bool {
	return slices.ContainsFunc(frames, func(f qlog.Frame) bool {
		_, ok := f.Frame.(T)
		return ok
	})
}
