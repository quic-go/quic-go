package self_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

func TestConnectionMigration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 5 * time.Millisecond
		network := newTestNetworkWithSettings(t, simnet.NodeBiDiLinkSettings{Latency: rtt / 2})

		var serverEvents events.Recorder
		ln, err := quic.Listen(network.NewConn(), getTLSConfig(), getQuicConfig(&quic.Config{Tracer: newTracer(&serverEvents)}))
		require.NoError(t, err)
		defer ln.Close()

		pc1 := network.NewConn()
		tr1 := &quic.Transport{Conn: pc1}
		defer tr1.Close()
		pc2 := network.NewConn()
		tr2 := &quic.Transport{Conn: pc2}
		defer tr2.Close()

		// packetsOnPath returns the number of packets sent and received on a path
		packetsOnPath := func(c *simnet.SimConn) int {
			s := c.Stats()
			return s.PacketsSent + s.PacketsRcvd
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var clientEvents events.Recorder
		conn, err := tr1.Dial(ctx, ln.Addr(), getTLSClientConfig(), getQuicConfig(&quic.Config{Tracer: newTracer(&clientEvents)}))
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
		require.NotZero(t, packetsOnPath(pc1))
		require.Zero(t, packetsOnPath(pc2))

		// probing the path causes a few packets to be sent on path 2
		path, err := conn.AddPath(tr2)
		require.NoError(t, err)
		require.ErrorIs(t, path.Switch(), quic.ErrPathNotValidated)
		n, ns := len(clientEvents.Events()), len(serverEvents.Events())
		require.NoError(t, path.Probe(ctx))
		require.Less(t, packetsOnPath(pc2), 5)

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
		c2 := packetsOnPath(pc2)
		sendAndReceiveFile(t) // stream 6
		require.Equal(t, packetsOnPath(pc2), c2)

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
		c1 := packetsOnPath(pc1)
		require.Equal(t, c1, packetsOnPath(pc1))
		require.Greater(t, packetsOnPath(pc2), c2)
		require.Equal(t, tr2.Conn.LocalAddr(), conn.LocalAddr())

		// switch back to the handshake path
		time.Sleep(3 * rtt) // wait for ACKs
		c1BeforeSwitch := packetsOnPath(pc1)
		c2BeforeSwitch := packetsOnPath(pc2)
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
		require.Greater(t, packetsOnPath(pc1), c1BeforeSwitch)
		// some path probing might have happened
		require.Less(t, packetsOnPath(pc2)-c2BeforeSwitch, 20)
		require.Equal(t, tr1.Conn.LocalAddr(), conn.LocalAddr())

		// switch to the first path again, which doesn't require probing it again
		require.NoError(t, path.Switch())
		sendAndReceiveFile(t) // stream 18
		require.Equal(t, tr2.Conn.LocalAddr(), conn.LocalAddr())

		requireConnIDsNotLinkable(t, clientEvents.Events())
		requireConnIDsNotLinkable(t, serverEvents.Events())
	})
}

// requireConnIDsNotLinkable checks that no connection ID is used on more than one tuple,
// since this would allow an on-path observer to link the tuples, see section 9.5 of RFC 9000.
func requireConnIDsNotLinkable(t *testing.T, evs []qlogwriter.Event) {
	t.Helper()

	type tuple struct {
		local, remote qlog.TupleEndpointInfo
	}

	tuples := make(map[string]tuple) // by TupleID
	usedOn := make(map[qlog.ConnectionID]tuple)
	for _, ev := range evs {
		switch e := ev.(type) {
		case qlog.StartedConnection:
			tuples[""] = tuple{local: e.Local, remote: e.Remote}
		case qlog.TupleAssigned:
			tuples[e.TupleID] = tuple{local: e.Local, remote: e.Remote}
		case qlog.PacketSent:
			connID := e.Header.DestConnectionID
			if connID.Len() == 0 {
				continue
			}
			tup, ok := tuples[e.Tuple]
			require.True(t, ok, "packet sent on unknown tuple %q", e.Tuple)
			if prev, ok := usedOn[connID]; ok {
				require.Equal(t, prev, tup, "connection ID %s used on multiple tuples", connID)
			}
			usedOn[connID] = tup
		}
	}
	require.NotEmpty(t, usedOn)
}

func hasFrame[T any](frames []qlog.Frame) bool {
	return slices.ContainsFunc(frames, func(f qlog.Frame) bool {
		_, ok := f.Frame.(T)
		return ok
	})
}
