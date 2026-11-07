package self_test

import (
	"context"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/testutils/events"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

// remarkingRouter rewrites each packet's ECN codepoint using Remark.
type remarkingRouter struct {
	simnet.PerfectRouter

	Remark func(protocol.ECN) protocol.ECN
}

var _ simnet.Router = &remarkingRouter{}

func (r *remarkingRouter) SendPacket(p simnet.Packet) error {
	p.ECN = r.Remark(p.ECN)
	return r.PerfectRouter.SendPacket(p)
}

func TestECNValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		router simnet.Router
		want   qlog.ECNStateUpdated
	}{
		{
			name:   "clean path",
			router: &simnet.PerfectRouter{},
			want:   qlog.ECNStateUpdated{State: qlog.ECNStateCapable},
		},
		{
			name:   "bleaching",
			router: &remarkingRouter{Remark: func(protocol.ECN) protocol.ECN { return protocol.ECNNon }},
			want: qlog.ECNStateUpdated{
				State:   qlog.ECNStateFailed,
				Trigger: "ACK doesn't contain ECN marks",
			},
		},
		{
			name:   "dropping ECN-marked packets",
			router: &droppingRouter{Drop: func(p simnet.Packet) bool { return p.ECN == protocol.ECT0 }},
			want: qlog.ECNStateUpdated{
				State:   qlog.ECNStateFailed,
				Trigger: "all ECN testing packets declared lost",
			},
		},
		{
			name:   "remarking to ECT(1)",
			router: &remarkingRouter{Remark: func(protocol.ECN) protocol.ECN { return protocol.ECT1 }},
			want: qlog.ECNStateUpdated{
				State:   qlog.ECNStateFailed,
				Trigger: "ACK contains more ECN counts than ECN-marked packets sent",
			},
		},
		{
			name:   "remarking to CE",
			router: &remarkingRouter{Remark: func(protocol.ECN) protocol.ECN { return protocol.ECNCE }},
			want: qlog.ECNStateUpdated{
				State:   qlog.ECNStateFailed,
				Trigger: "ECN mangling detected",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				clientConn, serverConn, closeFn := newSimnetLinkWithRouter(t, 10*time.Millisecond, tc.router)
				defer closeFn(t)

				ln, err := quic.Listen(serverConn, getTLSConfig(), getQuicConfig(nil))
				require.NoError(t, err)
				defer ln.Close()

				var eventRecorder events.Recorder
				conn, err := quic.Dial(
					context.Background(),
					clientConn,
					ln.Addr(),
					getTLSClientConfig(),
					getQuicConfig(&quic.Config{Tracer: newTracer(&eventRecorder)}),
				)
				require.NoError(t, err)
				defer conn.CloseWithError(0, "")
				sconn, err := ln.Accept(context.Background())
				require.NoError(t, err)
				defer sconn.CloseWithError(0, "")

				str, err := conn.OpenStream()
				require.NoError(t, err)
				_, err = str.Write(PRData)
				require.NoError(t, err)
				require.NoError(t, str.Close())
				sstr, err := sconn.AcceptStream(context.Background())
				require.NoError(t, err)
				data, err := io.ReadAll(sstr)
				require.NoError(t, err)
				require.Equal(t, PRData, data)

				evs := eventRecorder.Events(qlog.ECNStateUpdated{})
				require.NotEmpty(t, evs)
				require.Equal(t, tc.want, evs[len(evs)-1])
			})
		})
	}
}
