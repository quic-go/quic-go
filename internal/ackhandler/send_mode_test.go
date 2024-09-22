package ackhandler

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSendModeStringer(t *testing.T) {
	require.Equal(t, "none", SendNone.String())
	require.Equal(t, "any", SendAny.String())
	require.Equal(t, "pacing limited", SendPacingLimited.String())
	require.Equal(t, "ack", SendAck.String())
	require.Equal(t, "pto (Initial)", SendPTOInitial.String())
	require.Equal(t, "pto (Handshake)", SendPTOHandshake.String())
	require.Equal(t, "pto (Application Data)", SendPTOAppData.String())
	require.Equal(t, "invalid send mode: 123", SendMode(123).String())
}
