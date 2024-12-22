package handshake

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	mrand "math/rand/v2"
	"testing"
	"time"

	mocklogging "github.com/quic-go/quic-go/internal/mocks/logging"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"go.uber.org/mock/gomock"

	"github.com/stretchr/testify/require"
)

const (
	msg = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
	ad  = "Donec in velit neque."
)

func randomCipherSuite() *cipherSuite { return cipherSuites[mrand.IntN(len(cipherSuites))] }

func setupEndpoints(t *testing.T, serverRTTStats *utils.RTTStats) (client, server *updatableAEAD, serverTracer *mocklogging.MockConnectionTracer) {
	cs := randomCipherSuite()
	mockCtrl := gomock.NewController(t)
	tr, serverTracer := mocklogging.NewMockConnectionTracer(mockCtrl)

	trafficSecret1 := make([]byte, 16)
	trafficSecret2 := make([]byte, 16)
	rand.Read(trafficSecret1)
	rand.Read(trafficSecret2)

	client = newUpdatableAEAD(&utils.RTTStats{}, nil, utils.DefaultLogger, protocol.Version1)
	server = newUpdatableAEAD(serverRTTStats, tr, utils.DefaultLogger, protocol.Version1)
	client.SetReadKey(cs, trafficSecret2)
	client.SetWriteKey(cs, trafficSecret1)
	server.SetReadKey(cs, trafficSecret1)
	server.SetWriteKey(cs, trafficSecret2)
	return client, server, serverTracer
}

func TestChaChaTestVector(t *testing.T) {
	testCases := []struct {
		name            string
		version         protocol.Version
		expectedPayload []byte
		expectedPacket  []byte
	}{
		{
			version:         protocol.Version1,
			expectedPayload: splitHexString(t, "655e5cd55c41f69080575d7999c25a5bfb"),
			expectedPacket:  splitHexString(t, "4cfe4189655e5cd55c41f69080575d7999c25a5bfb"),
		},
		{
			version:         protocol.Version2,
			expectedPayload: splitHexString(t, "0ae7b6b932bc27d786f4bc2bb20f2162ba"),
			expectedPacket:  splitHexString(t, "5558b1c60ae7b6b932bc27d786f4bc2bb20f2162ba"),
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("QUIC %s", tc.version), func(t *testing.T) {
			secret := splitHexString(t, "9ac312a7f877468ebe69422748ad00a1 5443f18203a07d6060f688f30f21632b")
			aead := newUpdatableAEAD(&utils.RTTStats{}, nil, nil, tc.version)
			chacha := cipherSuites[2]
			require.Equal(t, tls.TLS_CHACHA20_POLY1305_SHA256, chacha.ID)
			aead.SetWriteKey(chacha, secret)
			const pnOffset = 1
			header := splitHexString(t, "4200bff4")
			payloadOffset := len(header)
			plaintext := splitHexString(t, "01")
			payload := aead.Seal(nil, plaintext, 654360564, header)
			require.Equal(t, tc.expectedPayload, payload)
			packet := append(header, payload...)
			aead.EncryptHeader(packet[pnOffset+4:pnOffset+4+16], &packet[0], packet[pnOffset:payloadOffset])
			require.Equal(t, tc.expectedPacket, packet)
		})
	}
}

func TestUpdatableAEADHeaderProtection(t *testing.T) {
	for _, v := range []protocol.Version{protocol.Version1, protocol.Version2} {
		for _, cs := range cipherSuites {
			t.Run(fmt.Sprintf("QUIC %s/%s", v, tls.CipherSuiteName(cs.ID)), func(t *testing.T) {
				trafficSecret1 := make([]byte, 16)
				trafficSecret2 := make([]byte, 16)
				rand.Read(trafficSecret1)
				rand.Read(trafficSecret2)

				client := newUpdatableAEAD(&utils.RTTStats{}, nil, utils.DefaultLogger, v)
				server := newUpdatableAEAD(&utils.RTTStats{}, nil, utils.DefaultLogger, v)
				client.SetReadKey(cs, trafficSecret2)
				client.SetWriteKey(cs, trafficSecret1)
				server.SetReadKey(cs, trafficSecret1)
				server.SetWriteKey(cs, trafficSecret2)

				var lastFiveBitsDifferent int
				for i := 0; i < 100; i++ {
					sample := make([]byte, 16)
					rand.Read(sample)
					header := []byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}
					client.EncryptHeader(sample, &header[0], header[9:13])
					if header[0]&0x1f != 0xb5&0x1f {
						lastFiveBitsDifferent++
					}
					require.Equal(t, byte(0xb5&0xe0), header[0]&0xe0)
					require.Equal(t, []byte{1, 2, 3, 4, 5, 6, 7, 8}, header[1:9])
					require.NotEqual(t, []byte{0xde, 0xad, 0xbe, 0xef}, header[9:13])
					server.DecryptHeader(sample, &header[0], header[9:13])
					require.Equal(t, []byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}, header)
				}
				require.Greater(t, lastFiveBitsDifferent, 75)
			})
		}
	}
}

func TestUpdatableAEADEncryptDecryptMessage(t *testing.T) {
	for _, v := range []protocol.Version{protocol.Version1, protocol.Version2} {
		for _, cs := range cipherSuites {
			t.Run(fmt.Sprintf("QUIC %s/%s", v, tls.CipherSuiteName(cs.ID)), func(t *testing.T) {
				rttStats := utils.RTTStats{}
				trafficSecret1 := make([]byte, 16)
				trafficSecret2 := make([]byte, 16)
				rand.Read(trafficSecret1)
				rand.Read(trafficSecret2)

				client := newUpdatableAEAD(&rttStats, nil, utils.DefaultLogger, v)
				server := newUpdatableAEAD(&rttStats, nil, utils.DefaultLogger, v)
				client.SetReadKey(cs, trafficSecret2)
				client.SetWriteKey(cs, trafficSecret1)
				server.SetReadKey(cs, trafficSecret1)
				server.SetWriteKey(cs, trafficSecret2)

				msg := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")
				ad := []byte("Donec in velit neque.")

				encrypted := server.Seal(nil, msg, 0x1337, ad)

				opened, err := client.Open(nil, encrypted, time.Now(), 0x1337, protocol.KeyPhaseZero, ad)
				require.NoError(t, err)
				require.Equal(t, msg, opened)

				_, err = client.Open(nil, encrypted, time.Now(), 0x1337, protocol.KeyPhaseZero, []byte("wrong ad"))
				require.Equal(t, ErrDecryptionFailed, err)

				_, err = client.Open(nil, encrypted, time.Now(), 0x42, protocol.KeyPhaseZero, ad)
				require.Equal(t, ErrDecryptionFailed, err)
			})
		}
	}
}

func TestUpdatableAEADPacketNumbers(t *testing.T) {
	client, server, _ := setupEndpoints(t, &utils.RTTStats{})
	msg := []byte("Lorem ipsum")
	ad := []byte("Donec in velit neque.")

	encrypted := server.Seal(nil, msg, 0x1337, ad)
	require.Equal(t, protocol.PacketNumber(0x1337), server.FirstPacketNumber()) // make sure we save the first packet number
	_ = server.Seal(nil, msg, 0x1338, ad)
	require.Equal(t, protocol.PacketNumber(0x1337), server.FirstPacketNumber()) // make sure we save the first packet number

	// check that decoding the packet number works as expected
	_, err := client.Open(nil, encrypted[:len(encrypted)-1], time.Now(), 0x1337, protocol.KeyPhaseZero, ad)
	require.Error(t, err)
	require.Equal(t, protocol.PacketNumber(0x38), client.DecodePacketNumber(0x38, protocol.PacketNumberLen1))

	_, err = client.Open(nil, encrypted, time.Now(), 0x1337, protocol.KeyPhaseZero, ad)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(0x1338), client.DecodePacketNumber(0x38, protocol.PacketNumberLen1))
}

func TestAEADLimitReached(t *testing.T) {
	client, _, _ := setupEndpoints(t, &utils.RTTStats{})
	client.invalidPacketLimit = 10
	for i := 0; i < 9; i++ {
		_, err := client.Open(nil, []byte("foobar"), time.Now(), protocol.PacketNumber(i), protocol.KeyPhaseZero, []byte("ad"))
		require.Equal(t, ErrDecryptionFailed, err)
	}
	_, err := client.Open(nil, []byte("foobar"), time.Now(), 10, protocol.KeyPhaseZero, []byte("ad"))
	require.Error(t, err)
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.AEADLimitReached, transportErr.ErrorCode)
}

func TestKeyUpdates(t *testing.T) {
	client, server, _ := setupEndpoints(t, &utils.RTTStats{})

	now := time.Now()
	require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
	encrypted0 := server.Seal(nil, []byte(msg), 0x1337, []byte(ad))
	server.rollKeys()
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
	encrypted1 := server.Seal(nil, []byte(msg), 0x1337, []byte(ad))
	require.NotEqual(t, encrypted0, encrypted1)

	_, err := client.Open(nil, encrypted1, now, 0x1337, protocol.KeyPhaseZero, []byte(ad))
	require.Equal(t, ErrDecryptionFailed, err)

	client.rollKeys()
	decrypted, err := client.Open(nil, encrypted1, now, 0x1337, protocol.KeyPhaseOne, []byte(ad))
	require.NoError(t, err)
	require.Equal(t, msg, string(decrypted))
}

// func TestUpdatesKeysWhenReceivingPacketWithNextKeyPhase(t *testing.T) {
// 	rttStats := utils.RTTStats{}
// 	mockCtrl := gomock.NewController(t)
// 	serverTracer := mocklogging.NewMockConnectionTracer(mockCtrl)

// 	trafficSecret1 := make([]byte, 16)
// 	trafficSecret2 := make([]byte, 16)
// 	rand.Read(trafficSecret1)
// 	rand.Read(trafficSecret2)

// 	client := newUpdatableAEAD(&rttStats, nil, utils.DefaultLogger, protocol.Version1)
// 	server := newUpdatableAEAD(&rttStats, serverTracer, utils.DefaultLogger, protocol.Version1)
// 	client.SetReadKey(cs, trafficSecret2)
// 	client.SetWriteKey(cs, trafficSecret1)
// 	server.SetReadKey(cs, trafficSecret1)
// 	server.SetWriteKey(cs, trafficSecret2)

// 	now := time.Now()
// 	encrypted0 := client.Seal(nil, []byte(msg), 0x42, ad)
// 	decrypted, err := server.Open(nil, encrypted0, now, 0x42, protocol.KeyPhaseZero, ad)
// 	require.NoError(t, err)
// 	require.Equal(t, msg, decrypted)

// 	require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
// 	_ = server.Seal(nil, msg, 0x1, ad)

// 	client.rollKeys()
// 	encrypted1 := client.Seal(nil, msg, 0x43, ad)
// 	serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), true)
// 	decrypted, err = server.Open(nil, encrypted1, now, 0x43, protocol.KeyPhaseOne, ad)
// 	require.NoError(t, err)
// 	require.Equal(t, msg, decrypted)
// 	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
// }

func TestReorderedPacketAfterKeyUpdate(t *testing.T) {
	client, server, serverTracer := setupEndpoints(t, &utils.RTTStats{})

	now := time.Now()
	encrypted01 := client.Seal(nil, []byte(msg), 0x42, []byte(ad))
	encrypted02 := client.Seal(nil, []byte(msg), 0x43, []byte(ad))
	_, err := server.Open(nil, encrypted01, now, 0x42, protocol.KeyPhaseZero, []byte(ad))
	require.NoError(t, err)
	_ = server.Seal(nil, []byte(msg), 0x1, []byte(ad))

	client.rollKeys()
	encrypted1 := client.Seal(nil, []byte(msg), 0x44, []byte(ad))
	require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
	serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), true)
	_, err = server.Open(nil, encrypted1, now, 0x44, protocol.KeyPhaseOne, []byte(ad))
	require.NoError(t, err)
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())

	// now receive a reordered packet
	decrypted, err := server.Open(nil, encrypted02, now, 0x43, protocol.KeyPhaseZero, []byte(ad))
	require.NoError(t, err)
	require.Equal(t, msg, string(decrypted))
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
}

func TestDropsKeys3PTOsAfterKeyUpdate(t *testing.T) {
	var rttStats utils.RTTStats
	client, server, serverTracer := setupEndpoints(t, &rttStats)

	now := time.Now()
	rttStats.UpdateRTT(10*time.Millisecond, 0)
	pto := rttStats.PTO(true)
	encrypted01 := client.Seal(nil, []byte(msg), 0x42, []byte(ad))
	encrypted02 := client.Seal(nil, []byte(msg), 0x43, []byte(ad))
	_, err := server.Open(nil, encrypted01, now, 0x42, protocol.KeyPhaseZero, []byte(ad))
	require.NoError(t, err)
	_ = server.Seal(nil, []byte(msg), 0x1, []byte(ad))

	client.rollKeys()
	encrypted1 := client.Seal(nil, []byte(msg), 0x44, []byte(ad))
	require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
	serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), true)
	serverTracer.EXPECT().DroppedKey(protocol.KeyPhase(0))
	_, err = server.Open(nil, encrypted1, now, 0x44, protocol.KeyPhaseOne, []byte(ad))
	require.NoError(t, err)
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())

	// packet arrived too late, the key was already dropped
	_, err = server.Open(nil, encrypted02, now.Add(3*pto).Add(time.Nanosecond), 0x43, protocol.KeyPhaseZero, []byte(ad))
	require.Equal(t, ErrKeysDropped, err)
}

func TestAllowsFirstKeyUpdateImmediately(t *testing.T) {
	client, server, serverTracer := setupEndpoints(t, &utils.RTTStats{})
	client.rollKeys()
	encrypted := client.Seal(nil, []byte(msg), 0x1337, []byte(ad))

	// if decryption failed, we don't expect a key phase update
	_, err := server.Open(nil, encrypted[:len(encrypted)-1], time.Now(), 0x1337, protocol.KeyPhaseOne, []byte(ad))
	require.Equal(t, ErrDecryptionFailed, err)

	// the key phase is updated on first successful decryption
	serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), true)
	_, err = server.Open(nil, encrypted, time.Now(), 0x1337, protocol.KeyPhaseOne, []byte(ad))
	require.NoError(t, err)
}

func TestRejectFrequentKeyUpdates(t *testing.T) {
	client, server, _ := setupEndpoints(t, &utils.RTTStats{})

	server.rollKeys()
	client.rollKeys()
	encrypted0 := client.Seal(nil, []byte(msg), 0x42, []byte(ad))
	_, err := server.Open(nil, encrypted0, time.Now(), 0x42, protocol.KeyPhaseOne, []byte(ad))
	require.NoError(t, err)

	client.rollKeys()
	encrypted1 := client.Seal(nil, []byte(msg), 0x42, []byte(ad))
	_, err = server.Open(nil, encrypted1, time.Now(), 0x42, protocol.KeyPhaseZero, []byte(ad))
	require.Equal(t, &qerr.TransportError{
		ErrorCode:    qerr.KeyUpdateError,
		ErrorMessage: "keys updated too quickly",
	}, err)
}

func setKeyUpdateIntervals(t *testing.T, firstKeyUpdateInterval, keyUpdateInterval uint64) {
	origKeyUpdateInterval := KeyUpdateInterval
	origFirstKeyUpdateInterval := FirstKeyUpdateInterval
	KeyUpdateInterval = keyUpdateInterval
	FirstKeyUpdateInterval = firstKeyUpdateInterval

	t.Cleanup(func() {
		KeyUpdateInterval = origKeyUpdateInterval
		FirstKeyUpdateInterval = origFirstKeyUpdateInterval
	})
}

func TestInitiateKeyUpdateAfterSendingMaxPackets(t *testing.T) {
	const firstKeyUpdateInterval = 5
	const keyUpdateInterval = 20
	setKeyUpdateIntervals(t, firstKeyUpdateInterval, keyUpdateInterval)

	client, server, serverTracer := setupEndpoints(t, &utils.RTTStats{})
	server.SetHandshakeConfirmed()

	var pn protocol.PacketNumber
	// first key update
	for i := 0; i < firstKeyUpdateInterval; i++ {
		require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
		server.Seal(nil, []byte(msg), pn, []byte(ad))
		pn++
	}
	// the first update is allowed without receiving an acknowledgement
	serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), false)
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())

	// subsequent key update
	for i := 0; i < 2*keyUpdateInterval; i++ {
		require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
		server.Seal(nil, []byte(msg), pn, []byte(ad))
		pn++
	}
	// no update allowed before receiving an acknowledgement for the current key phase
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
	// receive an ACK for a packet sent in key phase 1
	client.rollKeys()
	b := client.Seal(nil, []byte("foobar"), 1, []byte("ad"))
	_, err := server.Open(nil, b, time.Now(), 1, protocol.KeyPhaseOne, []byte("ad"))
	require.NoError(t, err)
	require.NoError(t, server.SetLargestAcked(firstKeyUpdateInterval))

	serverTracer.EXPECT().DroppedKey(protocol.KeyPhase(0))
	serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(2), false)
	require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
}

func TestKeyUpdateEnforceACKKeyPhase(t *testing.T) {
	const firstKeyUpdateInterval = 5
	setKeyUpdateIntervals(t, firstKeyUpdateInterval, KeyUpdateInterval)

	_, server, serverTracer := setupEndpoints(t, &utils.RTTStats{})
	server.SetHandshakeConfirmed()

	// First make sure that we update our keys.
	for i := 0; i < firstKeyUpdateInterval; i++ {
		pn := protocol.PacketNumber(i)
		require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
		server.Seal(nil, []byte(msg), pn, []byte(ad))
	}
	serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), false)
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())

	// Now that our keys are updated, send a packet using the new keys.
	const nextPN = firstKeyUpdateInterval + 1
	server.Seal(nil, []byte(msg), nextPN, []byte(ad))

	for i := 0; i < firstKeyUpdateInterval; i++ {
		// We haven't decrypted any packet in the new key phase yet.
		// This means that the ACK must have been sent in the old key phase.
		require.NoError(t, server.SetLargestAcked(protocol.PacketNumber(i)))
	}

	// We haven't decrypted any packet in the new key phase yet.
	// This means that the ACK must have been sent in the old key phase.
	err := server.SetLargestAcked(nextPN)
	require.Error(t, err)
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.KeyUpdateError, transportErr.ErrorCode)
	require.Equal(t, "received ACK for key phase 1, but peer didn't update keys", transportErr.ErrorMessage)
}

func TestKeyUpdateAfterOpeningMaxPackets(t *testing.T) {
	const firstKeyUpdateInterval = 5
	const keyUpdateInterval = 20
	setKeyUpdateIntervals(t, firstKeyUpdateInterval, keyUpdateInterval)

	client, server, serverTracer := setupEndpoints(t, &utils.RTTStats{})
	server.SetHandshakeConfirmed()

	msg := []byte("message")
	ad := []byte("additional data")

	// first key update
	var pn protocol.PacketNumber
	for i := 0; i < firstKeyUpdateInterval; i++ {
		require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
		encrypted := client.Seal(nil, msg, pn, ad)
		_, err := server.Open(nil, encrypted, time.Now(), pn, protocol.KeyPhaseZero, ad)
		require.NoError(t, err)
		pn++
	}

	// the first update is allowed without receiving an acknowledgement
	serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), false)
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())

	// subsequent key update
	client.rollKeys()
	for i := 0; i < keyUpdateInterval; i++ {
		require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
		encrypted := client.Seal(nil, msg, pn, ad)
		_, err := server.Open(nil, encrypted, time.Now(), pn, protocol.KeyPhaseOne, ad)
		require.NoError(t, err)
		pn++
	}

	// No update allowed before receiving an acknowledgement for the current key phase
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
	server.Seal(nil, msg, 1, ad)
	require.NoError(t, server.SetLargestAcked(firstKeyUpdateInterval+1))
	serverTracer.EXPECT().DroppedKey(protocol.KeyPhase(0))
	serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(2), false)
	require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
}

func TestKeyUpdateKeyPhaseSkipping(t *testing.T) {
	const firstKeyUpdateInterval = 5
	const keyUpdateInterval = 20
	setKeyUpdateIntervals(t, firstKeyUpdateInterval, keyUpdateInterval)

	var rttStats utils.RTTStats
	rttStats.UpdateRTT(10*time.Millisecond, 0)
	client, server, serverTracer := setupEndpoints(t, &rttStats)
	server.SetHandshakeConfirmed()

	now := time.Now()
	data1 := client.Seal(nil, []byte(msg), 1, []byte(ad))
	_, err := server.Open(nil, data1, now, 1, protocol.KeyPhaseZero, []byte(ad))
	require.NoError(t, err)
	for i := 0; i < firstKeyUpdateInterval; i++ {
		pn := protocol.PacketNumber(i)
		require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
		server.Seal(nil, []byte(msg), pn, []byte(ad))
		require.NoError(t, server.SetLargestAcked(pn))
	}
	serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), false)
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
	// The server never received a packet at key phase 1.
	// Make sure the key phase 0 is still there at a much later point.
	data2 := client.Seal(nil, []byte(msg), 1, []byte(ad))
	_, err = server.Open(nil, data2, now.Add(10*rttStats.PTO(true)), 1, protocol.KeyPhaseZero, []byte(ad))
	require.NoError(t, err)
}

func TestFastKeyUpdatesByPeer(t *testing.T) {
	const firstKeyUpdateInterval = 5
	const keyUpdateInterval = 20
	setKeyUpdateIntervals(t, firstKeyUpdateInterval, keyUpdateInterval)

	client, server, serverTracer := setupEndpoints(t, &utils.RTTStats{})
	server.SetHandshakeConfirmed()

	var pn protocol.PacketNumber
	for i := 0; i < firstKeyUpdateInterval; i++ {
		require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
		server.Seal(nil, []byte(msg), pn, []byte(ad))
		pn++
	}
	b := client.Seal(nil, []byte("foobar"), 1, []byte("ad"))
	_, err := server.Open(nil, b, time.Now(), 1, protocol.KeyPhaseZero, []byte("ad"))
	require.NoError(t, err)
	require.NoError(t, server.SetLargestAcked(0))
	serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), false)
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())

	// Send and receive an acknowledgement for a packet in key phase 1.
	// We are now running a timer to drop the keys with 3 PTO.
	server.Seal(nil, []byte(msg), pn, []byte(ad))
	client.rollKeys()
	dataKeyPhaseOne := client.Seal(nil, []byte(msg), 2, []byte(ad))
	now := time.Now()
	_, err = server.Open(nil, dataKeyPhaseOne, now, 2, protocol.KeyPhaseOne, []byte(ad))
	require.NoError(t, err)
	require.NoError(t, server.SetLargestAcked(pn))
	// Now the client sends us a packet in key phase 2, forcing us to update keys before the 3 PTO period is over.
	// This mean that we need to drop the keys for key phase 0 immediately.
	client.rollKeys()
	dataKeyPhaseTwo := client.Seal(nil, []byte(msg), 3, []byte(ad))
	gomock.InOrder(
		serverTracer.EXPECT().DroppedKey(protocol.KeyPhase(0)),
		serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(2), true),
	)
	_, err = server.Open(nil, dataKeyPhaseTwo, now, 3, protocol.KeyPhaseZero, []byte(ad))
	require.NoError(t, err)
	require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
}

func TestFastKeyUpdateByUs(t *testing.T) {
	const firstKeyUpdateInterval = 5
	const keyUpdateInterval = 20
	setKeyUpdateIntervals(t, firstKeyUpdateInterval, keyUpdateInterval)

	var rttStats utils.RTTStats
	rttStats.UpdateRTT(10*time.Millisecond, 0)
	client, server, serverTracer := setupEndpoints(t, &rttStats)
	server.SetHandshakeConfirmed()

	// send so many packets that we initiate the first key update
	for i := 0; i < firstKeyUpdateInterval; i++ {
		pn := protocol.PacketNumber(i)
		require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())
		server.Seal(nil, []byte(msg), pn, []byte(ad))
	}
	b := client.Seal(nil, []byte("foobar"), 1, []byte("ad"))
	_, err := server.Open(nil, b, time.Now(), 1, protocol.KeyPhaseZero, []byte("ad"))
	require.NoError(t, err)
	require.NoError(t, server.SetLargestAcked(0))
	serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), false)
	require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())

	// send so many packets that we initiate the next key update
	for i := keyUpdateInterval; i < 2*keyUpdateInterval; i++ {
		pn := protocol.PacketNumber(i)
		require.Equal(t, protocol.KeyPhaseOne, server.KeyPhase())
		server.Seal(nil, []byte(msg), pn, []byte(ad))
	}
	client.rollKeys()
	b = client.Seal(nil, []byte("foobar"), 2, []byte("ad"))
	now := time.Now()
	_, err = server.Open(nil, b, now, 2, protocol.KeyPhaseOne, []byte("ad"))
	require.NoError(t, err)
	require.NoError(t, server.SetLargestAcked(keyUpdateInterval))
	gomock.InOrder(
		serverTracer.EXPECT().DroppedKey(protocol.KeyPhase(0)),
		serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(2), false),
	)
	require.Equal(t, protocol.KeyPhaseZero, server.KeyPhase())

	// We haven't received an ACK for a packet sent in key phase 2 yet.
	// Make sure we canceled the timer to drop the previous key phase.
	b = client.Seal(nil, []byte("foobar"), 3, []byte("ad"))
	_, err = server.Open(nil, b, now.Add(10*rttStats.PTO(true)), 3, protocol.KeyPhaseOne, []byte("ad"))
	require.NoError(t, err)
}

func getClientAndServer() (client, server *updatableAEAD) {
	trafficSecret1 := make([]byte, 16)
	trafficSecret2 := make([]byte, 16)
	rand.Read(trafficSecret1)
	rand.Read(trafficSecret2)

	cs := cipherSuites[0]
	var rttStats utils.RTTStats
	client = newUpdatableAEAD(&rttStats, nil, utils.DefaultLogger, protocol.Version1)
	server = newUpdatableAEAD(&rttStats, nil, utils.DefaultLogger, protocol.Version1)
	client.SetReadKey(cs, trafficSecret2)
	client.SetWriteKey(cs, trafficSecret1)
	server.SetReadKey(cs, trafficSecret1)
	server.SetWriteKey(cs, trafficSecret2)
	return
}

func BenchmarkPacketEncryption(b *testing.B) {
	client, _ := getClientAndServer()
	const l = 1200
	src := make([]byte, l)
	rand.Read(src)
	ad := make([]byte, 32)
	rand.Read(ad)

	for i := 0; i < b.N; i++ {
		src = client.Seal(src[:0], src[:l], protocol.PacketNumber(i), ad)
	}
}

func BenchmarkPacketDecryption(b *testing.B) {
	client, server := getClientAndServer()
	const l = 1200
	src := make([]byte, l)
	dst := make([]byte, l)
	rand.Read(src)
	ad := make([]byte, 32)
	rand.Read(ad)
	src = client.Seal(src[:0], src[:l], 1337, ad)

	for i := 0; i < b.N; i++ {
		if _, err := server.Open(dst[:0], src, time.Time{}, 1337, protocol.KeyPhaseZero, ad); err != nil {
			b.Fatalf("opening failed: %v", err)
		}
	}
}

func BenchmarkRollKeys(b *testing.B) {
	client, _ := getClientAndServer()
	for i := 0; i < b.N; i++ {
		client.rollKeys()
	}
	if int(client.keyPhase) != b.N {
		b.Fatal("didn't roll keys often enough")
	}
}
