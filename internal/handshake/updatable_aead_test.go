package handshake

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	mocklogging "github.com/quic-go/quic-go/internal/mocks/logging"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Updatable AEAD", func() {
	DescribeTable("ChaCha test vector",
		func(v protocol.VersionNumber, expectedPayload, expectedPacket []byte) {
			secret := splitHexString("9ac312a7f877468ebe69422748ad00a1 5443f18203a07d6060f688f30f21632b")
			aead := newUpdatableAEAD(&utils.RTTStats{}, nil, nil, v)
			chacha := cipherSuites[2]
			Expect(chacha.ID).To(Equal(tls.TLS_CHACHA20_POLY1305_SHA256))
			aead.SetWriteKey(chacha, secret)
			const pnOffset = 1
			header := splitHexString("4200bff4")
			payloadOffset := len(header)
			plaintext := splitHexString("01")
			payload := aead.Seal(nil, plaintext, 654360564, header)
			Expect(payload).To(Equal(expectedPayload))
			packet := append(header, payload...)
			aead.EncryptHeader(packet[pnOffset+4:pnOffset+4+16], &packet[0], packet[pnOffset:payloadOffset])
			Expect(packet).To(Equal(expectedPacket))
		},
		Entry("QUIC v1",
			protocol.Version1,
			splitHexString("655e5cd55c41f69080575d7999c25a5bfb"),
			splitHexString("4cfe4189655e5cd55c41f69080575d7999c25a5bfb"),
		),
		Entry("QUIC v2",
			protocol.Version2,
			splitHexString("0ae7b6b932bc27d786f4bc2bb20f2162ba"),
			splitHexString("5558b1c60ae7b6b932bc27d786f4bc2bb20f2162ba"),
		),
	)

	for _, ver := range []protocol.VersionNumber{protocol.Version1, protocol.Version2} {
		v := ver

		Context(fmt.Sprintf("using version %s", v), func() {
			for i := range cipherSuites {
				cs := cipherSuites[i]

				Context(fmt.Sprintf("using %s", tls.CipherSuiteName(cs.ID)), func() {
					var (
						client, server *updatableAEAD
						serverTracer   *mocklogging.MockConnectionTracer
						rttStats       *utils.RTTStats
					)

					BeforeEach(func() {
						serverTracer = mocklogging.NewMockConnectionTracer(mockCtrl)
						trafficSecret1 := make([]byte, 16)
						trafficSecret2 := make([]byte, 16)
						rand.Read(trafficSecret1)
						rand.Read(trafficSecret2)

						rttStats = utils.NewRTTStats()
						client = newUpdatableAEAD(rttStats, nil, utils.DefaultLogger, v)
						server = newUpdatableAEAD(rttStats, serverTracer, utils.DefaultLogger, v)
						client.SetReadKey(cs, trafficSecret2)
						client.SetWriteKey(cs, trafficSecret1)
						server.SetReadKey(cs, trafficSecret1)
						server.SetWriteKey(cs, trafficSecret2)
					})

					Context("header protection", func() {
						It("encrypts and decrypts the header", func() {
							var lastFiveBitsDifferent int
							for i := 0; i < 100; i++ {
								sample := make([]byte, 16)
								rand.Read(sample)
								header := []byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}
								client.EncryptHeader(sample, &header[0], header[9:13])
								if header[0]&0x1f != 0xb5&0x1f {
									lastFiveBitsDifferent++
								}
								Expect(header[0] & 0xe0).To(Equal(byte(0xb5 & 0xe0)))
								Expect(header[1:9]).To(Equal([]byte{1, 2, 3, 4, 5, 6, 7, 8}))
								Expect(header[9:13]).ToNot(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
								server.DecryptHeader(sample, &header[0], header[9:13])
								Expect(header).To(Equal([]byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}))
							}
							Expect(lastFiveBitsDifferent).To(BeNumerically(">", 75))
						})
					})

					Context("message encryption", func() {
						var msg, ad []byte

						BeforeEach(func() {
							msg = []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")
							ad = []byte("Donec in velit neque.")
						})

						It("encrypts and decrypts a message", func() {
							encrypted := server.Seal(nil, msg, 0x1337, ad)
							opened, err := client.Open(nil, encrypted, time.Now(), 0x1337, protocol.KeyPhaseZero, ad)
							Expect(err).ToNot(HaveOccurred())
							Expect(opened).To(Equal(msg))
						})

						It("saves the first packet number", func() {
							client.Seal(nil, msg, 0x1337, ad)
							Expect(client.FirstPacketNumber()).To(Equal(protocol.PacketNumber(0x1337)))
							client.Seal(nil, msg, 0x1338, ad)
							Expect(client.FirstPacketNumber()).To(Equal(protocol.PacketNumber(0x1337)))
						})

						It("fails to open a message if the associated data is not the same", func() {
							encrypted := client.Seal(nil, msg, 0x1337, ad)
							_, err := server.Open(nil, encrypted, time.Now(), 0x1337, protocol.KeyPhaseZero, []byte("wrong ad"))
							Expect(err).To(MatchError(ErrDecryptionFailed))
						})

						It("fails to open a message if the packet number is not the same", func() {
							encrypted := server.Seal(nil, msg, 0x1337, ad)
							_, err := client.Open(nil, encrypted, time.Now(), 0x42, protocol.KeyPhaseZero, ad)
							Expect(err).To(MatchError(ErrDecryptionFailed))
						})

						It("decodes the packet number", func() {
							encrypted := server.Seal(nil, msg, 0x1337, ad)
							_, err := client.Open(nil, encrypted, time.Now(), 0x1337, protocol.KeyPhaseZero, ad)
							Expect(err).ToNot(HaveOccurred())
							Expect(client.DecodePacketNumber(0x38, protocol.PacketNumberLen1)).To(BeEquivalentTo(0x1338))
						})

						It("ignores packets it can't decrypt for packet number derivation", func() {
							encrypted := server.Seal(nil, msg, 0x1337, ad)
							_, err := client.Open(nil, encrypted[:len(encrypted)-1], time.Now(), 0x1337, protocol.KeyPhaseZero, ad)
							Expect(err).To(HaveOccurred())
							Expect(client.DecodePacketNumber(0x38, protocol.PacketNumberLen1)).To(BeEquivalentTo(0x38))
						})

						It("returns an AEAD_LIMIT_REACHED error when reaching the AEAD limit", func() {
							client.invalidPacketLimit = 10
							for i := 0; i < 9; i++ {
								_, err := client.Open(nil, []byte("foobar"), time.Now(), protocol.PacketNumber(i), protocol.KeyPhaseZero, []byte("ad"))
								Expect(err).To(MatchError(ErrDecryptionFailed))
							}
							_, err := client.Open(nil, []byte("foobar"), time.Now(), 10, protocol.KeyPhaseZero, []byte("ad"))
							Expect(err).To(HaveOccurred())
							Expect(err).To(BeAssignableToTypeOf(&qerr.TransportError{}))
							Expect(err.(*qerr.TransportError).ErrorCode).To(Equal(qerr.AEADLimitReached))
						})

						Context("key updates", func() {
							Context("receiving key updates", func() {
								It("updates keys", func() {
									now := time.Now()
									Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
									encrypted0 := server.Seal(nil, msg, 0x1337, ad)
									server.rollKeys()
									Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
									encrypted1 := server.Seal(nil, msg, 0x1337, ad)
									Expect(encrypted0).ToNot(Equal(encrypted1))
									// expect opening to fail. The client didn't roll keys yet
									_, err := client.Open(nil, encrypted1, now, 0x1337, protocol.KeyPhaseZero, ad)
									Expect(err).To(MatchError(ErrDecryptionFailed))
									client.rollKeys()
									decrypted, err := client.Open(nil, encrypted1, now, 0x1337, protocol.KeyPhaseOne, ad)
									Expect(err).ToNot(HaveOccurred())
									Expect(decrypted).To(Equal(msg))
								})

								It("updates the keys when receiving a packet with the next key phase", func() {
									now := time.Now()
									// receive the first packet at key phase zero
									encrypted0 := client.Seal(nil, msg, 0x42, ad)
									decrypted, err := server.Open(nil, encrypted0, now, 0x42, protocol.KeyPhaseZero, ad)
									Expect(err).ToNot(HaveOccurred())
									Expect(decrypted).To(Equal(msg))
									// send one packet at key phase zero
									Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
									_ = server.Seal(nil, msg, 0x1, ad)
									// now received a message at key phase one
									client.rollKeys()
									encrypted1 := client.Seal(nil, msg, 0x43, ad)
									serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), true)
									decrypted, err = server.Open(nil, encrypted1, now, 0x43, protocol.KeyPhaseOne, ad)
									Expect(err).ToNot(HaveOccurred())
									Expect(decrypted).To(Equal(msg))
									Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
								})

								It("opens a reordered packet with the old keys after an update", func() {
									now := time.Now()
									encrypted01 := client.Seal(nil, msg, 0x42, ad)
									encrypted02 := client.Seal(nil, msg, 0x43, ad)
									// receive the first packet with key phase 0
									_, err := server.Open(nil, encrypted01, now, 0x42, protocol.KeyPhaseZero, ad)
									Expect(err).ToNot(HaveOccurred())
									// send one packet at key phase zero
									_ = server.Seal(nil, msg, 0x1, ad)
									// now receive a packet with key phase 1
									client.rollKeys()
									encrypted1 := client.Seal(nil, msg, 0x44, ad)
									Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
									serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), true)
									_, err = server.Open(nil, encrypted1, now, 0x44, protocol.KeyPhaseOne, ad)
									Expect(err).ToNot(HaveOccurred())
									Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
									// now receive a reordered packet with key phase 0
									decrypted, err := server.Open(nil, encrypted02, now, 0x43, protocol.KeyPhaseZero, ad)
									Expect(err).ToNot(HaveOccurred())
									Expect(decrypted).To(Equal(msg))
									Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
								})

								It("drops keys 3 PTOs after a key update", func() {
									now := time.Now()
									rttStats.UpdateRTT(10*time.Millisecond, 0, now)
									pto := rttStats.PTO(true)
									encrypted01 := client.Seal(nil, msg, 0x42, ad)
									encrypted02 := client.Seal(nil, msg, 0x43, ad)
									// receive the first packet with key phase 0
									_, err := server.Open(nil, encrypted01, now, 0x42, protocol.KeyPhaseZero, ad)
									Expect(err).ToNot(HaveOccurred())
									// send one packet at key phase zero
									_ = server.Seal(nil, msg, 0x1, ad)
									// now receive a packet with key phase 1
									client.rollKeys()
									encrypted1 := client.Seal(nil, msg, 0x44, ad)
									Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
									serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), true)
									serverTracer.EXPECT().DroppedKey(protocol.KeyPhase(0))
									_, err = server.Open(nil, encrypted1, now, 0x44, protocol.KeyPhaseOne, ad)
									Expect(err).ToNot(HaveOccurred())
									Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
									// now receive a reordered packet with key phase 0
									_, err = server.Open(nil, encrypted02, now.Add(3*pto).Add(time.Nanosecond), 0x43, protocol.KeyPhaseZero, ad)
									Expect(err).To(MatchError(ErrKeysDropped))
								})

								It("allows the first key update immediately", func() {
									// receive a packet at key phase one, before having sent or received any packets at key phase 0
									client.rollKeys()
									encrypted1 := client.Seal(nil, msg, 0x1337, ad)
									serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), true)
									_, err := server.Open(nil, encrypted1, time.Now(), 0x1337, protocol.KeyPhaseOne, ad)
									Expect(err).ToNot(HaveOccurred())
								})

								It("only errors when the peer starts with key phase 1 if decrypting the packet succeeds", func() {
									client.rollKeys()
									encrypted := client.Seal(nil, msg, 0x1337, ad)
									encrypted = encrypted[:len(encrypted)-1]
									_, err := server.Open(nil, encrypted, time.Now(), 0x1337, protocol.KeyPhaseOne, ad)
									Expect(err).To(MatchError(ErrDecryptionFailed))
								})

								It("errors when the peer updates keys too frequently", func() {
									server.rollKeys()
									client.rollKeys()
									// receive the first packet at key phase one
									encrypted0 := client.Seal(nil, msg, 0x42, ad)
									_, err := server.Open(nil, encrypted0, time.Now(), 0x42, protocol.KeyPhaseOne, ad)
									Expect(err).ToNot(HaveOccurred())
									// now receive a packet at key phase two, before having sent any packets
									client.rollKeys()
									encrypted1 := client.Seal(nil, msg, 0x42, ad)
									_, err = server.Open(nil, encrypted1, time.Now(), 0x42, protocol.KeyPhaseZero, ad)
									Expect(err).To(MatchError(&qerr.TransportError{
										ErrorCode:    qerr.KeyUpdateError,
										ErrorMessage: "keys updated too quickly",
									}))
								})
							})

							Context("initiating key updates", func() {
								const firstKeyUpdateInterval = 5
								const keyUpdateInterval = 20
								var origKeyUpdateInterval, origFirstKeyUpdateInterval uint64

								BeforeEach(func() {
									origKeyUpdateInterval = KeyUpdateInterval
									origFirstKeyUpdateInterval = FirstKeyUpdateInterval
									KeyUpdateInterval = keyUpdateInterval
									FirstKeyUpdateInterval = firstKeyUpdateInterval
									server.SetHandshakeConfirmed()
								})

								AfterEach(func() {
									KeyUpdateInterval = origKeyUpdateInterval
									FirstKeyUpdateInterval = origFirstKeyUpdateInterval
								})

								It("initiates a key update after sealing the maximum number of packets, for the first update", func() {
									for i := 0; i < firstKeyUpdateInterval; i++ {
										pn := protocol.PacketNumber(i)
										Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
										server.Seal(nil, msg, pn, ad)
									}
									// the first update is allowed without receiving an acknowledgement
									serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), false)
									Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
								})

								It("initiates a key update after sealing the maximum number of packets, for subsequent updates", func() {
									server.rollKeys()
									client.rollKeys()
									for i := 0; i < keyUpdateInterval; i++ {
										pn := protocol.PacketNumber(i)
										Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
										server.Seal(nil, msg, pn, ad)
									}
									// no update allowed before receiving an acknowledgement for the current key phase
									Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
									// receive an ACK for a packet sent in key phase 0
									b := client.Seal(nil, []byte("foobar"), 1, []byte("ad"))
									_, err := server.Open(nil, b, time.Now(), 1, protocol.KeyPhaseOne, []byte("ad"))
									Expect(err).ToNot(HaveOccurred())
									ExpectWithOffset(1, server.SetLargestAcked(0)).To(Succeed())
									serverTracer.EXPECT().DroppedKey(protocol.KeyPhase(0))
									serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(2), false)
									Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
								})

								It("errors if the peer acknowledges a packet sent in the next key phase using the old key phase", func() {
									// First make sure that we update our keys.
									for i := 0; i < firstKeyUpdateInterval; i++ {
										pn := protocol.PacketNumber(i)
										Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
										server.Seal(nil, msg, pn, ad)
									}
									serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), false)
									Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
									// Now that our keys are updated, send a packet using the new keys.
									const nextPN = firstKeyUpdateInterval + 1
									server.Seal(nil, msg, nextPN, ad)
									// We haven't decrypted any packet in the new key phase yet.
									// This means that the ACK must have been sent in the old key phase.
									Expect(server.SetLargestAcked(nextPN)).To(MatchError(&qerr.TransportError{
										ErrorCode:    qerr.KeyUpdateError,
										ErrorMessage: "received ACK for key phase 1, but peer didn't update keys",
									}))
								})

								It("doesn't error before actually sending a packet in the new key phase", func() {
									// First make sure that we update our keys.
									for i := 0; i < firstKeyUpdateInterval; i++ {
										pn := protocol.PacketNumber(i)
										Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
										server.Seal(nil, msg, pn, ad)
									}
									b := client.Seal(nil, []byte("foobar"), 1, []byte("ad"))
									_, err := server.Open(nil, b, time.Now(), 1, protocol.KeyPhaseZero, []byte("ad"))
									Expect(err).ToNot(HaveOccurred())
									ExpectWithOffset(1, server.SetLargestAcked(0)).To(Succeed())
									serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), false)
									// Now that our keys are updated, send a packet using the new keys.
									Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
									// We haven't decrypted any packet in the new key phase yet.
									// This means that the ACK must have been sent in the old key phase.
									Expect(server.SetLargestAcked(1)).ToNot(HaveOccurred())
								})

								It("initiates a key update after opening the maximum number of packets, for the first update", func() {
									for i := 0; i < firstKeyUpdateInterval; i++ {
										pn := protocol.PacketNumber(i)
										Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
										encrypted := client.Seal(nil, msg, pn, ad)
										_, err := server.Open(nil, encrypted, time.Now(), pn, protocol.KeyPhaseZero, ad)
										Expect(err).ToNot(HaveOccurred())
									}
									// the first update is allowed without receiving an acknowledgement
									serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), false)
									Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
								})

								It("initiates a key update after opening the maximum number of packets, for subsequent updates", func() {
									server.rollKeys()
									client.rollKeys()
									for i := 0; i < keyUpdateInterval; i++ {
										pn := protocol.PacketNumber(i)
										Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
										encrypted := client.Seal(nil, msg, pn, ad)
										_, err := server.Open(nil, encrypted, time.Now(), pn, protocol.KeyPhaseOne, ad)
										Expect(err).ToNot(HaveOccurred())
									}
									// no update allowed before receiving an acknowledgement for the current key phase
									Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
									server.Seal(nil, msg, 1, ad)
									Expect(server.SetLargestAcked(1)).To(Succeed())
									serverTracer.EXPECT().DroppedKey(protocol.KeyPhase(0))
									serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(2), false)
									Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
								})

								It("drops keys 3 PTOs after a key update", func() {
									now := time.Now()
									for i := 0; i < firstKeyUpdateInterval; i++ {
										pn := protocol.PacketNumber(i)
										Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
										server.Seal(nil, msg, pn, ad)
									}
									b := client.Seal(nil, []byte("foobar"), 1, []byte("ad"))
									_, err := server.Open(nil, b, now, 1, protocol.KeyPhaseZero, []byte("ad"))
									Expect(err).ToNot(HaveOccurred())
									Expect(server.SetLargestAcked(0)).To(Succeed())
									// Now we've initiated the first key update.
									// Decrypt a message sent from the client more than 3 PTO later to make sure the key is still there
									threePTO := 3 * rttStats.PTO(false)
									dataKeyPhaseZero := client.Seal(nil, msg, 1, ad)
									_, err = server.Open(nil, dataKeyPhaseZero, now.Add(threePTO).Add(time.Second), 1, protocol.KeyPhaseZero, ad)
									Expect(err).ToNot(HaveOccurred())
									// Now receive a packet with key phase 1.
									// This should start the timer to drop the keys after 3 PTOs.
									client.rollKeys()
									dataKeyPhaseOne := client.Seal(nil, msg, 10, ad)
									t := now.Add(threePTO).Add(time.Second)
									serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), true)
									_, err = server.Open(nil, dataKeyPhaseOne, t, 10, protocol.KeyPhaseOne, ad)
									Expect(err).ToNot(HaveOccurred())
									// Make sure the keys are still here.
									_, err = server.Open(nil, dataKeyPhaseZero, t.Add(threePTO*9/10), 1, protocol.KeyPhaseZero, ad)
									Expect(err).ToNot(HaveOccurred())
									serverTracer.EXPECT().DroppedKey(protocol.KeyPhase(0))
									_, err = server.Open(nil, dataKeyPhaseZero, t.Add(threePTO).Add(time.Nanosecond), 1, protocol.KeyPhaseZero, ad)
									Expect(err).To(MatchError(ErrKeysDropped))
								})

								It("doesn't drop the first key generation too early", func() {
									now := time.Now()
									data1 := client.Seal(nil, msg, 1, ad)
									_, err := server.Open(nil, data1, now, 1, protocol.KeyPhaseZero, ad)
									Expect(err).ToNot(HaveOccurred())
									for i := 0; i < firstKeyUpdateInterval; i++ {
										pn := protocol.PacketNumber(i)
										Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
										server.Seal(nil, msg, pn, ad)
										Expect(server.SetLargestAcked(pn)).To(Succeed())
									}
									serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), false)
									Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
									// The server never received a packet at key phase 1.
									// Make sure the key phase 0 is still there at a much later point.
									data2 := client.Seal(nil, msg, 1, ad)
									_, err = server.Open(nil, data2, now.Add(10*rttStats.PTO(true)), 1, protocol.KeyPhaseZero, ad)
									Expect(err).ToNot(HaveOccurred())
								})

								It("drops keys early when the peer forces initiates a key update within the 3 PTO period", func() {
									for i := 0; i < firstKeyUpdateInterval; i++ {
										pn := protocol.PacketNumber(i)
										Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
										server.Seal(nil, msg, pn, ad)
									}
									b := client.Seal(nil, []byte("foobar"), 1, []byte("ad"))
									_, err := server.Open(nil, b, time.Now(), 1, protocol.KeyPhaseZero, []byte("ad"))
									Expect(err).ToNot(HaveOccurred())
									ExpectWithOffset(1, server.SetLargestAcked(0)).To(Succeed())
									serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), false)
									Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
									const nextPN = keyUpdateInterval + 1
									// Send and receive an acknowledgement for a packet in key phase 1.
									// We are now running a timer to drop the keys with 3 PTO.
									server.Seal(nil, msg, nextPN, ad)
									client.rollKeys()
									dataKeyPhaseOne := client.Seal(nil, msg, 2, ad)
									now := time.Now()
									_, err = server.Open(nil, dataKeyPhaseOne, now, 2, protocol.KeyPhaseOne, ad)
									Expect(err).ToNot(HaveOccurred())
									Expect(server.SetLargestAcked(nextPN))
									// Now the client sends us a packet in key phase 2, forcing us to update keys before the 3 PTO period is over.
									// This mean that we need to drop the keys for key phase 0 immediately.
									client.rollKeys()
									dataKeyPhaseTwo := client.Seal(nil, msg, 3, ad)
									gomock.InOrder(
										serverTracer.EXPECT().DroppedKey(protocol.KeyPhase(0)),
										serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(2), true),
									)
									_, err = server.Open(nil, dataKeyPhaseTwo, now, 3, protocol.KeyPhaseZero, ad)
									Expect(err).ToNot(HaveOccurred())
									Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
								})

								It("drops keys early when we initiate another key update within the 3 PTO period", func() {
									server.SetHandshakeConfirmed()
									// send so many packets that we initiate the first key update
									for i := 0; i < firstKeyUpdateInterval; i++ {
										pn := protocol.PacketNumber(i)
										Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
										server.Seal(nil, msg, pn, ad)
									}
									b := client.Seal(nil, []byte("foobar"), 1, []byte("ad"))
									_, err := server.Open(nil, b, time.Now(), 1, protocol.KeyPhaseZero, []byte("ad"))
									Expect(err).ToNot(HaveOccurred())
									ExpectWithOffset(1, server.SetLargestAcked(0)).To(Succeed())
									serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), false)
									Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
									// send so many packets that we initiate the next key update
									for i := keyUpdateInterval; i < 2*keyUpdateInterval; i++ {
										pn := protocol.PacketNumber(i)
										Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
										server.Seal(nil, msg, pn, ad)
									}
									client.rollKeys()
									b = client.Seal(nil, []byte("foobar"), 2, []byte("ad"))
									now := time.Now()
									_, err = server.Open(nil, b, now, 2, protocol.KeyPhaseOne, []byte("ad"))
									Expect(err).ToNot(HaveOccurred())
									ExpectWithOffset(1, server.SetLargestAcked(keyUpdateInterval)).To(Succeed())
									gomock.InOrder(
										serverTracer.EXPECT().DroppedKey(protocol.KeyPhase(0)),
										serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(2), false),
									)
									Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
									// We haven't received an ACK for a packet sent in key phase 2 yet.
									// Make sure we canceled the timer to drop the previous key phase.
									b = client.Seal(nil, []byte("foobar"), 3, []byte("ad"))
									_, err = server.Open(nil, b, now.Add(10*rttStats.PTO(true)), 3, protocol.KeyPhaseOne, []byte("ad"))
									Expect(err).ToNot(HaveOccurred())
								})
							})
						})
					})
				})
			}
		})
	}
})

func getClientAndServer() (client, server *updatableAEAD) {
	trafficSecret1 := make([]byte, 16)
	trafficSecret2 := make([]byte, 16)
	rand.Read(trafficSecret1)
	rand.Read(trafficSecret2)

	cs := cipherSuites[0]
	rttStats := utils.NewRTTStats()
	client = newUpdatableAEAD(rttStats, nil, utils.DefaultLogger, protocol.Version1)
	server = newUpdatableAEAD(rttStats, nil, utils.DefaultLogger, protocol.Version1)
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
