package handshake

import (
	"crypto/rand"
	"fmt"
	"os"
	"time"

	"github.com/lucas-clemente/quic-go/internal/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Updatable AEAD", func() {
	for i := range cipherSuites {
		cs := cipherSuites[i]

		Context(fmt.Sprintf("using %s", cipherSuiteName(cs.ID)), func() {

			getPeers := func(rttStats *congestion.RTTStats) (client, server *updatableAEAD) {
				trafficSecret1 := make([]byte, 16)
				trafficSecret2 := make([]byte, 16)
				rand.Read(trafficSecret1)
				rand.Read(trafficSecret2)

				client = newUpdatableAEAD(rttStats, utils.DefaultLogger)
				server = newUpdatableAEAD(rttStats, utils.DefaultLogger)
				client.SetReadKey(cs, trafficSecret2)
				client.SetWriteKey(cs, trafficSecret1)
				server.SetReadKey(cs, trafficSecret1)
				server.SetWriteKey(cs, trafficSecret2)
				return
			}

			Context("header protection", func() {
				It("encrypts and decrypts the header", func() {
					server, client := getPeers(&congestion.RTTStats{})
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
				var server, client *updatableAEAD
				var rttStats *congestion.RTTStats

				BeforeEach(func() {
					rttStats = &congestion.RTTStats{}
					server, client = getPeers(rttStats)
					msg = []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")
					ad = []byte("Donec in velit neque.")
				})

				It("encrypts and decrypts a message", func() {
					encrypted := server.Seal(nil, msg, 0x1337, ad)
					opened, err := client.Open(nil, encrypted, time.Now(), 0x1337, protocol.KeyPhaseZero, ad)
					Expect(err).ToNot(HaveOccurred())
					Expect(opened).To(Equal(msg))
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

				Context("key updates", func() {
					Context("receiving key updates", func() {
						It("updates keys", func() {
							now := time.Now()
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
							encrypted0 := server.Seal(nil, msg, 0x1337, ad)
							server.rollKeys(now)
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
							encrypted1 := server.Seal(nil, msg, 0x1337, ad)
							Expect(encrypted0).ToNot(Equal(encrypted1))
							// expect opening to fail. The client didn't roll keys yet
							_, err := client.Open(nil, encrypted1, now, 0x1337, protocol.KeyPhaseZero, ad)
							Expect(err).To(MatchError(ErrDecryptionFailed))
							client.rollKeys(now)
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
							client.rollKeys(now)
							encrypted1 := client.Seal(nil, msg, 0x43, ad)
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
							client.rollKeys(now)
							encrypted1 := client.Seal(nil, msg, 0x44, ad)
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
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
							client.rollKeys(now)
							encrypted1 := client.Seal(nil, msg, 0x44, ad)
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
							_, err = server.Open(nil, encrypted1, now, 0x44, protocol.KeyPhaseOne, ad)
							Expect(err).ToNot(HaveOccurred())
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
							// now receive a reordered packet with key phase 0
							_, err = server.Open(nil, encrypted02, now.Add(3*pto).Add(time.Nanosecond), 0x43, protocol.KeyPhaseZero, ad)
							Expect(err).To(MatchError(ErrKeysDropped))
						})

						It("errors when the peer starts with key phase 1", func() {
							client.rollKeys(time.Now())
							encrypted := client.Seal(nil, msg, 0x1337, ad)
							_, err := server.Open(nil, encrypted, time.Now(), 0x1337, protocol.KeyPhaseOne, ad)
							Expect(err).To(MatchError("PROTOCOL_VIOLATION: wrong initial keyphase"))
						})

						It("errors when the peer updates keys too frequently", func() {
							// receive the first packet at key phase zero
							encrypted0 := client.Seal(nil, msg, 0x42, ad)
							_, err := server.Open(nil, encrypted0, time.Now(), 0x42, protocol.KeyPhaseZero, ad)
							Expect(err).ToNot(HaveOccurred())
							// now receive a packet at key phase one, before having sent any packets
							client.rollKeys(time.Now())
							encrypted1 := client.Seal(nil, msg, 0x42, ad)
							_, err = server.Open(nil, encrypted1, time.Now(), 0x42, protocol.KeyPhaseOne, ad)
							Expect(err).To(MatchError("PROTOCOL_VIOLATION: keys updated too quickly"))
						})
					})

					Context("initiating key updates", func() {
						const keyUpdateInterval = 20

						BeforeEach(func() {
							Expect(server.keyUpdateInterval).To(BeEquivalentTo(protocol.KeyUpdateInterval))
							server.keyUpdateInterval = keyUpdateInterval
						})

						It("initiates a key update after sealing the maximum number of packets", func() {
							for i := 0; i < keyUpdateInterval; i++ {
								pn := protocol.PacketNumber(i)
								Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
								server.Seal(nil, msg, pn, ad)
							}
							// no update allowed before receiving an acknowledgement for the current key phase
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
							server.SetLargestAcked(0)
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
						})

						It("initiates a key update after opening the maximum number of packets", func() {
							for i := 0; i < keyUpdateInterval; i++ {
								pn := protocol.PacketNumber(i)
								Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
								encrypted := client.Seal(nil, msg, pn, ad)
								_, err := server.Open(nil, encrypted, time.Now(), pn, protocol.KeyPhaseZero, ad)
								Expect(err).ToNot(HaveOccurred())
							}
							// no update allowed before receiving an acknowledgement for the current key phase
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
							server.Seal(nil, msg, 1, ad)
							server.SetLargestAcked(1)
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
						})
					})

					Context("reading the key update env", func() {
						AfterEach(func() {
							os.Setenv(keyUpdateEnv, "")
							setKeyUpdateInterval()
						})

						It("uses the default value if the env is not set", func() {
							setKeyUpdateInterval()
							Expect(keyUpdateInterval).To(BeEquivalentTo(protocol.KeyUpdateInterval))
						})

						It("uses the env", func() {
							os.Setenv(keyUpdateEnv, "1337")
							setKeyUpdateInterval()
							Expect(keyUpdateInterval).To(BeEquivalentTo(1337))
						})

						It("panics when it can't parse the env", func() {
							os.Setenv(keyUpdateEnv, "foobar")
							Expect(setKeyUpdateInterval).To(Panic())
						})
					})
				})
			})
		})
	}
})
