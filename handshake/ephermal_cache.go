package handshake

import (
	"fmt"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

var (
	kexLifetime = protocol.EphermalKeyLifetime
	kexCurrent  crypto.KeyExchange
	kexSetOnce  sync.Once
	kexMutex    sync.RWMutex
)

// getEphermalKEX returns the currently active KEX, which changes every protocol.EphermalKeyLifetime
// See the explanation from the QUIC crypto doc:
//
// A single connection is the usual scope for forward security, but the security
// difference between an ephemeral key used for a single connection, and one
// used for all connections for 60 seconds is negligible. Thus we can amortise
// the Diffie-Hellman key generation at the server over all the connections in a
// small time span.
func getEphermalKEX() crypto.KeyExchange {
	kexSetOnce.Do(func() { go setKexRoutine() })
	kexMutex.RLock()
	defer kexMutex.RUnlock()
	return kexCurrent
}

func setKexRoutine() {
	for {
		time.Sleep(kexLifetime)
		kex, err := crypto.NewCurve25519KEX()
		if err != nil {
			utils.Errorf("could not set KEX: %s", err.Error())
			continue
		}
		kexMutex.Lock()
		kexCurrent = kex
		kexMutex.Unlock()
	}
}

func init() {
	kex, err := crypto.NewCurve25519KEX()
	if err != nil {
		panic(fmt.Sprintf("Could not set KEX: %s", err.Error()))
	}
	kexCurrent = kex
}
