package handshake

import (
	"bytes"
	"crypto/tls"
	"encoding/asn1"
	"time"
	"unsafe"

	"github.com/marten-seemann/qtls"

	"github.com/lucas-clemente/quic-go/internal/congestion"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

const clientSessionStateRevision = 0

type nonceField struct {
	Nonce   []byte
	AppData []byte
	RTT     int64 // in ns
}

type clientSessionCache struct {
	tls.ClientSessionCache
	rttStats *congestion.RTTStats

	getAppData func() []byte
	setAppData func([]byte)
}

func newClientSessionCache(
	cache tls.ClientSessionCache,
	rttStats *congestion.RTTStats,
	get func() []byte,
	set func([]byte),
) *clientSessionCache {
	return &clientSessionCache{
		ClientSessionCache: cache,
		rttStats:           rttStats,
		getAppData:         get,
		setAppData:         set,
	}
}

var _ qtls.ClientSessionCache = &clientSessionCache{}

func (c *clientSessionCache) Get(sessionKey string) (*qtls.ClientSessionState, bool) {
	sess, ok := c.ClientSessionCache.Get(sessionKey)
	if sess == nil {
		return nil, ok
	}
	// qtls.ClientSessionState is identical to the tls.ClientSessionState.
	// In order to allow users of quic-go to use a tls.Config,
	// we need this workaround to use the ClientSessionCache.
	// In unsafe.go we check that the two structs are actually identical.
	tlsSessBytes := (*[unsafe.Sizeof(*sess)]byte)(unsafe.Pointer(sess))[:]
	var session clientSessionState
	sessBytes := (*[unsafe.Sizeof(session)]byte)(unsafe.Pointer(&session))[:]
	copy(sessBytes, tlsSessBytes)
	r := bytes.NewReader(session.nonce)
	rev, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, false
	}
	if rev != clientSessionStateRevision {
		return nil, false
	}
	var nf nonceField
	if rest, err := asn1.Unmarshal(session.nonce[len(session.nonce)-r.Len():], &nf); err != nil || len(rest) != 0 {
		return nil, false
	}
	c.setAppData(nf.AppData)
	session.nonce = nf.Nonce
	c.rttStats.SetInitialRTT(time.Duration(nf.RTT) * time.Nanosecond)
	var qtlsSession qtls.ClientSessionState
	qtlsSessBytes := (*[unsafe.Sizeof(qtlsSession)]byte)(unsafe.Pointer(&qtlsSession))[:]
	copy(qtlsSessBytes, sessBytes)
	return &qtlsSession, ok
}

func (c *clientSessionCache) Put(sessionKey string, cs *qtls.ClientSessionState) {
	if cs == nil {
		c.ClientSessionCache.Put(sessionKey, nil)
		return
	}
	// qtls.ClientSessionState is identical to the tls.ClientSessionState.
	// In order to allow users of quic-go to use a tls.Config,
	// we need this workaround to use the ClientSessionCache.
	// In unsafe.go we check that the two structs are actually identical.
	qtlsSessBytes := (*[unsafe.Sizeof(*cs)]byte)(unsafe.Pointer(cs))[:]
	var session clientSessionState
	sessBytes := (*[unsafe.Sizeof(session)]byte)(unsafe.Pointer(&session))[:]
	copy(sessBytes, qtlsSessBytes)
	data, err := asn1.Marshal(nonceField{
		Nonce:   session.nonce,
		AppData: c.getAppData(),
		RTT:     c.rttStats.SmoothedRTT().Nanoseconds(),
	})
	b := bytes.NewBuffer(make([]byte, 0, int(utils.VarIntLen(clientSessionStateRevision))+len(data)))
	utils.WriteVarInt(b, clientSessionStateRevision)
	b.Write(data)
	if err != nil { // marshaling
		panic(err)
	}
	session.nonce = b.Bytes()
	var tlsSession tls.ClientSessionState
	tlsSessBytes := (*[unsafe.Sizeof(tlsSession)]byte)(unsafe.Pointer(&tlsSession))[:]
	copy(tlsSessBytes, sessBytes)
	c.ClientSessionCache.Put(sessionKey, &tlsSession)
}
