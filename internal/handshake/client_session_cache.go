package handshake

import (
	"bytes"
	"crypto/tls"
	"io"
	"time"
	"unsafe"

	"github.com/marten-seemann/qtls"

	"github.com/lucas-clemente/quic-go/internal/congestion"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

const clientSessionStateRevision = 2

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
	session := (*clientSessionState)(unsafe.Pointer(sess))
	r := bytes.NewReader(session.nonce)
	rev, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, false
	}
	if rev != clientSessionStateRevision {
		return nil, false
	}
	rtt, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, false
	}
	appDataLen, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, false
	}
	appData := make([]byte, appDataLen)
	if _, err := io.ReadFull(r, appData); err != nil {
		return nil, false
	}
	nonceLen, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, false
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, false
	}
	c.setAppData(appData)
	session.nonce = nonce
	c.rttStats.SetInitialRTT(time.Duration(rtt) * time.Microsecond)
	return (*qtls.ClientSessionState)(unsafe.Pointer(session)), ok
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
	session := (*clientSessionState)(unsafe.Pointer(cs))
	appData := c.getAppData()
	buf := &bytes.Buffer{}
	utils.WriteVarInt(buf, clientSessionStateRevision)
	utils.WriteVarInt(buf, uint64(c.rttStats.SmoothedRTT().Microseconds()))
	utils.WriteVarInt(buf, uint64(len(appData)))
	buf.Write(appData)
	utils.WriteVarInt(buf, uint64(len(session.nonce)))
	buf.Write(session.nonce)
	session.nonce = buf.Bytes()
	c.ClientSessionCache.Put(sessionKey, (*tls.ClientSessionState)(unsafe.Pointer(session)))
}
