package quic

import (
	"context"
	"net"

	"github.com/quic-go/quic-go/internal/protocol"
	tls "github.com/refraction-networking/utls"
)

type UTransport struct {
	*Transport

	QUICSpec *QUICSpec // [UQUIC] using ptr to avoid copying
}

// Dial dials a new connection to a remote host (not using 0-RTT).
func (t *UTransport) Dial(ctx context.Context, addr net.Addr, tlsConf *tls.Config, conf *Config) (Connection, error) {
	if err := validateConfig(conf); err != nil {
		return nil, err
	}
	conf = populateConfig(conf)

	// [UQUIC]
	// Override the default connection ID generator if the user has specified a length in QUICSpec.
	if t.QUICSpec != nil {
		if t.QUICSpec.InitialPacketSpec.SrcConnIDLength != 0 {
			t.ConnectionIDGenerator = &protocol.DefaultConnectionIDGenerator{ConnLen: t.QUICSpec.InitialPacketSpec.SrcConnIDLength}
		} else {
			t.ConnectionIDGenerator = &protocol.ExpEmptyConnectionIDGenerator{}
		}
	}
	// [/UQUIC]

	if err := t.init(t.isSingleUse); err != nil {
		return nil, err
	}
	var onClose func()
	if t.isSingleUse {
		onClose = func() { t.Close() }
	}
	tlsConf = tlsConf.Clone()
	tlsConf.MinVersion = tls.VersionTLS13

	return udial(ctx, newSendConn(t.conn, addr), t.connIDGenerator, t.handlerMap, tlsConf, conf, onClose, false, t.QUICSpec)
}

// DialEarly dials a new connection, attempting to use 0-RTT if possible.
func (t *UTransport) DialEarly(ctx context.Context, addr net.Addr, tlsConf *tls.Config, conf *Config) (EarlyConnection, error) {
	if err := validateConfig(conf); err != nil {
		return nil, err
	}
	conf = populateConfig(conf)

	// [UQUIC]
	// Override the default connection ID generator if the user has specified a length in QUICSpec.
	if t.QUICSpec != nil {
		if t.QUICSpec.InitialPacketSpec.SrcConnIDLength != 0 {
			t.ConnectionIDGenerator = &protocol.DefaultConnectionIDGenerator{ConnLen: t.QUICSpec.InitialPacketSpec.SrcConnIDLength}
		} else {
			t.ConnectionIDGenerator = &protocol.ExpEmptyConnectionIDGenerator{}
		}
	}
	// [/UQUIC]

	if err := t.init(t.isSingleUse); err != nil {
		return nil, err
	}
	var onClose func()
	if t.isSingleUse {
		onClose = func() { t.Close() }
	}
	tlsConf = tlsConf.Clone()
	tlsConf.MinVersion = tls.VersionTLS13

	return udial(ctx, newSendConn(t.conn, addr), t.connIDGenerator, t.handlerMap, tlsConf, conf, onClose, true, t.QUICSpec)
}

func (ut *UTransport) MakeDialer() func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *Config) (EarlyConnection, error) {
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *Config) (EarlyConnection, error) {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}
		return ut.DialEarly(ctx, udpAddr, tlsCfg, cfg)
	}
}
