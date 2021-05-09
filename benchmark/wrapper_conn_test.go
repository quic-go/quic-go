package benchmark

import (
	"net"
	"syscall"
)

type msg struct {
	n    int
	buf  []byte
	addr net.Addr
	err  error
}

type wrapperConn struct {
	net.PacketConn
	msgs   chan msg
	direct bool
}

func (w *wrapperConn) loop() {
	if w.direct {
		return
	}
	buf := make([]byte, 1500)
	for {
		n, addr, err := w.PacketConn.ReadFrom(buf)
		w.msgs <- msg{
			n:    n,
			buf:  buf,
			addr: addr,
			err:  err,
		}
		if err != nil {
			return
		}
	}
}

func (w *wrapperConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if w.direct {
		return w.PacketConn.ReadFrom(b)
	}

	msg := <-w.msgs
	n := msg.n
	if l := len(b); l < n {
		n = l
	}
	copy(b, msg.buf[:n])
	return n, msg.addr, msg.err
}

func (w *wrapperConn) SetReadBuffer(size int) error {
	return w.PacketConn.(*net.UDPConn).SetReadBuffer(size)
}

func (w *wrapperConn) SyscallConn() (syscall.RawConn, error) {
	return w.PacketConn.(*net.UDPConn).SyscallConn()
}
