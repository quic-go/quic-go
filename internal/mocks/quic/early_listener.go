// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/lucas-clemente/quic-go (interfaces: EarlyListener)

// Package mockquic is a generated GoMock package.
package mockquic

import (
	context "context"
	net "net"
	reflect "reflect"

	quic_go "github.com/Psiphon-Labs/quic-go"
	gomock "github.com/golang/mock/gomock"
	quic "github.com/lucas-clemente/quic-go"
)

// MockEarlyListener is a mock of EarlyListener interface
type MockEarlyListener struct {
	ctrl     *gomock.Controller
	recorder *MockEarlyListenerMockRecorder
}

// MockEarlyListenerMockRecorder is the mock recorder for MockEarlyListener
type MockEarlyListenerMockRecorder struct {
	mock *MockEarlyListener
}

// NewMockEarlyListener creates a new mock instance
func NewMockEarlyListener(ctrl *gomock.Controller) *MockEarlyListener {
	mock := &MockEarlyListener{ctrl: ctrl}
	mock.recorder = &MockEarlyListenerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockEarlyListener) EXPECT() *MockEarlyListenerMockRecorder {
	return m.recorder
}

// Accept mocks base method
func (m *MockEarlyListener) Accept(arg0 context.Context) (quic.EarlySession, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Accept", arg0)
	ret0, _ := ret[0].(quic.EarlySession)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Accept indicates an expected call of Accept
func (mr *MockEarlyListenerMockRecorder) Accept(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Accept", reflect.TypeOf((*MockEarlyListener)(nil).Accept), arg0)
}

// Addr mocks base method
func (m *MockEarlyListener) Addr() net.Addr {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Addr")
	ret0, _ := ret[0].(net.Addr)
	return ret0
}

// Addr indicates an expected call of Addr
func (mr *MockEarlyListenerMockRecorder) Addr() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Addr", reflect.TypeOf((*MockEarlyListener)(nil).Addr))
}

// Close mocks base method
func (m *MockEarlyListener) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close
func (mr *MockEarlyListenerMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockEarlyListener)(nil).Close))
}
