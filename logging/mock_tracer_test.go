// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/lucas-clemente/quic-go/logging (interfaces: Tracer)

// Package logging is a generated GoMock package.
package logging

import (
	net "net"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	protocol "github.com/lucas-clemente/quic-go/internal/protocol"
	wire "github.com/lucas-clemente/quic-go/internal/wire"
)

// MockTracer is a mock of Tracer interface
type MockTracer struct {
	ctrl     *gomock.Controller
	recorder *MockTracerMockRecorder
}

// MockTracerMockRecorder is the mock recorder for MockTracer
type MockTracerMockRecorder struct {
	mock *MockTracer
}

// NewMockTracer creates a new mock instance
func NewMockTracer(ctrl *gomock.Controller) *MockTracer {
	mock := &MockTracer{ctrl: ctrl}
	mock.recorder = &MockTracerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockTracer) EXPECT() *MockTracerMockRecorder {
	return m.recorder
}

// DroppedPacket mocks base method
func (m *MockTracer) DroppedPacket(arg0 net.Addr, arg1 protocol.PacketType, arg2 protocol.ByteCount, arg3 PacketDropReason) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "DroppedPacket", arg0, arg1, arg2, arg3)
}

// DroppedPacket indicates an expected call of DroppedPacket
func (mr *MockTracerMockRecorder) DroppedPacket(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DroppedPacket", reflect.TypeOf((*MockTracer)(nil).DroppedPacket), arg0, arg1, arg2, arg3)
}

// SentPacket mocks base method
func (m *MockTracer) SentPacket(arg0 net.Addr, arg1 *wire.Header, arg2 protocol.ByteCount, arg3 []Frame) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SentPacket", arg0, arg1, arg2, arg3)
}

// SentPacket indicates an expected call of SentPacket
func (mr *MockTracerMockRecorder) SentPacket(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SentPacket", reflect.TypeOf((*MockTracer)(nil).SentPacket), arg0, arg1, arg2, arg3)
}

// TracerForConnection mocks base method
func (m *MockTracer) TracerForConnection(arg0 protocol.Perspective, arg1 protocol.ConnectionID) ConnectionTracer {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "TracerForConnection", arg0, arg1)
	ret0, _ := ret[0].(ConnectionTracer)
	return ret0
}

// TracerForConnection indicates an expected call of TracerForConnection
func (mr *MockTracerMockRecorder) TracerForConnection(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TracerForConnection", reflect.TypeOf((*MockTracer)(nil).TracerForConnection), arg0, arg1)
}
