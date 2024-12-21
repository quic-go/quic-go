// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/quic-go/quic-go/internal/ackhandler (interfaces: SentPacketHandler)
//
// Generated by this command:
//
//	mockgen -typed -build_flags=-tags=gomock -package mockackhandler -destination ackhandler/sent_packet_handler.go github.com/quic-go/quic-go/internal/ackhandler SentPacketHandler
//

// Package mockackhandler is a generated GoMock package.
package mockackhandler

import (
	reflect "reflect"
	time "time"

	ackhandler "github.com/quic-go/quic-go/internal/ackhandler"
	protocol "github.com/quic-go/quic-go/internal/protocol"
	wire "github.com/quic-go/quic-go/internal/wire"
	gomock "go.uber.org/mock/gomock"
)

// MockSentPacketHandler is a mock of SentPacketHandler interface.
type MockSentPacketHandler struct {
	ctrl     *gomock.Controller
	recorder *MockSentPacketHandlerMockRecorder
	isgomock struct{}
}

// MockSentPacketHandlerMockRecorder is the mock recorder for MockSentPacketHandler.
type MockSentPacketHandlerMockRecorder struct {
	mock *MockSentPacketHandler
}

// NewMockSentPacketHandler creates a new mock instance.
func NewMockSentPacketHandler(ctrl *gomock.Controller) *MockSentPacketHandler {
	mock := &MockSentPacketHandler{ctrl: ctrl}
	mock.recorder = &MockSentPacketHandlerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSentPacketHandler) EXPECT() *MockSentPacketHandlerMockRecorder {
	return m.recorder
}

// DropPackets mocks base method.
func (m *MockSentPacketHandler) DropPackets(arg0 protocol.EncryptionLevel) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "DropPackets", arg0)
}

// DropPackets indicates an expected call of DropPackets.
func (mr *MockSentPacketHandlerMockRecorder) DropPackets(arg0 any) *MockSentPacketHandlerDropPacketsCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DropPackets", reflect.TypeOf((*MockSentPacketHandler)(nil).DropPackets), arg0)
	return &MockSentPacketHandlerDropPacketsCall{Call: call}
}

// MockSentPacketHandlerDropPacketsCall wrap *gomock.Call
type MockSentPacketHandlerDropPacketsCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockSentPacketHandlerDropPacketsCall) Return() *MockSentPacketHandlerDropPacketsCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockSentPacketHandlerDropPacketsCall) Do(f func(protocol.EncryptionLevel)) *MockSentPacketHandlerDropPacketsCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockSentPacketHandlerDropPacketsCall) DoAndReturn(f func(protocol.EncryptionLevel)) *MockSentPacketHandlerDropPacketsCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// ECNMode mocks base method.
func (m *MockSentPacketHandler) ECNMode(isShortHeaderPacket bool) protocol.ECN {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ECNMode", isShortHeaderPacket)
	ret0, _ := ret[0].(protocol.ECN)
	return ret0
}

// ECNMode indicates an expected call of ECNMode.
func (mr *MockSentPacketHandlerMockRecorder) ECNMode(isShortHeaderPacket any) *MockSentPacketHandlerECNModeCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ECNMode", reflect.TypeOf((*MockSentPacketHandler)(nil).ECNMode), isShortHeaderPacket)
	return &MockSentPacketHandlerECNModeCall{Call: call}
}

// MockSentPacketHandlerECNModeCall wrap *gomock.Call
type MockSentPacketHandlerECNModeCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockSentPacketHandlerECNModeCall) Return(arg0 protocol.ECN) *MockSentPacketHandlerECNModeCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockSentPacketHandlerECNModeCall) Do(f func(bool) protocol.ECN) *MockSentPacketHandlerECNModeCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockSentPacketHandlerECNModeCall) DoAndReturn(f func(bool) protocol.ECN) *MockSentPacketHandlerECNModeCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// GetLossDetectionTimeout mocks base method.
func (m *MockSentPacketHandler) GetLossDetectionTimeout() time.Time {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLossDetectionTimeout")
	ret0, _ := ret[0].(time.Time)
	return ret0
}

// GetLossDetectionTimeout indicates an expected call of GetLossDetectionTimeout.
func (mr *MockSentPacketHandlerMockRecorder) GetLossDetectionTimeout() *MockSentPacketHandlerGetLossDetectionTimeoutCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLossDetectionTimeout", reflect.TypeOf((*MockSentPacketHandler)(nil).GetLossDetectionTimeout))
	return &MockSentPacketHandlerGetLossDetectionTimeoutCall{Call: call}
}

// MockSentPacketHandlerGetLossDetectionTimeoutCall wrap *gomock.Call
type MockSentPacketHandlerGetLossDetectionTimeoutCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockSentPacketHandlerGetLossDetectionTimeoutCall) Return(arg0 time.Time) *MockSentPacketHandlerGetLossDetectionTimeoutCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockSentPacketHandlerGetLossDetectionTimeoutCall) Do(f func() time.Time) *MockSentPacketHandlerGetLossDetectionTimeoutCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockSentPacketHandlerGetLossDetectionTimeoutCall) DoAndReturn(f func() time.Time) *MockSentPacketHandlerGetLossDetectionTimeoutCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// OnLossDetectionTimeout mocks base method.
func (m *MockSentPacketHandler) OnLossDetectionTimeout() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OnLossDetectionTimeout")
	ret0, _ := ret[0].(error)
	return ret0
}

// OnLossDetectionTimeout indicates an expected call of OnLossDetectionTimeout.
func (mr *MockSentPacketHandlerMockRecorder) OnLossDetectionTimeout() *MockSentPacketHandlerOnLossDetectionTimeoutCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OnLossDetectionTimeout", reflect.TypeOf((*MockSentPacketHandler)(nil).OnLossDetectionTimeout))
	return &MockSentPacketHandlerOnLossDetectionTimeoutCall{Call: call}
}

// MockSentPacketHandlerOnLossDetectionTimeoutCall wrap *gomock.Call
type MockSentPacketHandlerOnLossDetectionTimeoutCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockSentPacketHandlerOnLossDetectionTimeoutCall) Return(arg0 error) *MockSentPacketHandlerOnLossDetectionTimeoutCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockSentPacketHandlerOnLossDetectionTimeoutCall) Do(f func() error) *MockSentPacketHandlerOnLossDetectionTimeoutCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockSentPacketHandlerOnLossDetectionTimeoutCall) DoAndReturn(f func() error) *MockSentPacketHandlerOnLossDetectionTimeoutCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// PeekPacketNumber mocks base method.
func (m *MockSentPacketHandler) PeekPacketNumber(arg0 protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PeekPacketNumber", arg0)
	ret0, _ := ret[0].(protocol.PacketNumber)
	ret1, _ := ret[1].(protocol.PacketNumberLen)
	return ret0, ret1
}

// PeekPacketNumber indicates an expected call of PeekPacketNumber.
func (mr *MockSentPacketHandlerMockRecorder) PeekPacketNumber(arg0 any) *MockSentPacketHandlerPeekPacketNumberCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PeekPacketNumber", reflect.TypeOf((*MockSentPacketHandler)(nil).PeekPacketNumber), arg0)
	return &MockSentPacketHandlerPeekPacketNumberCall{Call: call}
}

// MockSentPacketHandlerPeekPacketNumberCall wrap *gomock.Call
type MockSentPacketHandlerPeekPacketNumberCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockSentPacketHandlerPeekPacketNumberCall) Return(arg0 protocol.PacketNumber, arg1 protocol.PacketNumberLen) *MockSentPacketHandlerPeekPacketNumberCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockSentPacketHandlerPeekPacketNumberCall) Do(f func(protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen)) *MockSentPacketHandlerPeekPacketNumberCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockSentPacketHandlerPeekPacketNumberCall) DoAndReturn(f func(protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen)) *MockSentPacketHandlerPeekPacketNumberCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// PopPacketNumber mocks base method.
func (m *MockSentPacketHandler) PopPacketNumber(arg0 protocol.EncryptionLevel) protocol.PacketNumber {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PopPacketNumber", arg0)
	ret0, _ := ret[0].(protocol.PacketNumber)
	return ret0
}

// PopPacketNumber indicates an expected call of PopPacketNumber.
func (mr *MockSentPacketHandlerMockRecorder) PopPacketNumber(arg0 any) *MockSentPacketHandlerPopPacketNumberCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PopPacketNumber", reflect.TypeOf((*MockSentPacketHandler)(nil).PopPacketNumber), arg0)
	return &MockSentPacketHandlerPopPacketNumberCall{Call: call}
}

// MockSentPacketHandlerPopPacketNumberCall wrap *gomock.Call
type MockSentPacketHandlerPopPacketNumberCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockSentPacketHandlerPopPacketNumberCall) Return(arg0 protocol.PacketNumber) *MockSentPacketHandlerPopPacketNumberCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockSentPacketHandlerPopPacketNumberCall) Do(f func(protocol.EncryptionLevel) protocol.PacketNumber) *MockSentPacketHandlerPopPacketNumberCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockSentPacketHandlerPopPacketNumberCall) DoAndReturn(f func(protocol.EncryptionLevel) protocol.PacketNumber) *MockSentPacketHandlerPopPacketNumberCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// QueueProbePacket mocks base method.
func (m *MockSentPacketHandler) QueueProbePacket(arg0 protocol.EncryptionLevel) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "QueueProbePacket", arg0)
	ret0, _ := ret[0].(bool)
	return ret0
}

// QueueProbePacket indicates an expected call of QueueProbePacket.
func (mr *MockSentPacketHandlerMockRecorder) QueueProbePacket(arg0 any) *MockSentPacketHandlerQueueProbePacketCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "QueueProbePacket", reflect.TypeOf((*MockSentPacketHandler)(nil).QueueProbePacket), arg0)
	return &MockSentPacketHandlerQueueProbePacketCall{Call: call}
}

// MockSentPacketHandlerQueueProbePacketCall wrap *gomock.Call
type MockSentPacketHandlerQueueProbePacketCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockSentPacketHandlerQueueProbePacketCall) Return(arg0 bool) *MockSentPacketHandlerQueueProbePacketCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockSentPacketHandlerQueueProbePacketCall) Do(f func(protocol.EncryptionLevel) bool) *MockSentPacketHandlerQueueProbePacketCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockSentPacketHandlerQueueProbePacketCall) DoAndReturn(f func(protocol.EncryptionLevel) bool) *MockSentPacketHandlerQueueProbePacketCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// ReceivedAck mocks base method.
func (m *MockSentPacketHandler) ReceivedAck(f *wire.AckFrame, encLevel protocol.EncryptionLevel, rcvTime time.Time) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReceivedAck", f, encLevel, rcvTime)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ReceivedAck indicates an expected call of ReceivedAck.
func (mr *MockSentPacketHandlerMockRecorder) ReceivedAck(f, encLevel, rcvTime any) *MockSentPacketHandlerReceivedAckCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReceivedAck", reflect.TypeOf((*MockSentPacketHandler)(nil).ReceivedAck), f, encLevel, rcvTime)
	return &MockSentPacketHandlerReceivedAckCall{Call: call}
}

// MockSentPacketHandlerReceivedAckCall wrap *gomock.Call
type MockSentPacketHandlerReceivedAckCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockSentPacketHandlerReceivedAckCall) Return(arg0 bool, arg1 error) *MockSentPacketHandlerReceivedAckCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockSentPacketHandlerReceivedAckCall) Do(f func(*wire.AckFrame, protocol.EncryptionLevel, time.Time) (bool, error)) *MockSentPacketHandlerReceivedAckCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockSentPacketHandlerReceivedAckCall) DoAndReturn(f func(*wire.AckFrame, protocol.EncryptionLevel, time.Time) (bool, error)) *MockSentPacketHandlerReceivedAckCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// ReceivedBytes mocks base method.
func (m *MockSentPacketHandler) ReceivedBytes(arg0 protocol.ByteCount) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReceivedBytes", arg0)
}

// ReceivedBytes indicates an expected call of ReceivedBytes.
func (mr *MockSentPacketHandlerMockRecorder) ReceivedBytes(arg0 any) *MockSentPacketHandlerReceivedBytesCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReceivedBytes", reflect.TypeOf((*MockSentPacketHandler)(nil).ReceivedBytes), arg0)
	return &MockSentPacketHandlerReceivedBytesCall{Call: call}
}

// MockSentPacketHandlerReceivedBytesCall wrap *gomock.Call
type MockSentPacketHandlerReceivedBytesCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockSentPacketHandlerReceivedBytesCall) Return() *MockSentPacketHandlerReceivedBytesCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockSentPacketHandlerReceivedBytesCall) Do(f func(protocol.ByteCount)) *MockSentPacketHandlerReceivedBytesCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockSentPacketHandlerReceivedBytesCall) DoAndReturn(f func(protocol.ByteCount)) *MockSentPacketHandlerReceivedBytesCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// ResetForRetry mocks base method.
func (m *MockSentPacketHandler) ResetForRetry(rcvTime time.Time) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResetForRetry", rcvTime)
	ret0, _ := ret[0].(error)
	return ret0
}

// ResetForRetry indicates an expected call of ResetForRetry.
func (mr *MockSentPacketHandlerMockRecorder) ResetForRetry(rcvTime any) *MockSentPacketHandlerResetForRetryCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResetForRetry", reflect.TypeOf((*MockSentPacketHandler)(nil).ResetForRetry), rcvTime)
	return &MockSentPacketHandlerResetForRetryCall{Call: call}
}

// MockSentPacketHandlerResetForRetryCall wrap *gomock.Call
type MockSentPacketHandlerResetForRetryCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockSentPacketHandlerResetForRetryCall) Return(arg0 error) *MockSentPacketHandlerResetForRetryCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockSentPacketHandlerResetForRetryCall) Do(f func(time.Time) error) *MockSentPacketHandlerResetForRetryCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockSentPacketHandlerResetForRetryCall) DoAndReturn(f func(time.Time) error) *MockSentPacketHandlerResetForRetryCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// SendMode mocks base method.
func (m *MockSentPacketHandler) SendMode(now time.Time) ackhandler.SendMode {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendMode", now)
	ret0, _ := ret[0].(ackhandler.SendMode)
	return ret0
}

// SendMode indicates an expected call of SendMode.
func (mr *MockSentPacketHandlerMockRecorder) SendMode(now any) *MockSentPacketHandlerSendModeCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendMode", reflect.TypeOf((*MockSentPacketHandler)(nil).SendMode), now)
	return &MockSentPacketHandlerSendModeCall{Call: call}
}

// MockSentPacketHandlerSendModeCall wrap *gomock.Call
type MockSentPacketHandlerSendModeCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockSentPacketHandlerSendModeCall) Return(arg0 ackhandler.SendMode) *MockSentPacketHandlerSendModeCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockSentPacketHandlerSendModeCall) Do(f func(time.Time) ackhandler.SendMode) *MockSentPacketHandlerSendModeCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockSentPacketHandlerSendModeCall) DoAndReturn(f func(time.Time) ackhandler.SendMode) *MockSentPacketHandlerSendModeCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// SentPacket mocks base method.
func (m *MockSentPacketHandler) SentPacket(t time.Time, pn, largestAcked protocol.PacketNumber, streamFrames []ackhandler.StreamFrame, frames []ackhandler.Frame, encLevel protocol.EncryptionLevel, ecn protocol.ECN, size protocol.ByteCount, isPathMTUProbePacket bool) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SentPacket", t, pn, largestAcked, streamFrames, frames, encLevel, ecn, size, isPathMTUProbePacket)
}

// SentPacket indicates an expected call of SentPacket.
func (mr *MockSentPacketHandlerMockRecorder) SentPacket(t, pn, largestAcked, streamFrames, frames, encLevel, ecn, size, isPathMTUProbePacket any) *MockSentPacketHandlerSentPacketCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SentPacket", reflect.TypeOf((*MockSentPacketHandler)(nil).SentPacket), t, pn, largestAcked, streamFrames, frames, encLevel, ecn, size, isPathMTUProbePacket)
	return &MockSentPacketHandlerSentPacketCall{Call: call}
}

// MockSentPacketHandlerSentPacketCall wrap *gomock.Call
type MockSentPacketHandlerSentPacketCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockSentPacketHandlerSentPacketCall) Return() *MockSentPacketHandlerSentPacketCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockSentPacketHandlerSentPacketCall) Do(f func(time.Time, protocol.PacketNumber, protocol.PacketNumber, []ackhandler.StreamFrame, []ackhandler.Frame, protocol.EncryptionLevel, protocol.ECN, protocol.ByteCount, bool)) *MockSentPacketHandlerSentPacketCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockSentPacketHandlerSentPacketCall) DoAndReturn(f func(time.Time, protocol.PacketNumber, protocol.PacketNumber, []ackhandler.StreamFrame, []ackhandler.Frame, protocol.EncryptionLevel, protocol.ECN, protocol.ByteCount, bool)) *MockSentPacketHandlerSentPacketCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// SetHandshakeConfirmed mocks base method.
func (m *MockSentPacketHandler) SetHandshakeConfirmed() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetHandshakeConfirmed")
}

// SetHandshakeConfirmed indicates an expected call of SetHandshakeConfirmed.
func (mr *MockSentPacketHandlerMockRecorder) SetHandshakeConfirmed() *MockSentPacketHandlerSetHandshakeConfirmedCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetHandshakeConfirmed", reflect.TypeOf((*MockSentPacketHandler)(nil).SetHandshakeConfirmed))
	return &MockSentPacketHandlerSetHandshakeConfirmedCall{Call: call}
}

// MockSentPacketHandlerSetHandshakeConfirmedCall wrap *gomock.Call
type MockSentPacketHandlerSetHandshakeConfirmedCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockSentPacketHandlerSetHandshakeConfirmedCall) Return() *MockSentPacketHandlerSetHandshakeConfirmedCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockSentPacketHandlerSetHandshakeConfirmedCall) Do(f func()) *MockSentPacketHandlerSetHandshakeConfirmedCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockSentPacketHandlerSetHandshakeConfirmedCall) DoAndReturn(f func()) *MockSentPacketHandlerSetHandshakeConfirmedCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// SetMaxDatagramSize mocks base method.
func (m *MockSentPacketHandler) SetMaxDatagramSize(count protocol.ByteCount) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetMaxDatagramSize", count)
}

// SetMaxDatagramSize indicates an expected call of SetMaxDatagramSize.
func (mr *MockSentPacketHandlerMockRecorder) SetMaxDatagramSize(count any) *MockSentPacketHandlerSetMaxDatagramSizeCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetMaxDatagramSize", reflect.TypeOf((*MockSentPacketHandler)(nil).SetMaxDatagramSize), count)
	return &MockSentPacketHandlerSetMaxDatagramSizeCall{Call: call}
}

// MockSentPacketHandlerSetMaxDatagramSizeCall wrap *gomock.Call
type MockSentPacketHandlerSetMaxDatagramSizeCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockSentPacketHandlerSetMaxDatagramSizeCall) Return() *MockSentPacketHandlerSetMaxDatagramSizeCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockSentPacketHandlerSetMaxDatagramSizeCall) Do(f func(protocol.ByteCount)) *MockSentPacketHandlerSetMaxDatagramSizeCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockSentPacketHandlerSetMaxDatagramSizeCall) DoAndReturn(f func(protocol.ByteCount)) *MockSentPacketHandlerSetMaxDatagramSizeCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// TimeUntilSend mocks base method.
func (m *MockSentPacketHandler) TimeUntilSend() time.Time {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "TimeUntilSend")
	ret0, _ := ret[0].(time.Time)
	return ret0
}

// TimeUntilSend indicates an expected call of TimeUntilSend.
func (mr *MockSentPacketHandlerMockRecorder) TimeUntilSend() *MockSentPacketHandlerTimeUntilSendCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TimeUntilSend", reflect.TypeOf((*MockSentPacketHandler)(nil).TimeUntilSend))
	return &MockSentPacketHandlerTimeUntilSendCall{Call: call}
}

// MockSentPacketHandlerTimeUntilSendCall wrap *gomock.Call
type MockSentPacketHandlerTimeUntilSendCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockSentPacketHandlerTimeUntilSendCall) Return(arg0 time.Time) *MockSentPacketHandlerTimeUntilSendCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockSentPacketHandlerTimeUntilSendCall) Do(f func() time.Time) *MockSentPacketHandlerTimeUntilSendCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockSentPacketHandlerTimeUntilSendCall) DoAndReturn(f func() time.Time) *MockSentPacketHandlerTimeUntilSendCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
