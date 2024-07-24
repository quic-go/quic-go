// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/quic-go/quic-go (interfaces: StreamSender)
//
// Generated by this command:
//
//	mockgen -typed -build_flags=-tags=gomock -package quic -self_package github.com/quic-go/quic-go -destination mock_stream_sender_test.go github.com/quic-go/quic-go StreamSender
//

// Package quic is a generated GoMock package.
package quic

import (
	reflect "reflect"

	protocol "github.com/quic-go/quic-go/internal/protocol"
	wire "github.com/quic-go/quic-go/internal/wire"
	gomock "go.uber.org/mock/gomock"
)

// MockStreamSender is a mock of StreamSender interface.
type MockStreamSender struct {
	ctrl     *gomock.Controller
	recorder *MockStreamSenderMockRecorder
}

// MockStreamSenderMockRecorder is the mock recorder for MockStreamSender.
type MockStreamSenderMockRecorder struct {
	mock *MockStreamSender
}

// NewMockStreamSender creates a new mock instance.
func NewMockStreamSender(ctrl *gomock.Controller) *MockStreamSender {
	mock := &MockStreamSender{ctrl: ctrl}
	mock.recorder = &MockStreamSenderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockStreamSender) EXPECT() *MockStreamSenderMockRecorder {
	return m.recorder
}

// onHasStreamData mocks base method.
func (m *MockStreamSender) onHasStreamData(arg0 protocol.StreamID, arg1 sendStreamI) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "onHasStreamData", arg0, arg1)
}

// onHasStreamData indicates an expected call of onHasStreamData.
func (mr *MockStreamSenderMockRecorder) onHasStreamData(arg0, arg1 any) *MockStreamSenderonHasStreamDataCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "onHasStreamData", reflect.TypeOf((*MockStreamSender)(nil).onHasStreamData), arg0, arg1)
	return &MockStreamSenderonHasStreamDataCall{Call: call}
}

// MockStreamSenderonHasStreamDataCall wrap *gomock.Call
type MockStreamSenderonHasStreamDataCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockStreamSenderonHasStreamDataCall) Return() *MockStreamSenderonHasStreamDataCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockStreamSenderonHasStreamDataCall) Do(f func(protocol.StreamID, sendStreamI)) *MockStreamSenderonHasStreamDataCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockStreamSenderonHasStreamDataCall) DoAndReturn(f func(protocol.StreamID, sendStreamI)) *MockStreamSenderonHasStreamDataCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// onHasStreamWindowUpdate mocks base method.
func (m *MockStreamSender) onHasStreamWindowUpdate(arg0 protocol.StreamID, arg1 receiveStreamI) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "onHasStreamWindowUpdate", arg0, arg1)
}

// onHasStreamWindowUpdate indicates an expected call of onHasStreamWindowUpdate.
func (mr *MockStreamSenderMockRecorder) onHasStreamWindowUpdate(arg0, arg1 any) *MockStreamSenderonHasStreamWindowUpdateCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "onHasStreamWindowUpdate", reflect.TypeOf((*MockStreamSender)(nil).onHasStreamWindowUpdate), arg0, arg1)
	return &MockStreamSenderonHasStreamWindowUpdateCall{Call: call}
}

// MockStreamSenderonHasStreamWindowUpdateCall wrap *gomock.Call
type MockStreamSenderonHasStreamWindowUpdateCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockStreamSenderonHasStreamWindowUpdateCall) Return() *MockStreamSenderonHasStreamWindowUpdateCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockStreamSenderonHasStreamWindowUpdateCall) Do(f func(protocol.StreamID, receiveStreamI)) *MockStreamSenderonHasStreamWindowUpdateCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockStreamSenderonHasStreamWindowUpdateCall) DoAndReturn(f func(protocol.StreamID, receiveStreamI)) *MockStreamSenderonHasStreamWindowUpdateCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// onStreamCompleted mocks base method.
func (m *MockStreamSender) onStreamCompleted(arg0 protocol.StreamID) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "onStreamCompleted", arg0)
}

// onStreamCompleted indicates an expected call of onStreamCompleted.
func (mr *MockStreamSenderMockRecorder) onStreamCompleted(arg0 any) *MockStreamSenderonStreamCompletedCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "onStreamCompleted", reflect.TypeOf((*MockStreamSender)(nil).onStreamCompleted), arg0)
	return &MockStreamSenderonStreamCompletedCall{Call: call}
}

// MockStreamSenderonStreamCompletedCall wrap *gomock.Call
type MockStreamSenderonStreamCompletedCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockStreamSenderonStreamCompletedCall) Return() *MockStreamSenderonStreamCompletedCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockStreamSenderonStreamCompletedCall) Do(f func(protocol.StreamID)) *MockStreamSenderonStreamCompletedCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockStreamSenderonStreamCompletedCall) DoAndReturn(f func(protocol.StreamID)) *MockStreamSenderonStreamCompletedCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// queueControlFrame mocks base method.
func (m *MockStreamSender) queueControlFrame(arg0 wire.Frame) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "queueControlFrame", arg0)
}

// queueControlFrame indicates an expected call of queueControlFrame.
func (mr *MockStreamSenderMockRecorder) queueControlFrame(arg0 any) *MockStreamSenderqueueControlFrameCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "queueControlFrame", reflect.TypeOf((*MockStreamSender)(nil).queueControlFrame), arg0)
	return &MockStreamSenderqueueControlFrameCall{Call: call}
}

// MockStreamSenderqueueControlFrameCall wrap *gomock.Call
type MockStreamSenderqueueControlFrameCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockStreamSenderqueueControlFrameCall) Return() *MockStreamSenderqueueControlFrameCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockStreamSenderqueueControlFrameCall) Do(f func(wire.Frame)) *MockStreamSenderqueueControlFrameCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockStreamSenderqueueControlFrameCall) DoAndReturn(f func(wire.Frame)) *MockStreamSenderqueueControlFrameCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
