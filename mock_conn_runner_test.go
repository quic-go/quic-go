// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/quic-go/quic-go (interfaces: ConnRunner)
//
// Generated by this command:
//
//	mockgen -typed -build_flags=-tags=gomock -package quic -self_package github.com/quic-go/quic-go -destination mock_conn_runner_test.go github.com/quic-go/quic-go ConnRunner
//

// Package quic is a generated GoMock package.
package quic

import (
	reflect "reflect"

	protocol "github.com/quic-go/quic-go/internal/protocol"
	gomock "go.uber.org/mock/gomock"
)

// MockConnRunner is a mock of ConnRunner interface.
type MockConnRunner struct {
	ctrl     *gomock.Controller
	recorder *MockConnRunnerMockRecorder
	isgomock struct{}
}

// MockConnRunnerMockRecorder is the mock recorder for MockConnRunner.
type MockConnRunnerMockRecorder struct {
	mock *MockConnRunner
}

// NewMockConnRunner creates a new mock instance.
func NewMockConnRunner(ctrl *gomock.Controller) *MockConnRunner {
	mock := &MockConnRunner{ctrl: ctrl}
	mock.recorder = &MockConnRunnerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockConnRunner) EXPECT() *MockConnRunnerMockRecorder {
	return m.recorder
}

// Add mocks base method.
func (m *MockConnRunner) Add(arg0 protocol.ConnectionID, arg1 packetHandler) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Add", arg0, arg1)
	ret0, _ := ret[0].(bool)
	return ret0
}

// Add indicates an expected call of Add.
func (mr *MockConnRunnerMockRecorder) Add(arg0, arg1 any) *MockConnRunnerAddCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Add", reflect.TypeOf((*MockConnRunner)(nil).Add), arg0, arg1)
	return &MockConnRunnerAddCall{Call: call}
}

// MockConnRunnerAddCall wrap *gomock.Call
type MockConnRunnerAddCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockConnRunnerAddCall) Return(arg0 bool) *MockConnRunnerAddCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockConnRunnerAddCall) Do(f func(protocol.ConnectionID, packetHandler) bool) *MockConnRunnerAddCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockConnRunnerAddCall) DoAndReturn(f func(protocol.ConnectionID, packetHandler) bool) *MockConnRunnerAddCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// AddResetToken mocks base method.
func (m *MockConnRunner) AddResetToken(arg0 protocol.StatelessResetToken, arg1 packetHandler) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AddResetToken", arg0, arg1)
}

// AddResetToken indicates an expected call of AddResetToken.
func (mr *MockConnRunnerMockRecorder) AddResetToken(arg0, arg1 any) *MockConnRunnerAddResetTokenCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddResetToken", reflect.TypeOf((*MockConnRunner)(nil).AddResetToken), arg0, arg1)
	return &MockConnRunnerAddResetTokenCall{Call: call}
}

// MockConnRunnerAddResetTokenCall wrap *gomock.Call
type MockConnRunnerAddResetTokenCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockConnRunnerAddResetTokenCall) Return() *MockConnRunnerAddResetTokenCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockConnRunnerAddResetTokenCall) Do(f func(protocol.StatelessResetToken, packetHandler)) *MockConnRunnerAddResetTokenCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockConnRunnerAddResetTokenCall) DoAndReturn(f func(protocol.StatelessResetToken, packetHandler)) *MockConnRunnerAddResetTokenCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Remove mocks base method.
func (m *MockConnRunner) Remove(arg0 protocol.ConnectionID) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Remove", arg0)
}

// Remove indicates an expected call of Remove.
func (mr *MockConnRunnerMockRecorder) Remove(arg0 any) *MockConnRunnerRemoveCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Remove", reflect.TypeOf((*MockConnRunner)(nil).Remove), arg0)
	return &MockConnRunnerRemoveCall{Call: call}
}

// MockConnRunnerRemoveCall wrap *gomock.Call
type MockConnRunnerRemoveCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockConnRunnerRemoveCall) Return() *MockConnRunnerRemoveCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockConnRunnerRemoveCall) Do(f func(protocol.ConnectionID)) *MockConnRunnerRemoveCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockConnRunnerRemoveCall) DoAndReturn(f func(protocol.ConnectionID)) *MockConnRunnerRemoveCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// RemoveResetToken mocks base method.
func (m *MockConnRunner) RemoveResetToken(arg0 protocol.StatelessResetToken) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "RemoveResetToken", arg0)
}

// RemoveResetToken indicates an expected call of RemoveResetToken.
func (mr *MockConnRunnerMockRecorder) RemoveResetToken(arg0 any) *MockConnRunnerRemoveResetTokenCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoveResetToken", reflect.TypeOf((*MockConnRunner)(nil).RemoveResetToken), arg0)
	return &MockConnRunnerRemoveResetTokenCall{Call: call}
}

// MockConnRunnerRemoveResetTokenCall wrap *gomock.Call
type MockConnRunnerRemoveResetTokenCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockConnRunnerRemoveResetTokenCall) Return() *MockConnRunnerRemoveResetTokenCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockConnRunnerRemoveResetTokenCall) Do(f func(protocol.StatelessResetToken)) *MockConnRunnerRemoveResetTokenCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockConnRunnerRemoveResetTokenCall) DoAndReturn(f func(protocol.StatelessResetToken)) *MockConnRunnerRemoveResetTokenCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// ReplaceWithClosed mocks base method.
func (m *MockConnRunner) ReplaceWithClosed(arg0 []protocol.ConnectionID, arg1 []byte) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReplaceWithClosed", arg0, arg1)
}

// ReplaceWithClosed indicates an expected call of ReplaceWithClosed.
func (mr *MockConnRunnerMockRecorder) ReplaceWithClosed(arg0, arg1 any) *MockConnRunnerReplaceWithClosedCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReplaceWithClosed", reflect.TypeOf((*MockConnRunner)(nil).ReplaceWithClosed), arg0, arg1)
	return &MockConnRunnerReplaceWithClosedCall{Call: call}
}

// MockConnRunnerReplaceWithClosedCall wrap *gomock.Call
type MockConnRunnerReplaceWithClosedCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockConnRunnerReplaceWithClosedCall) Return() *MockConnRunnerReplaceWithClosedCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockConnRunnerReplaceWithClosedCall) Do(f func([]protocol.ConnectionID, []byte)) *MockConnRunnerReplaceWithClosedCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockConnRunnerReplaceWithClosedCall) DoAndReturn(f func([]protocol.ConnectionID, []byte)) *MockConnRunnerReplaceWithClosedCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Retire mocks base method.
func (m *MockConnRunner) Retire(arg0 protocol.ConnectionID) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Retire", arg0)
}

// Retire indicates an expected call of Retire.
func (mr *MockConnRunnerMockRecorder) Retire(arg0 any) *MockConnRunnerRetireCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Retire", reflect.TypeOf((*MockConnRunner)(nil).Retire), arg0)
	return &MockConnRunnerRetireCall{Call: call}
}

// MockConnRunnerRetireCall wrap *gomock.Call
type MockConnRunnerRetireCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockConnRunnerRetireCall) Return() *MockConnRunnerRetireCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockConnRunnerRetireCall) Do(f func(protocol.ConnectionID)) *MockConnRunnerRetireCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockConnRunnerRetireCall) DoAndReturn(f func(protocol.ConnectionID)) *MockConnRunnerRetireCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
