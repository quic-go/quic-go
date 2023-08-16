// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/quic-go/quic-go/internal/qtls (interfaces: ClientSessionCache)

// Package mocktls is a generated GoMock package.
package mocktls

import (
	reflect "reflect"

	tls "github.com/quic-go/quic-go/internal/qtls"

	gomock "github.com/golang/mock/gomock"
)

// MockClientSessionCache is a mock of ClientSessionCache interface.
type MockClientSessionCache struct {
	ctrl     *gomock.Controller
	recorder *MockClientSessionCacheMockRecorder
}

// MockClientSessionCacheMockRecorder is the mock recorder for MockClientSessionCache.
type MockClientSessionCacheMockRecorder struct {
	mock *MockClientSessionCache
}

// NewMockClientSessionCache creates a new mock instance.
func NewMockClientSessionCache(ctrl *gomock.Controller) *MockClientSessionCache {
	mock := &MockClientSessionCache{ctrl: ctrl}
	mock.recorder = &MockClientSessionCacheMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClientSessionCache) EXPECT() *MockClientSessionCacheMockRecorder {
	return m.recorder
}

// Get mocks base method.
func (m *MockClientSessionCache) Get(arg0 string) (*tls.ClientSessionState, bool) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", arg0)
	ret0, _ := ret[0].(*tls.ClientSessionState)
	ret1, _ := ret[1].(bool)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockClientSessionCacheMockRecorder) Get(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockClientSessionCache)(nil).Get), arg0)
}

// Put mocks base method.
func (m *MockClientSessionCache) Put(arg0 string, arg1 *tls.ClientSessionState) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Put", arg0, arg1)
}

// Put indicates an expected call of Put.
func (mr *MockClientSessionCacheMockRecorder) Put(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Put", reflect.TypeOf((*MockClientSessionCache)(nil).Put), arg0, arg1)
}
