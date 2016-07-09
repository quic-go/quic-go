package flowcontrol

import (
	"errors"
	"sync"

	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
)

type flowControlManager struct {
	connectionParametersManager        *handshake.ConnectionParametersManager
	streamFlowController               map[protocol.StreamID]*flowController
	contributesToConnectionFlowControl map[protocol.StreamID]bool
	mutex                              sync.Mutex
}

var (
	// ErrStreamFlowControlViolation is a stream flow control violation
	ErrStreamFlowControlViolation = errors.New("Stream level flow control violation")
	// ErrConnectionFlowControlViolation is a connection level flow control violation
	ErrConnectionFlowControlViolation = errors.New("Connection level flow control violation")
)

var errMapAccess = errors.New("Error accessing the flowController map.")

// NewFlowControlManager creates a new flow control manager
func NewFlowControlManager(connectionParametersManager *handshake.ConnectionParametersManager) FlowControlManager {
	fcm := flowControlManager{
		connectionParametersManager:        connectionParametersManager,
		streamFlowController:               make(map[protocol.StreamID]*flowController),
		contributesToConnectionFlowControl: make(map[protocol.StreamID]bool),
	}
	// initialize connection level flow controller
	fcm.streamFlowController[0] = newFlowController(0, connectionParametersManager)
	fcm.contributesToConnectionFlowControl[0] = false
	return &fcm
}

// NewStream creates new flow controllers for a stream
func (f *flowControlManager) NewStream(streamID protocol.StreamID, contributesToConnectionFlow bool) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	if _, ok := f.streamFlowController[streamID]; ok {
		return
	}

	f.streamFlowController[streamID] = newFlowController(streamID, f.connectionParametersManager)
	f.contributesToConnectionFlowControl[streamID] = contributesToConnectionFlow
}

// UpdateHighestReceived updates the highest received byte offset for a stream
// it adds the number of additional bytes to connection level flow control
// streamID must not be 0 here
func (f *flowControlManager) UpdateHighestReceived(streamID protocol.StreamID, byteOffset protocol.ByteCount) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	streamFlowController, err := f.getFlowController(streamID)
	if err != nil {
		return err
	}
	increment := streamFlowController.UpdateHighestReceived(byteOffset)

	if streamFlowController.CheckFlowControlViolation() {
		return ErrStreamFlowControlViolation
	}

	if f.contributesToConnectionFlowControl[streamID] {
		connectionFlowController := f.streamFlowController[0]
		connectionFlowController.IncrementHighestReceived(increment)
		if connectionFlowController.CheckFlowControlViolation() {
			return ErrConnectionFlowControlViolation
		}
	}

	return nil
}

// streamID must not be 0 here
func (f *flowControlManager) AddBytesRead(streamID protocol.StreamID, n protocol.ByteCount) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	streamFlowController, err := f.getFlowController(streamID)
	if err != nil {
		return err
	}

	streamFlowController.AddBytesRead(n)

	if f.contributesToConnectionFlowControl[streamID] {
		f.streamFlowController[0].AddBytesRead(n)
	}

	return nil
}

// streamID must not be 0 here
func (f *flowControlManager) MaybeTriggerStreamWindowUpdate(streamID protocol.StreamID) (bool, protocol.ByteCount, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	streamFlowController, err := f.getFlowController(streamID)
	if err != nil {
		return false, 0, err
	}

	doIt, offset := streamFlowController.MaybeTriggerWindowUpdate()
	return doIt, offset, nil
}

func (f *flowControlManager) MaybeTriggerConnectionWindowUpdate() (bool, protocol.ByteCount) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	return f.streamFlowController[0].MaybeTriggerWindowUpdate()
}

// streamID must not be 0 here
func (f *flowControlManager) AddBytesSent(streamID protocol.StreamID, n protocol.ByteCount) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	streamFlowController, err := f.getFlowController(streamID)
	if err != nil {
		return err
	}

	streamFlowController.AddBytesSent(n)

	if f.contributesToConnectionFlowControl[streamID] {
		f.streamFlowController[0].AddBytesSent(n)
	}

	return nil
}

// must not be called with StreamID 0
func (f *flowControlManager) SendWindowSize(streamID protocol.StreamID) (protocol.ByteCount, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	streamFlowController, err := f.getFlowController(streamID)
	if err != nil {
		return 0, err
	}

	return streamFlowController.SendWindowOffset(), nil
}

func (f *flowControlManager) RemainingConnectionWindowSize() protocol.ByteCount {
	return f.streamFlowController[0].SendWindowSize()
}

// streamID may be 0 here
func (f *flowControlManager) UpdateWindow(streamID protocol.StreamID, offset protocol.ByteCount) (bool, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	streamFlowController, err := f.getFlowController(streamID)
	if err != nil {
		return false, err
	}

	return streamFlowController.UpdateSendWindow(offset), nil
}

func (f *flowControlManager) StreamContributesToConnectionFlowControl(streamID protocol.StreamID) (bool, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	contributes, ok := f.contributesToConnectionFlowControl[streamID]
	if !ok {
		return false, errMapAccess
	}
	return contributes, nil
}

func (f *flowControlManager) getFlowController(streamID protocol.StreamID) (*flowController, error) {
	streamFlowController, ok := f.streamFlowController[streamID]
	if !ok {
		return nil, errMapAccess
	}
	return streamFlowController, nil
}
