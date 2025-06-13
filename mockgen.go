//go:build gomock || generate

package quic

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/Noooste/uquic-go -destination mock_send_conn_test.go github.com/Noooste/uquic-go SendConn"
type SendConn = sendConn

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/Noooste/uquic-go -destination mock_raw_conn_test.go github.com/Noooste/uquic-go RawConn"
type RawConn = rawConn

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/Noooste/uquic-go -destination mock_sender_test.go github.com/Noooste/uquic-go Sender"
type Sender = sender

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/Noooste/uquic-go -destination mock_stream_internal_test.go github.com/Noooste/uquic-go StreamI"
type StreamI = streamI

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/Noooste/uquic-go -destination mock_receive_stream_internal_test.go github.com/Noooste/uquic-go ReceiveStreamI"
type ReceiveStreamI = receiveStreamI

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/Noooste/uquic-go -destination mock_send_stream_internal_test.go github.com/Noooste/uquic-go SendStreamI"
type SendStreamI = sendStreamI

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/Noooste/uquic-go -destination mock_stream_sender_test.go github.com/Noooste/uquic-go StreamSender"
type StreamSender = streamSender

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/Noooste/uquic-go -destination mock_stream_control_frame_getter_test.go github.com/Noooste/uquic-go StreamControlFrameGetter"
type StreamControlFrameGetter = streamControlFrameGetter

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/Noooste/uquic-go -destination mock_frame_source_test.go github.com/Noooste/uquic-go FrameSource"
type FrameSource = frameSource

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/Noooste/uquic-go -destination mock_ack_frame_source_test.go github.com/Noooste/uquic-go AckFrameSource"
type AckFrameSource = ackFrameSource

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/Noooste/uquic-go -destination mock_stream_manager_test.go github.com/Noooste/uquic-go StreamManager"
type StreamManager = streamManager

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/Noooste/uquic-go -destination mock_sealing_manager_test.go github.com/Noooste/uquic-go SealingManager"
type SealingManager = sealingManager

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/Noooste/uquic-go -destination mock_unpacker_test.go github.com/Noooste/uquic-go Unpacker"
type Unpacker = unpacker

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/Noooste/uquic-go -destination mock_packer_test.go github.com/Noooste/uquic-go Packer"
type Packer = packer

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/Noooste/uquic-go -destination mock_mtu_discoverer_test.go github.com/Noooste/uquic-go MTUDiscoverer"
type MTUDiscoverer = mtuDiscoverer

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/Noooste/uquic-go -destination mock_conn_runner_test.go github.com/Noooste/uquic-go ConnRunner"
type ConnRunner = connRunner

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/Noooste/uquic-go -destination mock_quic_conn_test.go github.com/Noooste/uquic-go QUICConn"
type QUICConn = quicConn

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package quic -self_package github.com/Noooste/uquic-go -destination mock_packet_handler_test.go github.com/Noooste/uquic-go PacketHandler"
type PacketHandler = packetHandler

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -package quic -self_package github.com/Noooste/uquic-go -self_package github.com/Noooste/uquic-go -destination mock_packetconn_test.go net PacketConn"
