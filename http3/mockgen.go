//go:build gomock || generate

package http3

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -mock_names=TestClientConnInterface=MockClientConn  -package http3 -destination mock_clientconn_test.go github.com/Noooste/uquic-go/http3 TestClientConnInterface"
type TestClientConnInterface = clientConn

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -mock_names=DatagramStream=MockDatagramStream  -package http3 -destination mock_datagram_stream_test.go github.com/Noooste/uquic-go/http3 DatagramStream"
type DatagramStream = datagramStream

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -package http3 -destination mock_quic_early_listener_test.go github.com/Noooste/uquic-go/http3 QUICEarlyListener"
