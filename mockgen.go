package quic

//go:generate sh -c "./mockgen_private.sh quic mock_stream_internal_test.go github.com/lucas-clemente/quic-go streamI StreamI"
//go:generate sh -c "./mockgen_private.sh quic mock_stream_sender_test.go github.com/lucas-clemente/quic-go streamSender StreamSender"
