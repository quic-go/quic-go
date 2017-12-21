package quic

//go:generate sh -c "./mockgen_private.sh quic mock_stream_internal_test.go github.com/lucas-clemente/quic-go streamI StreamI"
//go:generate sh -c "./mockgen_private.sh quic mock_stream_sender_test.go github.com/lucas-clemente/quic-go streamSender StreamSender"
//go:generate sh -c "./mockgen_private.sh quic mock_stream_getter_test.go github.com/lucas-clemente/quic-go streamGetter StreamGetter"
//go:generate sh -c "./mockgen_private.sh quic mock_crypto_stream_test.go github.com/lucas-clemente/quic-go cryptoStreamI CryptoStream"
//go:generate sh -c "sed -i '' 's/quic_go.//g' mock_stream_getter_test.go"
//go:generate sh -c "goimports -w mock*_test.go"
