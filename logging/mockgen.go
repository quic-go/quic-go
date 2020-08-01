package logging

//go:generate sh -c "mockgen -package logging -destination mock_connection_tracer_test.go github.com/lucas-clemente/quic-go/logging ConnectionTracer"
//go:generate sh -c "mockgen -package logging -destination mock_tracer_test.go github.com/lucas-clemente/quic-go/logging Tracer"
