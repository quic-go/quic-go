# quic-go Prometheus / Grafana setup

Expose a Grafana endpoint on `http://localhost:5001/prometheus`:
```go
import "github.com/prometheus/client_golang/prometheus/promhttp"

go func() {
    http.Handle("/prometheus", promhttp.Handler())
    log.Fatal(http.ListenAndServe(":5001", nil))
}()
```

Set a metrics tracer on the `Transport`:
```go
quic.Transport{
	Tracer: metrics.NewTracer(),
}
```

When using multiple `Transport`s, it is recommended to use the metrics tracer struct for all of them.


Set a metrics connection tracer on the `Config`:
```go
tracer := metrics.DefaultTracer()
quic.Config{
	Tracer: tracer,
}
```

It is recommended to use the same connection tracer returned by `DefaultTracer` on the `Config`s for all connections.


Running:
```shell
docker-compose up
```
