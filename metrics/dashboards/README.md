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
quic.Config{
	Tracer: metrics.DefaultConnectionTracer,
}
```

Running:
```shell
docker-compose up
```
