# quic-go Prometheus / Grafana Local Development Setup

For local development and debugging, it can be useful to spin up a local Prometheus and Grafana instance.

Please refer to the [documentation](https://quic-go.net/docs/quic/metrics/) for how to configure quic-go to expose Prometheus metrics.

The configuration files in this directory assume that the application exposes the Prometheus endpoint at `http://localhost:5001/prometheus`:
```go
import "github.com/prometheus/client_golang/prometheus/promhttp"

go func() {
    http.Handle("/prometheus", promhttp.Handler())
    log.Fatal(http.ListenAndServe("localhost:5001", nil))
}()
```

Prometheus and Grafana can be started using Docker Compose:

Running:
```shell
docker compose up
```

[quic-go.json](./quic-go.json) contains the JSON model of an example Grafana dashboard.
