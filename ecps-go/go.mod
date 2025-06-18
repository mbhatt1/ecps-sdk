module github.com/ecps/ecps-go

go 1.20

require (
	github.com/cloudevents/sdk-go/v2 v2.14.0
	github.com/eclipse/paho.mqtt.golang v1.4.3
	github.com/golang/protobuf v1.5.3
	github.com/nats-io/nats.go v1.30.0
	github.com/stretchr/testify v1.8.4
	go.opentelemetry.io/otel v1.19.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.19.0
	go.opentelemetry.io/otel/sdk v1.19.0
	go.opentelemetry.io/otel/trace v1.19.0
	go.uber.org/zap v1.26.0
	google.golang.org/grpc v1.59.0
	google.golang.org/protobuf v1.31.0
	klauspost/compress v1.17.0 // zstandard compression
)