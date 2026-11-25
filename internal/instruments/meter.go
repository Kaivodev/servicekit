// Package instruments supplies the explicitly injected meter for each component.
package instruments

import (
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

func Meter(provider metric.MeterProvider, component string) metric.Meter {
	if provider == nil {
		provider = noop.NewMeterProvider()
	}
	return provider.Meter("github.com/Kaivodev/servicekit/" + component)
}
