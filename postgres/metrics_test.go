package postgres

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestPoolMetrics(t *testing.T) {
	ctx := t.Context()
	cfg, err := pgxpool.ParseConfig("pool_max_conns=7 pool_min_conns=0")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	if _, err := ObservePool(provider, "bad.pool", pool); err == nil {
		t.Fatal("invalid pool name accepted")
	}
	unregister, err := ObservePool(provider, "primary", pool)
	if err != nil {
		t.Fatal(err)
	}
	var data metricdata.ResourceMetrics
	if err = reader.Collect(ctx, &data); err != nil {
		t.Fatal(err)
	}
	metrics := data.ScopeMetrics[0].Metrics
	if len(metrics) != 6 {
		t.Fatal(metrics)
	}
	label := attribute.String("pool", "primary")
	attrs := attribute.NewSet(label)
	for _, m := range metrics {
		if m.Name != "kaivo.db.pool.empty_acquire.wait" && m.Unit != "" {
			t.Fatal(m)
		}
		switch m.Name {
		case "kaivo.db.pool.connections":
			got := map[attribute.Set]int64{}
			for _, p := range m.Data.(metricdata.Gauge[int64]).DataPoints {
				got[p.Attributes] = p.Value
			}
			if len(got) != 3 {
				t.Fatal(got)
			}
			for _, state := range []string{"idle", "acquired", "constructing"} {
				if n, ok := got[attribute.NewSet(label, attribute.String("state", state))]; !ok || n != 0 {
					t.Fatal(got)
				}
			}
		case "kaivo.db.pool.max_connections":
			p := m.Data.(metricdata.Gauge[int64]).DataPoints[0]
			if p.Value != 7 || p.Attributes != attrs {
				t.Fatal(p)
			}
		case "kaivo.db.pool.acquires", "kaivo.db.pool.empty_acquires", "kaivo.db.pool.canceled_acquires":
			sum := m.Data.(metricdata.Sum[int64])
			p := sum.DataPoints[0]
			if !sum.IsMonotonic || p.Value != 0 || p.Attributes != attrs {
				t.Fatal(m)
			}
		case "kaivo.db.pool.empty_acquire.wait":
			sum := m.Data.(metricdata.Sum[float64])
			p := sum.DataPoints[0]
			if !sum.IsMonotonic || m.Unit != "s" || p.Value != 0 || p.Attributes != attrs {
				t.Fatal(m)
			}
		default:
			t.Fatal(m.Name)
		}
	}
	if err = unregister(); err != nil {
		t.Fatal(err)
	}
	if err = reader.Collect(ctx, &data); err != nil || len(data.ScopeMetrics) != 0 {
		t.Fatalf("after unregister: %v %v", data, err)
	}
}
