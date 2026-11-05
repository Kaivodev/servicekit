package queue

import (
	"context"
	"testing"
	"time"

	"github.com/Kaivodev/observability/asynqobs"
	"github.com/hibiken/asynq"
)

func TestQueueRejectsInvalidOrUnboundedTaskTimeouts(t *testing.T) {
	cfg, err := Load("test", func(key string) string {
		if key == "AIPAY_QUEUE_REDIS_URL" {
			return "redis://127.0.0.1:6379/0"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []time.Duration{0, time.Millisecond, 1500 * time.Millisecond, -time.Second} {
		bad := cfg
		bad.TaskTimeout = d
		if bad.Validate() == nil {
			t.Fatalf("accepted timeout %v", d)
		}
		// Invalid per-task values must be rejected before touching the broker.
		p := new(Producer)
		if _, err = p.Enqueue(context.Background(), asynqobs.Message{}, asynq.Timeout(d)); err == nil {
			t.Fatal("invalid override accepted")
		}
	}
	if _, err = Load("test", func(string) string { return "" }); err == nil {
		t.Fatal("cache connection implicitly reused for queue")
	}
}
