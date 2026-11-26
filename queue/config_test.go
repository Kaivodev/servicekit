package queue

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Kaivodev/observability/asynqobs"
	"github.com/hibiken/asynq"
)

func TestLoadQueueRedisTLS(t *testing.T) {
	const (
		password    = "queue-password"
		plaintext   = "redis://:" + password + "@localhost/0"
		tlsError    = "AIPAY_QUEUE_REDIS_URL requires rediss:// in production"
		formatError = "AIPAY_QUEUE_REDIS_URL must point to a dedicated redis:// or rediss:// endpoint"
		envError    = "AIPAY_ENVIRONMENT must be development, test or production"
	)
	for _, tc := range []struct{ name, environment, redisURL, wantErr string }{
		{"production plaintext", "production", plaintext, tlsError},
		{"default plaintext", "", plaintext, tlsError},
		{"production TLS", "production", "rediss://localhost/0", ""},
		{"development plaintext", "development", plaintext, ""},
		{"test plaintext", "test", plaintext, ""},
		{"invalid environment", "dev", plaintext, envError},
		{"invalid environment and URL", "dev", "", envError},
		{"unsupported scheme", "production", "http://localhost/0", formatError},
		{"missing host", "production", "redis:///0", formatError},
		{"malformed URL", "production", plaintext + "%", formatError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := map[string]string{"AIPAY_QUEUE_REDIS_URL": tc.redisURL}
			if tc.environment != "" {
				settings["AIPAY_ENVIRONMENT"] = tc.environment
			}
			_, err := Load("fixture", func(key string) string { return settings[key] })
			if err != nil && strings.Contains(err.Error(), password) {
				t.Fatal("queue Redis password exposed")
			}
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || err.Error() != tc.wantErr {
				t.Fatalf("Load() error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateIsEnvironmentIndependent(t *testing.T) {
	t.Setenv("AIPAY_ENVIRONMENT", "production")
	cfg := Config{
		RedisURL: "redis://localhost/0", Name: "fixture",
		Concurrency: 1, PoolSize: 1, MaxPayloadBytes: 1,
		RedisTimeout: time.Second, TaskTimeout: time.Second, ShutdownTimeout: time.Second,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestQueueRejectsInvalidOrUnboundedTaskTimeouts(t *testing.T) {
	cfg, err := Load("test", func(key string) string {
		switch key {
		case "AIPAY_ENVIRONMENT":
			return "test"
		case "AIPAY_QUEUE_REDIS_URL":
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
