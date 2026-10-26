//go:build integration

package integration

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aipay-dev/observability/asynqobs"
	"github.com/aipay-dev/observability/hertzobs"
	"github.com/aipay-dev/observability/httpobs"
	"github.com/aipay-dev/observability/logging"
	"github.com/aipay-dev/observability/requestmeta"
	"github.com/aipay-dev/observability/tracing"
	"github.com/aipay-dev/servicekit/queue"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/network/standard"
	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestHTTPOutboxQueueRetryDownstreamTrace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	raw := os.Getenv("AIPAY_TEST_DATABASE_URL")
	if raw == "" {
		t.Fatal("isolated PostgreSQL is required")
	}
	db, err := pgxpool.New(ctx, raw)
	if err != nil {
		t.Fatal("open test PostgreSQL")
	}
	defer db.Close()
	schema := fmt.Sprintf("trace_test_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = db.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE")
	// Fixtures only: product schemas and financial state are never created here.
	if _, err = db.Exec(ctx, "CREATE TABLE "+quoted+".intent(id text PRIMARY KEY); CREATE TABLE "+quoted+".outbox(id text PRIMARY KEY REFERENCES "+quoted+".intent(id),message jsonb NOT NULL); CREATE TABLE "+quoted+".effect(id text PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	sink, endpoint := startSink(t)
	var logs traceBuffer
	gateway := traceRuntime(t, endpoint, "trace-gateway", &logs)
	owner := traceRuntime(t, endpoint, "trace-owner", &logs)
	relay := traceRuntime(t, endpoint, "trace-relay", &logs)
	workerRT := traceRuntime(t, endpoint, "trace-worker", &logs)
	downstream := traceRuntime(t, endpoint, "trace-downstream", &logs)
	certs := traceMaterials(t)
	id := uuid.NewString()
	originalDone := make(chan (<-chan struct{}), 1)
	ownerServer := startFixtureRPC(t, "iam", "backend", certs["iam"], owner, &logs, func(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
		originalDone <- ctx.Done()
		ctx, span := owner.Tracer("integration").Start(ctx, "outbox.commit")
		defer span.End()
		tx, err := db.Begin(ctx)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback(context.Background())
		message := asynqobs.NewMessage(ctx, "fixture.deliver", []byte("payload-secret"))
		encoded, err := json.Marshal(message)
		if err != nil {
			return nil, err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO "+quoted+".intent VALUES($1)", id); err != nil {
			return nil, err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO "+quoted+".outbox VALUES($1,$2)", id, encoded); err != nil {
			return nil, err
		}
		return &emptypb.Empty{}, tx.Commit(ctx)
	})
	ownerConn := traceConnect(t, ownerServer, "iam", certs["backend"], gateway)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := server.New(server.WithListener(listener), server.WithTransport(standard.NewTransporter), server.WithDisablePrintRoute(true))
	h.Use(hertzobs.Middleware(gateway.Provider(), nil))
	h.GET("/fixture", func(ctx context.Context, c *app.RequestContext) {
		ctx = requestmeta.Ensure(ctx)
		c.Response.Header.Set("X-Trace-ID", requestmeta.From(ctx).TraceID)
		if err := ownerConn.Invoke(ctx, "/test.Trace/Call", &emptypb.Empty{}, &emptypb.Empty{}); err != nil {
			c.SetStatusCode(500)
			return
		}
		logging.New(&logs, slog.LevelInfo).InfoContext(ctx, "fixture HTTP complete")
		c.SetStatusCode(204)
	})
	httpDone := make(chan error, 1)
	go func() { httpDone <- h.Run() }()
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h.Shutdown(stop)
		_ = h.Close()
		_ = listener.Close()
		<-httpDone
	})
	response, err := http.Get("http://" + listener.Addr().String() + "/fixture?token=query-secret")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal("fixture HTTP failed")
	}
	traceID := response.Header.Get("X-Trace-ID")
	select {
	case <-<-originalDone:
	case <-ctx.Done():
		t.Fatal("original RPC did not end")
	}
	// Restore the committed carrier using a fresh dispatch context after RPC ends.
	var encoded []byte
	if err = db.QueryRow(ctx, "SELECT message FROM "+quoted+".outbox WHERE id=$1", id).Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	var message asynqobs.Message
	if err = json.Unmarshal(encoded, &message); err != nil {
		t.Fatal(err)
	}
	cfg := testQueueConfig(t)
	log := logging.New(&logs, slog.LevelInfo)
	producer, err := queue.NewProducer(ctx, cfg, relay.Provider(), log)
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Close()
	info, err := producer.Enqueue(context.Background(), message, asynq.TaskID(id), asynq.Retention(time.Minute), asynq.Queue("unowned"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Queue != cfg.Name {
		t.Fatal("caller overrode owned queue")
	}
	if _, err = producer.Enqueue(ctx, message, asynq.TaskID(id)); !errors.Is(err, asynq.ErrTaskIDConflict) {
		t.Fatal("duplicate admission was not preserved")
	}
	downstreamServer := startFixtureRPC(t, "ledger", "iam", certs["ledger"], downstream, &logs, func(context.Context, *emptypb.Empty) (*emptypb.Empty, error) { return &emptypb.Empty{}, nil })
	downstreamConn := traceConnect(t, downstreamServer, "ledger", certs["iam"], workerRT)
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("traceparent") != "" {
			t.Error("external callback received internal trace header")
		}
		w.WriteHeader(204)
	}))
	defer external.Close()
	httpClient := &http.Client{Transport: &httpobs.Transport{Tracer: workerRT.Tracer("integration"), Operation: "fixture.callback"}, Timeout: time.Second}
	var attempts atomic.Int32
	handler := asynq.HandlerFunc(func(ctx context.Context, task *asynq.Task) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		taskID, _ := asynq.GetTaskID(ctx)
		if taskID != id {
			return errors.New("wrong task identity")
		}
		if _, err := db.Exec(ctx, "INSERT INTO "+quoted+".effect VALUES($1) ON CONFLICT DO NOTHING", taskID); err != nil {
			return err
		}
		if attempts.Add(1) == 1 {
			return errors.New("private-error-secret")
		}
		if err := downstreamConn.Invoke(ctx, "/test.Trace/Call", &emptypb.Empty{}, &emptypb.Empty{}); err != nil {
			return err
		}
		request, _ := http.NewRequestWithContext(ctx, http.MethodPost, external.URL+"/?token=query-secret", nil)
		response, err := httpClient.Do(request)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, response.Body)
		return response.Body.Close()
	})
	runWorker, stopWorker := startQueue(t, cfg, workerRT, &logs, handler)
	inspect, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		t.Fatal("invalid test Redis")
	}
	redisClient := redis.NewClient(inspect)
	defer redisClient.Close()
	inspector := asynq.NewInspectorFromRedisClient(redisClient)
	eventually(t, 20*time.Second, "retry completion", func() bool {
		info, err := inspector.GetTaskInfo(cfg.Name, id)
		return err == nil && info.State == asynq.TaskStateCompleted
	})
	stopWorker()
	if err := <-runWorker; err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 2 {
		t.Fatalf("attempts=%d", attempts.Load())
	}
	var effects int
	if err = db.QueryRow(ctx, "SELECT count(*) FROM "+quoted+".effect").Scan(&effects); err != nil || effects != 1 {
		t.Fatal("retry duplicated durable effect")
	}
	for _, rt := range []*tracing.Runtime{gateway, owner, relay, workerRT, downstream} {
		if err = rt.Shutdown(ctx); err != nil {
			t.Fatal(err)
		}
		if rt.ExportFailures() != 0 {
			t.Fatal("OTLP export failed")
		}
	}
	spans := map[string]*tracepb.Span{}
	services := map[string]bool{}
	var attemptsSpans []*tracepb.Span
	for _, resource := range sink.snapshot() {
		for _, a := range resource.Resource.Attributes {
			if a.Key == "service.name" {
				services[a.Value.GetStringValue()] = true
			}
		}
		for _, scope := range resource.ScopeSpans {
			for _, span := range scope.Spans {
				if hex.EncodeToString(span.TraceId) != traceID {
					t.Fatal("durable trace chain split")
				}
				spans[hex.EncodeToString(span.SpanId)] = span
				if span.Name == "process fixture.deliver" {
					attemptsSpans = append(attemptsSpans, span)
				}
				bytes, _ := json.Marshal(span)
				if strings.Contains(string(bytes), "secret") {
					t.Fatal("private data in exported span")
				}
			}
		}
	}
	if len(services) != 5 || len(attemptsSpans) != 2 || len(spans) < 11 {
		t.Fatalf("missing services/spans: services=%d attempts=%d spans=%d", len(services), len(attemptsSpans), len(spans))
	}
	roots := 0
	for _, span := range spans {
		if len(span.ParentSpanId) == 0 {
			roots++
		} else if spans[hex.EncodeToString(span.ParentSpanId)] == nil {
			t.Fatalf("orphan span %s", span.Name)
		}
	}
	if roots != 1 || string(attemptsSpans[0].SpanId) == string(attemptsSpans[1].SpanId) || string(attemptsSpans[0].ParentSpanId) != string(attemptsSpans[1].ParentSpanId) {
		t.Fatal("invalid root or retry parent relationship")
	}
	if strings.Contains(logs.String(), "secret") {
		t.Fatal("private payload/error/query in logs")
	}
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var event map[string]any
		if err = json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		if spanID, ok := event["span_id"].(string); ok {
			if event["trace_id"] != traceID || spans[spanID] == nil {
				t.Fatal("log does not identify an exported span")
			}
		}
	}
	verifyJaeger(t, traceID, len(spans))
	t.Logf("HTTP → mTLS RPC → PostgreSQL outbox → Asynq retry → mTLS RPC/HTTP: %d spans across %d resources, trace=%s", len(spans), len(services), traceID)
}

func testQueueConfig(t *testing.T) queue.Config {
	t.Helper()
	cfg, err := queue.Load("fixture", func(key string) string {
		if key == "AIPAY_QUEUE_REDIS_URL" {
			return os.Getenv("AIPAY_TEST_REDIS_URL")
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Name = "test." + uuid.NewString()
	cfg.Concurrency = 1
	cfg.TaskTimeout = 3 * time.Second
	cfg.MaxRetry = 1
	cfg.ShutdownTimeout = 5 * time.Second
	return cfg
}
func startQueue(t *testing.T, cfg queue.Config, rt *tracing.Runtime, logs *traceBuffer, handler asynq.Handler) (<-chan error, context.CancelFunc) {
	t.Helper()
	log := logging.New(logs, slog.LevelInfo)
	worker, err := queue.NewWorker(context.Background(), cfg, rt.Provider(), log, log, handler, queue.WorkerOptions{RetryDelay: func(int, error, *asynq.Task) time.Duration { return time.Second }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	t.Cleanup(cancel)
	eventually(t, 3*time.Second, "queue readiness", func() bool { return worker.Check(context.Background()) == nil })
	return done, cancel
}
func verifyJaeger(t *testing.T, id string, count int) {
	t.Helper()
	base := os.Getenv("AIPAY_TEST_JAEGER_URL")
	if base == "" {
		return
	}
	client := &http.Client{Timeout: time.Second}
	eventually(t, 10*time.Second, "Collector → Jaeger query", func() bool {
		r, err := client.Get(base + "/api/traces/" + id)
		if err != nil {
			return false
		}
		defer r.Body.Close()
		var result struct {
			Data []struct {
				Spans []json.RawMessage `json:"spans"`
			} `json:"data"`
		}
		return r.StatusCode == 200 && json.NewDecoder(r.Body).Decode(&result) == nil && len(result.Data) == 1 && len(result.Data[0].Spans) >= count
	})
}
