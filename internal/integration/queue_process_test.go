//go:build integration

package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/aipay-dev/observability/asynqobs"
	"github.com/aipay-dev/observability/logging"
	"github.com/aipay-dev/observability/requestmeta"
	"github.com/aipay-dev/observability/tracing"
	"github.com/aipay-dev/servicekit/queue"
	"github.com/hibiken/asynq"
)

// This helper runs in a new OS process, so no Go context, connection or worker
// object can survive the restart. Only Redis headers carry the origin IDs.
func TestQueueProcessHelper(t *testing.T) {
	if os.Getenv("AIPAY_QUEUE_TEST_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	var cfg queue.Config
	if err := json.Unmarshal([]byte(os.Getenv("AIPAY_QUEUE_TEST_CONFIG")), &cfg); err != nil {
		t.Fatal("decode child config")
	}
	output, err := os.OpenFile(os.Getenv("AIPAY_QUEUE_TEST_LOG"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	logger := logging.New(output, slog.LevelInfo)
	tcfg := tracing.DefaultConfig()
	tcfg.Endpoint = os.Getenv("AIPAY_QUEUE_TEST_OTLP")
	tcfg.BatchInterval = 50 * time.Millisecond
	rt, err := tracing.Open(context.Background(), tracing.Options{Config: tcfg, Service: "queue-process", Version: "test", Instance: fmt.Sprintf("worker-%d", os.Getpid())}, logger)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()
	worker, err := queue.NewWorker(ctx, cfg, rt.Provider(), logger, logger, asynq.HandlerFunc(func(ctx context.Context, _ *asynq.Task) error {
		id, _ := asynq.GetTaskID(ctx)
		data, _ := json.Marshal(map[string]string{"task_id": id, "trace_id": requestmeta.From(ctx).TraceID})
		return os.WriteFile(os.Getenv("AIPAY_QUEUE_TEST_RESULT"), data, 0600)
	}))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	eventually(t, 3*time.Second, "child readiness", func() bool { return worker.Check(context.Background()) == nil })
	fmt.Println("queue-worker-ready")
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if err = rt.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestQueueTraceSurvivesProcessRestart(t *testing.T) {
	_, endpoint := startSink(t)
	var logs traceBuffer
	rt := traceRuntime(t, endpoint, "queue-process-origin", &logs)
	cfg := testQueueConfig(t)
	configJSON, _ := json.Marshal(cfg)
	root := t.TempDir()
	result := filepath.Join(root, "result.json")
	start := func(label string) *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=^TestQueueProcessHelper$", "-test.timeout=30s")
		cmd.Env = append(os.Environ(), "AIPAY_QUEUE_TEST_CHILD=1", "AIPAY_QUEUE_TEST_CONFIG="+string(configJSON), "AIPAY_QUEUE_TEST_OTLP="+endpoint, "AIPAY_QUEUE_TEST_LOG="+filepath.Join(root, label+".log"), "AIPAY_QUEUE_TEST_RESULT="+result)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		var stderr traceBuffer
		cmd.Stderr = &stderr
		if err = cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if cmd.ProcessState == nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		})
		ready := make(chan bool, 1)
		go func() {
			scanner := bufio.NewScanner(stdout)
			found := false
			for scanner.Scan() {
				if scanner.Text() == "queue-worker-ready" {
					ready <- true
					found = true
				}
			}
			if !found {
				ready <- false
			}
		}()
		select {
		case ok := <-ready:
			if !ok {
				t.Fatal("child failed before readiness: ", stderr.String())
			}
		case <-time.After(5 * time.Second):
			t.Fatal("child readiness timeout")
		}
		return cmd
	}
	stop := func(cmd *exec.Cmd) {
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal("worker process shutdown: ", err)
			}
		case <-time.After(7 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			t.Fatal("worker process shutdown timeout")
		}
	}
	first := start("first")
	stop(first)
	origin, cancel := context.WithCancel(context.Background())
	origin, span := rt.Tracer("test").Start(origin, "process.origin")
	traceID := span.SpanContext().TraceID().String()
	message := asynqobs.NewMessage(origin, "fixture.process", nil)
	span.End()
	cancel()
	producer, err := queue.NewProducer(context.Background(), cfg, rt.Provider(), logging.New(&logs, slog.LevelInfo))
	if err != nil {
		t.Fatal(err)
	}
	info, err := producer.Enqueue(context.Background(), message, asynq.Retention(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	_ = producer.Close()
	second := start("second")
	inspector := queueInspector(t, cfg)
	eventually(t, 6*time.Second, "new process completed persisted task", func() bool {
		task, err := inspector.GetTaskInfo(cfg.Name, info.ID)
		return err == nil && task.State == asynq.TaskStateCompleted
	})
	stop(second)
	data, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var actual map[string]string
	if err = json.Unmarshal(data, &actual); err != nil {
		t.Fatal(err)
	}
	if actual["trace_id"] != traceID || actual["task_id"] != info.ID {
		t.Fatal("process restart lost task trace or identity")
	}
}
