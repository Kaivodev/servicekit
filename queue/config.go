// Package queue owns explicit Asynq connection and worker lifecycles. It never
// registers business handlers implicitly or owns outbox SQL and business state.
package queue

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/Kaivodev/servicekit/config"
)

type Config struct {
	RedisURL        string
	Name            string
	Concurrency     int
	PoolSize        int
	RedisTimeout    time.Duration
	TaskTimeout     time.Duration
	MaxRetry        int
	MaxPayloadBytes int
	ShutdownTimeout time.Duration
}

var queueName = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,127}$`)

func Load(service string, get func(string) string) (Config, error) {
	if get == nil || !queueName.MatchString(service) {
		return Config{}, errors.New("queue configuration requires a service and environment reader")
	}
	environment, err := config.LoadEnvironment(get)
	if err != nil {
		return Config{}, err
	}
	value := func(key, fallback string) string {
		if v := get("AIPAY_QUEUE_" + key); v != "" {
			return v
		}
		return fallback
	}
	var problems []error
	integer := func(key, fallback string) int {
		n, err := strconv.Atoi(value(key, fallback))
		if err != nil {
			problems = append(problems, fmt.Errorf("AIPAY_QUEUE_%s must be an integer", key))
		}
		return n
	}
	duration := func(key, fallback string) time.Duration {
		d, err := time.ParseDuration(value(key, fallback))
		if err != nil {
			problems = append(problems, fmt.Errorf("AIPAY_QUEUE_%s must be a duration", key))
		}
		return d
	}
	cfg := Config{RedisURL: get("AIPAY_QUEUE_REDIS_URL"), Name: value("NAME", "aipay."+service), Concurrency: integer("CONCURRENCY", "10"), PoolSize: integer("POOL_SIZE", "20"), RedisTimeout: duration("REDIS_TIMEOUT", "3s"), TaskTimeout: duration("TASK_TIMEOUT", "5m"), MaxRetry: integer("MAX_RETRY", "10"), MaxPayloadBytes: integer("MAX_PAYLOAD_BYTES", "1048576"), ShutdownTimeout: duration("SHUTDOWN_TIMEOUT", "15s")}
	return cfg, errors.Join(append(problems, cfg.validate(!environment.IsDevelopmentOrTest()))...)
}

// Validate checks the endpoint and limits independently of the environment.
// Callers that construct a Config directly must enforce their environment's TLS policy.
func (c Config) Validate() error {
	return c.validate(false)
}

func (c Config) validate(requireTLS bool) error {
	u, err := url.Parse(c.RedisURL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "redis" && u.Scheme != "rediss") {
		return errors.New("AIPAY_QUEUE_REDIS_URL must point to a dedicated redis:// or rediss:// endpoint")
	}
	var problems []error
	if requireTLS && u.Scheme != "rediss" {
		problems = append(problems, errors.New("AIPAY_QUEUE_REDIS_URL requires rediss:// in production"))
	}
	if !queueName.MatchString(c.Name) || c.Concurrency < 1 || c.Concurrency > 1024 || c.PoolSize < 1 || c.PoolSize > 10000 || c.RedisTimeout <= 0 || c.TaskTimeout < time.Second || c.TaskTimeout%time.Second != 0 || c.MaxRetry < 0 || c.MaxRetry > 100 || c.MaxPayloadBytes < 1 || c.MaxPayloadBytes > 16<<20 || c.ShutdownTimeout <= 0 {
		problems = append(problems, errors.New("invalid queue name, limits or timeouts"))
	}
	return errors.Join(problems...)
}
