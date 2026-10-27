// Package config validates process settings without opening resources.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aipay-dev/observability/logging"
	"github.com/aipay-dev/observability/tracing"
)

type Config struct {
	Service         string
	Environment     Environment
	Logging         logging.Options
	Tracing         tracing.Config
	LogLevel        slog.Level
	RPC             RPC
	TLS             TLS
	Database        Database
	Redis           Redis
	StartupTimeout  time.Duration
	ShutdownTimeout time.Duration
	HealthTimeout   time.Duration
	HealthInterval  time.Duration
}

type RPC struct {
	Address              string
	ServerName           string
	AllowedPeers         []string
	CallTimeout          time.Duration
	MaxMessageBytes      int
	MaxConcurrentStreams uint32
	// MaxConnectionAge closes server connections so clients handshake again
	// with current certificates; MaxConnectionAgeGrace lets in-flight RPCs
	// finish first. grpc-go adds ±10% jitter to the age, so the 54m default
	// plus the 30s grace keeps every connection under one hour.
	MaxConnectionAge      time.Duration
	MaxConnectionAgeGrace time.Duration
}

// MaxConnectionAgeLimit is the longest connection lifetime a server accepts.
const MaxConnectionAgeLimit = time.Hour

type TLS struct {
	CAFile      string
	CertFile    string
	KeyFile     string
	TrustDomain string
	// ReloadInterval is how often mtls.Material.Watch re-reads the files.
	ReloadInterval time.Duration
}

type Database struct {
	URL             string
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
}

// An empty URL disables Redis; services only enable dependencies they use.
type Redis struct {
	URL      string
	PoolSize int
	Timeout  time.Duration
}

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
var domainPattern = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)

func ValidService(name string) bool { return namePattern.MatchString(name) }
func ValidTrustDomain(domain string) bool {
	return len(domain) <= 253 && domainPattern.MatchString(domain)
}

func Load(service, defaultAddress string, get func(string) string) (Config, error) {
	if get == nil {
		return Config{}, errors.New("configuration requires an environment reader")
	}
	var problems []error
	value := func(key, fallback string) string {
		if v := get("AIPAY_" + key); v != "" {
			return v
		}
		return fallback
	}
	duration := func(key, fallback string) time.Duration {
		v, err := time.ParseDuration(value(key, fallback))
		if err != nil || v <= 0 {
			problems = append(problems, fmt.Errorf("AIPAY_%s must be a positive duration", key))
		}
		return v
	}
	integer := func(key, fallback string, min, max int64) int64 {
		v, err := strconv.ParseInt(value(key, fallback), 10, 64)
		if err != nil || v < min || v > max {
			problems = append(problems, fmt.Errorf("AIPAY_%s must be between %d and %d", key, min, max))
		}
		return v
	}
	logs, level, logErr := logging.Load(service, get)
	problems = append(problems, logErr)
	traceConfig, traceErr := tracing.Load(get)
	problems = append(problems, traceErr)
	environment, envErr := LoadEnvironment(get)
	problems = append(problems, envErr)
	c := Config{
		Service: service, Environment: environment, Logging: logs, LogLevel: level, Tracing: traceConfig,
		RPC: RPC{
			Address: value("GRPC_ADDR", defaultAddress), ServerName: value("GRPC_SERVER_NAME", service),
			CallTimeout:           duration("RPC_CALL_TIMEOUT", "5s"),
			MaxMessageBytes:       int(integer("RPC_MAX_MESSAGE_BYTES", "1048576", 1024, 16<<20)),
			MaxConcurrentStreams:  uint32(integer("RPC_MAX_CONCURRENT_STREAMS", "128", 1, 10000)),
			MaxConnectionAge:      duration("RPC_MAX_CONNECTION_AGE", "54m"),
			MaxConnectionAgeGrace: duration("RPC_MAX_CONNECTION_AGE_GRACE", "30s"),
		},
		TLS:            TLS{CAFile: get("AIPAY_TLS_CA_FILE"), CertFile: get("AIPAY_TLS_CERT_FILE"), KeyFile: get("AIPAY_TLS_KEY_FILE"), TrustDomain: value("TLS_TRUST_DOMAIN", "aipay.internal"), ReloadInterval: duration("TLS_RELOAD_INTERVAL", "30s")},
		Database:       Database{URL: get("AIPAY_DATABASE_URL"), MaxConns: int32(integer("DATABASE_MAX_CONNS", "20", 1, 10000)), MinConns: int32(integer("DATABASE_MIN_CONNS", "2", 0, 10000)), MaxConnLifetime: duration("DATABASE_MAX_CONN_LIFETIME", "30m")},
		Redis:          Redis{URL: get("AIPAY_REDIS_URL"), PoolSize: int(integer("REDIS_POOL_SIZE", "10", 1, 10000)), Timeout: duration("REDIS_TIMEOUT", "3s")},
		StartupTimeout: duration("STARTUP_TIMEOUT", "10s"), ShutdownTimeout: duration("SHUTDOWN_TIMEOUT", "15s"), HealthTimeout: duration("HEALTH_TIMEOUT", "2s"), HealthInterval: duration("HEALTH_INTERVAL", "3s"),
	}
	if !ValidService(service) {
		problems = append(problems, errors.New("invalid service name"))
	}
	if err := ValidateAddress(c.RPC.Address); err != nil {
		problems = append(problems, err)
	}
	if strings.TrimSpace(c.RPC.ServerName) == "" || strings.ContainsAny(c.RPC.ServerName, "/:\r\n\x00") {
		problems = append(problems, errors.New("AIPAY_GRPC_SERVER_NAME must be a DNS name"))
	}
	seen := map[string]bool{}
	for _, raw := range strings.Split(get("AIPAY_RPC_ALLOWED_PEERS"), ",") {
		peer := strings.TrimSpace(raw)
		if !ValidService(peer) || seen[peer] {
			problems = append(problems, errors.New("AIPAY_RPC_ALLOWED_PEERS requires unique service names"))
			continue
		}
		seen[peer] = true
		c.RPC.AllowedPeers = append(c.RPC.AllowedPeers, peer)
	}
	if err := ValidateTLS(c.TLS); err != nil {
		problems = append(problems, err)
	}
	if err := ValidateDatabase(c.Database.URL); err != nil {
		problems = append(problems, err)
	}
	if c.Database.MinConns > c.Database.MaxConns {
		problems = append(problems, errors.New("database minimum pool size exceeds maximum"))
	}
	if c.Redis.URL != "" && !validURL(c.Redis.URL, "redis", "rediss") {
		problems = append(problems, errors.New("AIPAY_REDIS_URL must be a redis:// or rediss:// URL with a host"))
	}
	if c.RPC.MaxConnectionAge > MaxConnectionAgeLimit || c.RPC.MaxConnectionAgeGrace > c.RPC.MaxConnectionAge {
		problems = append(problems, errors.New("AIPAY_RPC_MAX_CONNECTION_AGE must be at most 1h and not shorter than its grace period"))
	}
	if c.HealthTimeout > c.StartupTimeout {
		problems = append(problems, errors.New("health timeout must not exceed startup timeout"))
	}
	return c, errors.Join(problems...)
}

func ValidateAddress(address string) error {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("AIPAY_GRPC_ADDR must be host:port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("AIPAY_GRPC_ADDR must use a port between 1 and 65535")
	}
	return nil
}

func ValidateTLS(c TLS) error {
	if strings.TrimSpace(c.CAFile) == "" || strings.TrimSpace(c.CertFile) == "" || strings.TrimSpace(c.KeyFile) == "" {
		return errors.New("AIPAY_TLS_CA_FILE, AIPAY_TLS_CERT_FILE and AIPAY_TLS_KEY_FILE are required")
	}
	if !ValidTrustDomain(c.TrustDomain) {
		return errors.New("invalid AIPAY_TLS_TRUST_DOMAIN")
	}
	return nil
}

func ValidateDatabase(raw string) error {
	if !validURL(raw, "postgres", "postgresql") {
		return errors.New("AIPAY_DATABASE_URL must be a postgres:// or postgresql:// URL with a host")
	}
	return nil
}

func validURL(raw string, schemes ...string) bool {
	u, err := url.Parse(raw)
	if err != nil || strings.TrimSpace(u.Hostname()) == "" {
		return false
	}
	for _, scheme := range schemes {
		if u.Scheme == scheme {
			return true
		}
	}
	return false
}
