// Command egress-proxy serves the namespace-local market CONNECT proxy.
// It never terminates TLS or loads exchange credentials.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/Kaivodev/servicekit/config"
	"github.com/Kaivodev/servicekit/egressproxy"
)

var version = "dev"

func settings(get func(string) string) (string, egressproxy.Config, error) {
	var cfg egressproxy.Config
	env, err := config.LoadEnvironment(get)
	cidrs := get("AIPAY_EGRESS_PROXY_TEST_ONLY_ALLOW_CIDRS")
	if cidrs != "" && !env.IsDevelopment() {
		return "", cfg, errors.Join(err, errors.New("AIPAY_EGRESS_PROXY_TEST_ONLY_ALLOW_CIDRS requires AIPAY_ENVIRONMENT=development"))
	}
	if err != nil {
		return "", cfg, err
	}
	cfg.Environment = env
	if cidrs != "" {
		for s := range strings.SplitSeq(cidrs, ",") {
			p, err := netip.ParsePrefix(strings.TrimSpace(s))
			if err != nil {
				return "", cfg, errors.New("invalid AIPAY_EGRESS_PROXY_TEST_ONLY_ALLOW_CIDRS prefix")
			}
			cfg.AllowCIDRs = append(cfg.AllowCIDRs, p)
		}
	}
	if raw := get("AIPAY_EGRESS_PROXY_ALLOWED_HOSTS"); raw != "" {
		for h := range strings.SplitSeq(raw, ",") {
			cfg.AllowedHosts = append(cfg.AllowedHosts, strings.TrimSpace(h))
		}
	} else {
		return "", cfg, errors.New("AIPAY_EGRESS_PROXY_ALLOWED_HOSTS is required")
	}
	cfg.MaxConnections = 64
	if raw := get("AIPAY_EGRESS_PROXY_MAX_CONNECTIONS"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 1024 {
			return "", cfg, errors.New("AIPAY_EGRESS_PROXY_MAX_CONNECTIONS must be between 1 and 1024")
		}
		cfg.MaxConnections = n
	}
	addr := get("AIPAY_EGRESS_PROXY_ADDR")
	if addr == "" {
		addr = ":3128"
	}
	return addr, cfg, nil
}

func run(ctx context.Context, args []string, get func(string) string, out io.Writer, log *slog.Logger) error {
	if len(args) == 0 {
		args = []string{"serve"}
	}
	if len(args) != 1 {
		return errors.New("usage: egress-proxy [serve | version]")
	}
	switch args[0] {
	case "version":
		return json.NewEncoder(out).Encode(map[string]string{"service": "egress-proxy", "version": version})
	case "serve":
		addr, cfg, err := settings(get)
		if err != nil {
			return err
		}
		server, err := egressproxy.New(cfg, log)
		if err != nil {
			return err
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		return server.Serve(ctx, ln)
	default:
		return errors.New("usage: egress-proxy [serve | version]")
	}
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Getenv, os.Stdout, log); err != nil {
		log.Error("egress-proxy failed", "error", err)
		os.Exit(1)
	}
}
