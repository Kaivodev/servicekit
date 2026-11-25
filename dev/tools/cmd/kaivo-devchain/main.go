package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/Kaivodev/servicekit/dev/tools/internal/devchain"
)

func run(args []string) error {
	if os.Getenv("AIPAY_ENVIRONMENT") != "development" {
		return errors.New("devchain requires AIPAY_ENVIRONMENT=development")
	}
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configured := os.Getenv("AIPAY_DEVCHAIN_LISTEN")
	address := configured
	if address == "" {
		address = "127.0.0.1:8545"
	}
	listen := flags.String("listen", address, "listener IP:port")
	path := flags.String("dataset", os.Getenv("AIPAY_DEVCHAIN_DATASET"), "chain dataset")
	finalized := flags.String("finalized", os.Getenv("AIPAY_DEVCHAIN_FINALIZED"), "override finalized block height")
	if len(args) == 0 || args[0] != "serve" || flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return errors.New("usage: kaivo-devchain serve -dataset FILE [-listen IP:PORT] [-finalized HEIGHT]")
	}
	host, _, err := net.SplitHostPort(*listen)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || (!ip.IsLoopback() && *listen != configured) {
		return errors.New("devchain requires a literal loopback listener or an explicitly configured container IP listener")
	}
	data, err := devchain.Load(*path, *finalized)
	if err != nil {
		return err
	}
	server := http.Server{Addr: *listen, Handler: data, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	return server.ListenAndServe()
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
