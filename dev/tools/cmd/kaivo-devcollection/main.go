package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Kaivodev/servicekit/config"
	"github.com/Kaivodev/servicekit/dev/tools/internal/collection"
	"github.com/Kaivodev/servicekit/mtls"
	"github.com/Kaivodev/servicekit/postgres"
	"github.com/Kaivodev/servicekit/rpc"
)

func run(ctx context.Context, args []string) error {
	get := os.Getenv
	if get("AIPAY_ENVIRONMENT") != "development" || get("AIPAY_DEVCOLLECTION_CHAIN_ID") != "31337" {
		return errors.New("collection requires development environment and chain ID 31337")
	}
	const address = "127.0.0.1:9106"
	if len(args) == 1 && args[0] == "healthcheck" {
		// A controller-side probe using the ledger identity, never a server credential.
		probe, err := config.LoadProbe("collection", address, get)
		if err != nil {
			return err
		}
		return rpc.Probe(ctx, "ledger", "collection", probe)
	}
	receipt := len(args) == 4 && args[0] == "receipt" && (args[1] == "add" || args[1] == "replay")
	if !receipt && !(len(args) == 1 && (args[0] == "serve" || args[0] == "head" || args[0] == "migrate")) {
		return errors.New("usage: kaivo-devcollection serve | head | migrate | receipt {add|replay} SCENARIO RECEIPT_KEY")
	}
	cfg, err := config.Load("collection", address, get)
	if err != nil {
		return err
	}
	startup, cancel := context.WithTimeout(ctx, cfg.StartupTimeout)
	defer cancel()
	db, err := postgres.Open(startup, "collection", cfg.Database)
	if err != nil {
		return err
	}
	defer db.Close()
	switch args[0] {
	case "migrate":
		return collection.Migrate(startup, db)
	case "head":
		seq, digest, err := collection.Head(startup, db)
		if err == nil {
			fmt.Printf("%d %x\n", seq, digest)
		}
		return err
	}
	signer, err := collection.FileSigner(startup, get)
	if err != nil {
		return err
	}
	if receipt {
		claim, err := collection.ReadReceipt(args[2], args[3])
		if err != nil {
			return err
		}
		eventID, err := collection.Append(startup, db, signer, args[3], claim, args[1] == "replay")
		if err == nil {
			fmt.Println(eventID)
		}
		return err
	}
	reader, err := collection.NewReader(db)
	if err != nil {
		return err
	}
	material, err := mtls.Load(cfg.TLS, "collection")
	if err != nil {
		return err
	}
	check := func(ctx context.Context) error { _, _, err := collection.Head(ctx, db); return err }
	if err = check(startup); err != nil {
		return err
	}
	source := collection.OverlappingReads(reader, material.Peer, get("AIPAY_DEVCOLLECTION_OVERLAP_FILE"))
	server, err := collection.NewServer(cfg, material, source, check)
	if err != nil {
		return err
	}
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	go material.Watch(runCtx, cfg.TLS.ReloadInterval, slog.Default())
	return server.Run(runCtx)
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
