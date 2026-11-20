package collection

import (
	"context"
	"errors"
	"log/slog"
	"slices"

	eventsv1 "github.com/Kaivodev/protobuf/gen/go/aipay/events/v1"
	"github.com/Kaivodev/servicekit/authz"
	"github.com/Kaivodev/servicekit/config"
	"github.com/Kaivodev/servicekit/mtls"
	"github.com/Kaivodev/servicekit/rpc"
	"github.com/Kaivodev/servicekit/signing"
	"google.golang.org/grpc"
)

func FileSigner(ctx context.Context, get func(string) string) (signing.Signer, error) {
	cfg, err := signing.Load(get)
	if err != nil {
		return nil, err
	}
	if cfg.Backend != signing.BackendFile || cfg.KeyID != "collection-dev" {
		return nil, errors.New("collection requires its persistent collection-dev file signer")
	}
	signer, err := signing.Open(ctx, cfg, nil)
	if err != nil {
		return nil, err
	}
	keys, err := signing.LoadJWKS(get("AIPAY_DEVCOLLECTION_JWKS_FILE"))
	if err != nil {
		return nil, err
	}
	key, ok := keys.Lookup(signer.KeyID())
	if !ok || !signer.PublicKey().Equal(key) {
		return nil, errors.New("collection signer differs from pinned public key")
	}
	return signer, nil
}

func NewServer(cfg config.Config, material *mtls.Material, reader eventsv1.EventStreamServiceServer, check rpc.Check) (*rpc.Server, error) {
	peers := slices.Clone(cfg.RPC.AllowedPeers)
	slices.Sort(peers)
	if !slices.Equal(peers, []string{"ledger", "reconciliation"}) {
		return nil, errors.New("collection peers must be ledger and reconciliation")
	}
	desc := eventsv1.File_aipay_events_v1_event_stream_proto.Services().ByName("EventStreamService")
	policies, err := authz.LoadPolicies(desc)
	if err != nil {
		return nil, err
	}
	log := slog.Default()
	authorizer, err := authz.New(authz.Options{Service: "collection", Policies: policies, Peer: material.Peer, Log: log})
	if err != nil {
		return nil, err
	}
	options := rpc.ServerOptions{
		Authorizer: authorizer, RPC: cfg.RPC,
		HealthTimeout: cfg.HealthTimeout, HealthInterval: cfg.HealthInterval,
		ShutdownTimeout: cfg.ShutdownTimeout,
	}
	return rpc.NewServer(options, material, log, log, map[string]rpc.Check{"collection": check, "tls": material.Check}, func(server grpc.ServiceRegistrar) {
		eventsv1.RegisterEventStreamServiceServer(server, reader)
	})
}
