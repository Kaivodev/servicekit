package main

import (
	"context"
	"io"
	"os/exec"
	"time"
)

func (k *kubeEnvironment) applyMarket() {
	require(k.seed != "", "set KAIVO_STAGING_SEED to the staging seed executable")
	ctx, cancel := context.WithTimeout(k.ctx, 90*time.Second)
	defer cancel()
	producer := exec.CommandContext(ctx, k.seed, "market")
	consumer := k.bin(ctx, "apply", "--server-side", "--field-manager=kaivo-staging-market", "--force-conflicts", "-f", "-")
	pipe, e := producer.StdoutPipe()
	check(e)
	consumer.Stdin = pipe
	producer.Stderr = io.Discard
	consumer.Stderr = io.Discard
	require(producer.Start() == nil, "could not start market seed")
	err := consumer.Run()
	pipe.Close()
	if err != nil {
		cancel()
	}
	seedErr := producer.Wait()
	require(err == nil && seedErr == nil, "market seed or server-side apply failed")
}
func (k *kubeEnvironment) refreshMarket() {
	for _, service := range []string{"payment", "ledger", "reconciliation"} {
		k.requireDevelopment(service)
	}
	k.applyMarket()
	k.waitProjection()
}

func (k *kubeEnvironment) waitProjection() {
	k.pause(k.syncDelay)
}
