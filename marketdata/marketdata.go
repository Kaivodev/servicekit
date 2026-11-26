// Package marketdata collects public exchange prices and raw evidence for a
// service-owned Sink. It has no database access and makes no quoting, release
// or ledger registration decisions.
package marketdata

import (
	"context"
	"errors"
	"time"
)

// Source identifies one of the four public price feeds.
type Source string

const (
	OKX      Source = "okx"
	Binance  Source = "binance"
	Coinbase Source = "coinbase"
	Kraken   Source = "kraken"
)

// Outcome classifies the exchange response before persistence.
type Outcome string

const (
	OK                  Outcome = "ok"
	HTTPStatus          Outcome = "http_status"
	ParseError          Outcome = "parse_error"
	InsufficientSamples Outcome = "insufficient_samples"
	TransportError      Outcome = "transport_error"
)

// Observation records a canonical positive price at its scheduled UTC minute.
// CollectedAt is the UTC body-read completion time at microsecond precision.
type Observation struct {
	Source      Source
	Minute      time.Time
	Value       string
	Samples     int
	CollectedAt time.Time
}

// Raw contains the same decompressed response bytes in hashed and compressed
// form. Oversize responses retain only the first 2 MiB.
type Raw struct {
	SHA256 [32]byte
	Gzip   []byte
	Size   int
}

// Result describes one attempt. Raw is present for every received body, and
// Observation is present only for OK. Detail contains bounded diagnostic text.
type Result struct {
	Source      Source
	Minute      time.Time
	Attempt     int
	Outcome     Outcome
	Observation *Observation
	Raw         *Raw
	Detail      string
}

// ErrDuplicate indicates that the source minute is already in the domain store.
var ErrDuplicate = errors.New("source minute already recorded")

// Sink atomically appends the raw attempt and any successful minute observation.
// The collector may submit the same Result again after a write error. Implementations
// must handle repeat submissions idempotently or return an error wrapping ErrDuplicate.
// They must support concurrent calls, honor cancellation, and report ErrDuplicate
// for conflicts with an already recorded source minute.
type Sink interface {
	Record(context.Context, Result) error
}

// Schedule is supplied by the domain. Pair is optional and ordered with the
// reference first. An empty MaxDeviation disables the usable-minute gauge.
type Schedule struct {
	Sources      []Source
	Every        time.Duration
	Pair         [2]Source
	MaxDeviation string
}
