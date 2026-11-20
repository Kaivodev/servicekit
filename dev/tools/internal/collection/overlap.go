package collection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	events "github.com/Kaivodev/protobuf/gen/go/aipay/events/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// OverlappingReads coordinates two real ledger replicas at the same cursor. Both
// RPCs return the page already obtained from the normal authorized reader.
func OverlappingReads(reader events.EventStreamServiceServer, identity func(context.Context) (string, error), control string) events.EventStreamServiceServer {
	if control == "" {
		return reader
	}
	return &overlapReader{EventStreamServiceServer: reader, identity: identity, control: control}
}

type overlapReader struct {
	events.EventStreamServiceServer
	identity func(context.Context) (string, error)
	control  string
	mu       sync.Mutex
	first    *waitingRead
}
type waitingRead struct {
	peer, digest string
	seq          uint64
	ctx          context.Context
	ready        chan struct{}
}
type OverlapProof struct {
	EventID  string `json:"event_id"`
	Sequence uint64 `json:"sequence"`
	SHA256   string `json:"signed_envelope_sha256"`
	Readers  int    `json:"readers"`
}

func (r *overlapReader) ListEvents(ctx context.Context, q *events.ListEventsRequest) (*events.ListEventsResponse, error) {
	result, e := r.EventStreamServiceServer.ListEvents(ctx, q)
	if e != nil || len(result.GetEvents()) == 0 {
		return result, e
	}
	name, e := r.identity(ctx)
	if e != nil {
		return nil, status.Error(codes.PermissionDenied, "missing reader identity")
	}
	if name != "ledger" {
		return result, nil
	}
	data, e := os.ReadFile(r.control)
	if errors.Is(e, os.ErrNotExist) {
		return result, nil
	}
	var plan struct {
		Sequence uint64
		Expires  time.Time
	}
	if e != nil || json.Unmarshal(data, &plan) != nil {
		return nil, status.Error(codes.Unavailable, "invalid overlap control")
	}
	event := result.Events[0]
	if !time.Now().Before(plan.Expires) || event.GetSequence() != plan.Sequence {
		return result, nil
	}
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return nil, status.Error(codes.Unavailable, "missing connection")
	}
	b, e := proto.MarshalOptions{Deterministic: true}.Marshal(event)
	if e != nil {
		return nil, status.Error(codes.Internal, "cannot identify envelope")
	}
	h := sha256.Sum256(b)
	digest := hex.EncodeToString(h[:])
	addr := p.Addr.String()
	r.mu.Lock()
	first := r.first
	if first != nil && first.seq == plan.Sequence && first.ctx.Err() == nil && first.peer != addr && first.digest == digest {
		proof := OverlapProof{event.GetEventId(), plan.Sequence, digest, 2}
		data, _ := json.Marshal(proof)
		f, e := os.CreateTemp(filepath.Dir(r.control), ".overlap-")
		if e == nil {
			defer os.Remove(f.Name())
			_, e = f.Write(data)
			ce := f.Close()
			if e == nil {
				e = ce
			}
			if e == nil {
				e = os.Rename(f.Name(), r.control+".proof")
			}
		}
		if e != nil {
			r.mu.Unlock()
			return nil, status.Error(codes.Unavailable, "cannot record overlapping reads")
		}
		close(first.ready)
		r.first = nil
		r.mu.Unlock()
		return result, nil
	}
	if first != nil && first.ctx.Err() == nil && first.seq == plan.Sequence {
		r.mu.Unlock()
		return nil, status.Error(codes.Unavailable, "waiting for a different reader")
	}
	w := &waitingRead{peer: addr, digest: digest, seq: plan.Sequence, ctx: ctx, ready: make(chan struct{})}
	r.first = w
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		if r.first == w {
			r.first = nil
		}
		r.mu.Unlock()
	}()
	select {
	case <-w.ready:
		return result, nil
	case <-ctx.Done():
		return nil, status.FromContextError(ctx.Err()).Err()
	case <-time.After(time.Until(plan.Expires)):
		return nil, status.Error(codes.DeadlineExceeded, "overlap expired")
	}
}
