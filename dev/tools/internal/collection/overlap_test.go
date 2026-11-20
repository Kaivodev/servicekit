package collection

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	events "github.com/Kaivodev/protobuf/gen/go/aipay/events/v1"
	"google.golang.org/grpc/peer"
)

type pageReader struct {
	events.UnimplementedEventStreamServiceServer
	page *events.ListEventsResponse
}

func (r pageReader) ListEvents(context.Context, *events.ListEventsRequest) (*events.ListEventsResponse, error) {
	return r.page, nil
}
func TestOverlappingReadsPreservePage(t *testing.T) {
	control := filepath.Join(t.TempDir(), "overlap.json")
	plan, _ := json.Marshal(map[string]any{"sequence": 17, "expires": time.Now().Add(time.Second * 4)})
	if e := os.WriteFile(control, plan, 0600); e != nil {
		t.Fatal(e)
	}
	page := &events.ListEventsResponse{Events: []*events.SignedEvent{{Sequence: 17, EventId: "receipt"}}}
	r := OverlappingReads(pageReader{page: page}, func(context.Context) (string, error) { return "ledger", nil }, control)
	result := make(chan error, 2)
	read := func(ctx context.Context, port int) {
		ctx = peer.NewContext(ctx, &peer.Peer{Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}})
		v, e := r.ListEvents(ctx, &events.ListEventsRequest{AfterSequence: 16, Stream: Stream, Limit: 100})
		if e == nil && v != page {
			t.Error("modified the original page")
		}
		result <- e
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	go read(cancelled, 1)
	if e := <-result; e == nil {
		t.Fatal("cancelled reader counted")
	}
	go read(t.Context(), 2)
	go read(t.Context(), 3)
	for range 2 {
		if e := <-result; e != nil {
			t.Fatal(e)
		}
	}
	var proof OverlapProof
	b, e := os.ReadFile(control + ".proof")
	if e != nil || json.Unmarshal(b, &proof) != nil || proof.Sequence != 17 || proof.EventID != "receipt" || len(proof.SHA256) != 64 || proof.Readers != 2 {
		t.Fatal("missing matching proof", e)
	}
}
