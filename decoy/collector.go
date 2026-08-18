package decoy

import (
	"context"
	"strings"
	"time"

	"github.com/nizartuanku/decoy/core"
)

// Collector is Path B: the poll-driven backstop. It reads persisted state and
// re-emits, every scan, one armed-finding per live deployment plus one finding
// per recorded trip. This keeps the reconcile engine's view consistent —
// deleting a trap auto-resolves its armed finding, while trips (re-emitted
// forever because they are persisted) stay open until archived. The real-time
// TripSink carries the urgent signal; this keeps the books.
type Collector struct {
	store Store
}

// New builds the Decoy collector over a decoy Store.
func New(s Store) *Collector { return &Collector{store: s} }

// Describe returns the module metadata. The interval is generous: the
// real-time path handles urgency, so the poll only needs to reconcile health
// (a deleted trap, a restored one) periodically.
func (c *Collector) Describe() core.ModuleInfo {
	return core.ModuleInfo{
		ID:              ModuleID,
		Name:            "Decoy",
		Version:         "0.1.0",
		TargetKind:      "trap",
		DefaultInterval: 15 * time.Minute,
		ResolveAfter:    1,
	}
}

// ValidateTarget canonicalises a deployment id. Traps are created through the
// Decoy console endpoints (which mint secrets and artefacts); this exists so a
// minted deployment can be registered with the scheduler as a target and
// restored on restart. The id must be non-empty; existence is checked at scan
// time (a deleted trap yields no findings and auto-resolves).
func (c *Collector) ValidateTarget(raw string) (core.Target, error) {
	id := strings.TrimSpace(raw)
	if id == "" {
		return core.Target{}, &core.IngestError{Field: "target", Reason: "empty deployment id"}
	}
	return core.Target{Raw: raw, Canonical: id}, nil
}

// Collect emits the armed finding and every trip for one deployment. An absent
// (deleted) deployment returns nil so reconcile auto-resolves its armed
// finding; trips are re-emitted so they never resolve.
func (c *Collector) Collect(ctx context.Context, t core.Target) ([]core.Finding, error) {
	dep, ok, err := c.store.GetDeployment(t.Canonical)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	out := []core.Finding{armedFinding(dep)}

	trips, err := c.store.ListTripsFor(dep.ID)
	if err != nil {
		return nil, err
	}
	for _, tr := range trips {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if tr.Label == "" {
			tr.Label = dep.Label
		}
		out = append(out, tripFinding(tr))
	}
	return out, nil
}

// Diff defers to the core's fingerprint-based diff.
func (c *Collector) Diff(previous, current []core.Finding) []core.Change { return nil }
