package decoy

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nizartuanku/decoy/core"
	"github.com/nizartuanku/decoy/notify"
	"github.com/nizartuanku/decoy/store"
)

func burstSink(fstore store.Store, dstore *MemStore, window time.Duration) *TripSink {
	n := 0
	return &TripSink{
		Store: fstore, Decoy: dstore, DigestWindow: window,
		NewID: func(tm time.Time) (string, error) { n++; return fmt.Sprintf("id-%04d", n), nil },
	}
}

func touch(t *testing.T, s *TripSink, at time.Time, ip, path string) {
	t.Helper()
	if err := s.Record(Trip{
		DeploymentID: "dep-1",
		Kind:         KindWebToken,
		Label:        "backup keys",
		At:           at,
		SourceIP:     ip,
		Detail:       map[string]any{"path": path, "ua": "curl/8"},
	}); err != nil {
		t.Fatal(err)
	}
}

var t0 = time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)

// P-4 (5 Sep 2026): the README promised "never a flood" while every touch
// minted its own finding — 20 identical requests were 20 findings and 20
// notifications. The alert must collapse; the evidence must not.
func TestDigest_RepeatedTouchesAreOneFindingButAllTripsKept(t *testing.T) {
	fstore, dstore := store.NewMemStore(), NewMemStore()
	s := burstSink(fstore, dstore, 15*time.Minute)
	for i := 0; i < 20; i++ {
		touch(t, s, t0.Add(time.Duration(i)*time.Second), "203.0.113.9", "/admin")
	}
	open, _ := fstore.ListOpen(ModuleID)
	if len(open) != 1 {
		t.Fatalf("20 identical touches must be 1 finding, got %d", len(open))
	}
	if got := evidenceCount(open[0].Evidence); got != 20 {
		t.Fatalf("count must reach 20, got %d", got)
	}
	trips, _ := dstore.ListTrips()
	if len(trips) != 20 {
		t.Fatalf("every trip is evidence and must be kept: got %d", len(trips))
	}
	if open[0].FirstSeen != t0 {
		t.Errorf("FirstSeen must stay at the first touch, got %v", open[0].FirstSeen)
	}
	if want := t0.Add(19 * time.Second); open[0].LastSeen != want {
		t.Errorf("LastSeen must track the newest touch, got %v", open[0].LastSeen)
	}
}

// A different source is a different intruder. It must never be folded into
// somebody else's burst, however noisy that one is.
func TestDigest_DifferentSourceIsItsOwnFinding(t *testing.T) {
	fstore, dstore := store.NewMemStore(), NewMemStore()
	s := burstSink(fstore, dstore, 15*time.Minute)
	for i := 0; i < 5; i++ {
		touch(t, s, t0.Add(time.Duration(i)*time.Second), "203.0.113.9", "/admin")
	}
	touch(t, s, t0.Add(6*time.Second), "198.51.100.4", "/admin")
	open, _ := fstore.ListOpen(ModuleID)
	if len(open) != 2 {
		t.Fatalf("two sources must be two findings, got %d", len(open))
	}
}

// Past the window it is a new incident, and it must alert again. Without this
// the fix would trade a flood for silence — the worse failure for an intrusion
// alert.
func TestDigest_TouchAfterWindowAlertsAgain(t *testing.T) {
	fstore, dstore := store.NewMemStore(), NewMemStore()
	s := burstSink(fstore, dstore, 15*time.Minute)
	touch(t, s, t0, "203.0.113.9", "/admin")
	touch(t, s, t0.Add(31*time.Minute), "203.0.113.9", "/admin")
	open, _ := fstore.ListOpen(ModuleID)
	if len(open) != 2 {
		t.Fatalf("a touch past the window is a new incident: got %d findings", len(open))
	}
}

// Path A (sink) and Path B (poll) must derive the same identity, or the poll
// would resurrect what the sink folded together.
func TestDigest_CollectorFoldsIdenticallyToSink(t *testing.T) {
	fstore, dstore := store.NewMemStore(), NewMemStore()
	if err := dstore.PutDeployment(Deployment{ID: "dep-1", Label: "backup keys", Kind: KindWebToken}); err != nil {
		t.Fatal(err)
	}
	s := burstSink(fstore, dstore, 15*time.Minute)
	for i := 0; i < 7; i++ {
		touch(t, s, t0.Add(time.Duration(i)*time.Second), "203.0.113.9", "/admin")
	}
	c := New(dstore)
	tgt, err := c.ValidateTarget("dep-1")
	if err != nil {
		t.Fatal(err)
	}
	found, err := c.Collect(context.Background(), tgt)
	if err != nil {
		t.Fatal(err)
	}
	var trips []int
	fps := map[string]bool{}
	for _, f := range found {
		if f.Check == "trap.tripped" {
			trips = append(trips, evidenceCount(f.Evidence))
			fps[f.Fingerprint] = true
		}
	}
	if len(trips) != 1 || trips[0] != 7 {
		t.Fatalf("collector must fold 7 trips into one finding of count 7, got %v", trips)
	}
	open, _ := fstore.ListOpen(ModuleID)
	if len(open) != 1 || !fps[open[0].Fingerprint] {
		t.Fatal("sink and collector must agree on the fingerprint")
	}
}

// The headline claim: twenty requests, one alert. Findings collapsing is only
// half of it — the notifier must not fire per touch either.
func TestDigest_OneNotificationPerBurst(t *testing.T) {
	fstore, dstore := store.NewMemStore(), NewMemStore()
	cap := &capCh{}
	disp := notify.NewDispatcher(notify.Config{FlushInterval: time.Hour}, cap)
	n := 0
	s := &TripSink{
		Store: fstore, Decoy: dstore, Disp: disp, DigestWindow: 15 * time.Minute,
		NewID: func(tm time.Time) (string, error) { n++; return fmt.Sprintf("id-%04d", n), nil },
	}
	for i := 0; i < 20; i++ {
		touch(t, s, t0.Add(time.Duration(i)*time.Second), "203.0.113.9", "/admin")
	}
	// A second intruder must still get through immediately.
	touch(t, s, t0.Add(30*time.Second), "198.51.100.4", "/admin")
	disp.Close() // flushes and waits for the async send

	opened := cap.opened()
	if len(opened) != 2 {
		t.Fatalf("want 2 alerts (one per burst), got %d", len(opened))
	}
}

// P-4b (6 Sep 2026): the burst notification was correct in number and wrong in
// content — it was the FIRST touch, so it could not say how many followed.
// "touched 20 times" lived only on the dashboard. When the window closes, one
// summary must go out carrying the count.
func TestDigest_WindowCloseSendsOneCountedSummary(t *testing.T) {
	fstore, dstore := store.NewMemStore(), NewMemStore()
	cap := &capCh{}
	disp := notify.NewDispatcher(notify.Config{FlushInterval: time.Hour}, cap)
	n := 0
	s := &TripSink{
		Store: fstore, Decoy: dstore, Disp: disp, DigestWindow: 15 * time.Minute,
		NewID: func(tm time.Time) (string, error) { n++; return fmt.Sprintf("id-%04d", n), nil },
	}
	for i := 0; i < 20; i++ {
		touch(t, s, t0.Add(time.Duration(i)*time.Second), "203.0.113.9", "/admin")
	}
	// Nothing extra before the window closes: the first alert is the only one.
	if got := s.FlushDigests(t0.Add(time.Minute)); len(got) != 0 {
		t.Fatalf("no summary is due before the window closes, got %d", len(got))
	}
	// t0 is 10:00:00, so the bucket ends at 10:15:00.
	if got := s.FlushDigests(t0.Add(20 * time.Minute)); len(got) != 1 {
		t.Fatalf("one closed burst must produce one summary, got %d", len(got))
	}
	disp.Close()

	opened := cap.opened()
	if len(opened) != 2 {
		t.Fatalf("20 identical touches must be exactly 2 notifications (first + summary), got %d", len(opened))
	}
	var summary *core.Finding
	for i := range opened {
		if opened[i].Evidence["summary"] == true {
			summary = &opened[i]
		}
	}
	if summary == nil {
		t.Fatal("no summary notification was sent")
	}
	if got := evidenceCount(summary.Evidence); got != 20 {
		t.Fatalf("summary count must be 20, got %d", got)
	}
	if !strings.Contains(summary.Title, "20 times") {
		t.Fatalf("the summary must say how many times: %q", summary.Title)
	}
	if !strings.Contains(summary.Title, "203.0.113.9") || !strings.Contains(summary.Title, "15 min") {
		t.Fatalf("the summary must name the source and the window: %q", summary.Title)
	}
}

// Two intruders are two bursts, so two first alerts and two summaries — never
// one merged count that hides that a second address was involved.
func TestDigest_TwoSourcesGiveFourNotifications(t *testing.T) {
	fstore, dstore := store.NewMemStore(), NewMemStore()
	cap := &capCh{}
	disp := notify.NewDispatcher(notify.Config{FlushInterval: time.Hour}, cap)
	n := 0
	s := &TripSink{
		Store: fstore, Decoy: dstore, Disp: disp, DigestWindow: 15 * time.Minute,
		NewID: func(tm time.Time) (string, error) { n++; return fmt.Sprintf("id-%04d", n), nil },
	}
	for i := 0; i < 20; i++ {
		touch(t, s, t0.Add(time.Duration(i)*time.Second), "203.0.113.9", "/admin")
	}
	for i := 0; i < 20; i++ {
		touch(t, s, t0.Add(time.Duration(i)*time.Second), "198.51.100.4", "/admin")
	}
	if got := s.FlushDigests(t0.Add(20 * time.Minute)); len(got) != 2 {
		t.Fatalf("two bursts must produce two summaries, got %d", len(got))
	}
	disp.Close()
	if got := len(cap.opened()); got != 4 {
		t.Fatalf("two intruders must be 4 notifications (2 first + 2 summaries), got %d", got)
	}
}

// A single touch is complete on its own. Sending a "1 times" summary fifteen
// minutes later would be noise, which is the thing this whole mechanism exists
// to prevent.
func TestDigest_SingleTouchGetsNoSummary(t *testing.T) {
	fstore, dstore := store.NewMemStore(), NewMemStore()
	cap := &capCh{}
	disp := notify.NewDispatcher(notify.Config{FlushInterval: time.Hour}, cap)
	n := 0
	s := &TripSink{
		Store: fstore, Decoy: dstore, Disp: disp, DigestWindow: 15 * time.Minute,
		NewID: func(tm time.Time) (string, error) { n++; return fmt.Sprintf("id-%04d", n), nil },
	}
	touch(t, s, t0, "203.0.113.9", "/admin")
	if got := s.FlushDigests(t0.Add(20 * time.Minute)); len(got) != 0 {
		t.Fatalf("a burst of one needs no summary, got %d", len(got))
	}
	disp.Close()
	if got := len(cap.opened()); got != 1 {
		t.Fatalf("one touch must be exactly one notification, got %d", got)
	}
}
