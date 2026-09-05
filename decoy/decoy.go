// Package decoy is the third Sentinel product: self-hosted canary tokens and
// honeypots that stay silent until something touches them.
//
// It is the framework's event-driven case. CertWatch and ASM poll: the
// scheduler runs Collect() on an interval. A canary trap trips at an arbitrary
// moment and the alert must fire in seconds. Decoy reconciles the two with TWO
// write paths into the same store, WITHOUT changing the core:
//
//   - Path A (real-time): token callbacks, honeypot listeners, and the DNS
//     responder record a trip and notify immediately. See TripSink.
//   - Path B (poll, backstop): the Collector re-emits every armed trap and
//     every persisted trip so the reconcile engine keeps the dashboard and
//     health view consistent. See Collector.
//
// Everything else — store, reconcile, notifier, dashboard shell, licensing —
// is reused unchanged.
package decoy

import (
	"fmt"
	"time"

	"github.com/nizartuanku/decoy/core"
	"github.com/nizartuanku/decoy/notify"
	"github.com/nizartuanku/decoy/store"
)

// ModuleID is the module id used across findings and the scheduler.
const ModuleID = "decoy"

// TrapKind enumerates the trap primitives.
type TrapKind string

const (
	KindWebToken  TrapKind = "web_token"  // an unguessable URL that trips when fetched
	KindDocBeacon TrapKind = "doc_beacon" // a document embedding a web token
	KindHoneypot  TrapKind = "honeypot"   // a decoy TCP service
	KindDNSToken  TrapKind = "dns_token"  // a hostname that trips when resolved
	KindCloudCred TrapKind = "cloud_cred" // a fake credential file embedding a web token
)

// Deployment is one armed trap the user has planted. Web tokens, doc beacons,
// and cloud-cred traps all trip through the web-token callback (they differ
// only in the artefact handed to the user); honeypots and DNS tokens trip
// through their own listeners.
type Deployment struct {
	ID        string    `json:"id"`      // short, unguessable; used in URLs and paths
	Kind      TrapKind  `json:"kind"`    //
	Label     string    `json:"label"`   // user-facing name, e.g. "2026_salaries.xlsx"
	Port      int       `json:"port"`    // honeypot only: the bound TCP port
	Service   string    `json:"service"` // honeypot only: ssh|rdp|http|postgres|mysql|redis|mongodb
	Host      string    `json:"host"`    // dns_token only: the trap hostname
	CreatedAt time.Time `json:"created_at"`
}

// Severity of a trip depends on the trap: a touched honeypot or credential is a
// near-certain intrusion (critical); a fetched web token or resolved DNS token
// is high (could be an over-eager crawler in rare cases, still worth a look).
func (k TrapKind) tripSeverity() core.Severity {
	switch k {
	case KindHoneypot, KindCloudCred:
		return core.SeverityCritical
	default:
		return core.SeverityHigh
	}
}

// Trip is one recorded interaction with a trap — an immutable incident fact.
type Trip struct {
	ID           string         `json:"id"`
	DeploymentID string         `json:"deployment_id"`
	Kind         TrapKind       `json:"kind"`
	Label        string         `json:"label"`
	At           time.Time      `json:"at"`
	SourceIP     string         `json:"source_ip"`
	Detail       map[string]any `json:"detail,omitempty"` // UA, path, port, creds tried, first bytes
}

// Store persists deployments and trips. A SQLite implementation ships in the
// store package; an in-memory one (MemStore) is used by tests and ephemeral
// runs. Kept separate from the core store.Store, like verify.Store.
type Store interface {
	PutDeployment(d Deployment) error
	GetDeployment(id string) (Deployment, bool, error)
	ListDeployments() ([]Deployment, error)
	DeleteDeployment(id string) error

	PutTrip(t Trip) error
	ListTrips() ([]Trip, error)
	ListTripsFor(deploymentID string) ([]Trip, error)
}

// armedFinding is the "trap is in place" info finding for a deployment. It
// auto-resolves when the deployment is deleted (Collect stops emitting it).
// Path B only — an armed trap is a steady state, not an event.
func armedFinding(d Deployment) core.Finding {
	return core.Finding{
		Fingerprint: core.Fingerprint(ModuleID, d.ID, "trap.armed", ""),
		Target:      d.ID, // MUST equal the scanned canonical so reconcile groups it
		Check:       "trap.armed",
		Title:       "Trap armed: " + d.Label + " (" + string(d.Kind) + ")",
		Severity:    core.SeverityInfo,
		Remediation: "Leave it in place. You'll be alerted the moment anything touches it.",
		Evidence: map[string]any{
			"deployment_id": d.ID,
			"kind":          string(d.Kind),
			"service":       d.Service,
			"port":          d.Port,
			"host":          d.Host,
		},
	}
}

// DefaultDigestWindow is how long repeated touches of the same trap, from the
// same source, at the same thing count as ONE incident. A scan or a
// brute-force runs for minutes and would otherwise raise an alert per request;
// a visit hours later is a separate event and must alert again. Fifteen
// minutes is the default, not a law — see TripSink.DigestWindow.
const DefaultDigestWindow = 15 * time.Minute

func digestWindow(w time.Duration) time.Duration {
	if w <= 0 {
		return DefaultDigestWindow
	}
	return w
}

// burstKey names the actor and the act: the same source touching the same
// thing on the same trap. A DIFFERENT source IP is a different intruder and
// never folds into an existing burst, however busy the first one is.
func burstKey(t Trip) string {
	var what string
	for _, k := range []string{"path", "port", "service", "query", "name"} {
		if v, ok := t.Detail[k]; ok {
			what = fmt.Sprint(v)
			break
		}
	}
	return t.DeploymentID + "|" + t.SourceIP + "|" + string(t.Kind) + "|" + what
}

// tripDiscriminator buckets a trip into a fixed window. Bucketing by wall
// clock rather than by "time since the last touch" is deliberate: it is
// computable from the trip alone, so the real-time sink (Path A) and the
// poll-driven collector (Path B) derive the SAME identity without sharing
// state. The cost is a boundary — two touches either side of it are two
// findings — which is the honest failure direction for an intrusion alert.
func tripDiscriminator(t Trip, window time.Duration) string {
	bucket := t.At.UTC().Truncate(digestWindow(window)).Format(time.RFC3339)
	return burstKey(t) + "@" + bucket
}

// tripFinding is the finding for a single recorded trip (count 1).
func tripFinding(t Trip, window time.Duration) core.Finding {
	return tripFindingN(t, window, 1, t.At, t.At)
}

// tripFindingN is the finding for a burst of touches that share one
// discriminator: same trap, same source, same thing touched, same window. The
// individual trips are still stored, every one of them — this collapses the
// ALERT, never the evidence.
func tripFindingN(t Trip, window time.Duration, count int, first, last time.Time) core.Finding {
	ip := t.SourceIP
	if ip == "" {
		ip = "an unknown source"
	}
	ev := map[string]any{
		"deployment_id": t.DeploymentID,
		"kind":          string(t.Kind),
		"source_ip":     t.SourceIP,
		"at":            t.At.UTC().Format(time.RFC3339),
		"count":         count,
		"first_seen":    first.UTC().Format(time.RFC3339),
		"last_seen":     last.UTC().Format(time.RFC3339),
		"digest_window": digestWindow(window).String(),
	}
	for k, v := range t.Detail {
		ev[k] = v
	}
	title := "DECOY TRIPPED: " + t.Label + " touched by " + ip
	if count > 1 {
		title = fmt.Sprintf("DECOY TRIPPED: %s touched %d times by %s", t.Label, count, ip)
	}
	return core.Finding{
		Fingerprint: core.Fingerprint(ModuleID, t.DeploymentID, "trap.tripped", tripDiscriminator(t, window)),
		Target:      t.DeploymentID, // MUST equal the scanned canonical so reconcile groups it
		Check:       "trap.tripped",
		Title:       title,
		Severity:    t.Kind.tripSeverity(),
		Remediation: "Investigate " + ip + " now. A legitimate user has no reason to touch this — treat it as a possible intrusion.",
		Evidence:    ev,
	}
}

// TripSink is Path A. Any real-time ingest source (web callback, honeypot
// listener, DNS responder) calls Record when a trap is touched. Record
// persists the trip, writes the finding to the store as already-open (so it
// shows on the dashboard instantly and the later Collect does NOT re-notify
// it), and fires an immediate notification.
type TripSink struct {
	Store store.Store        // core finding store (Upsert)
	Decoy Store              // decoy deployment/trip store
	Disp  *notify.Dispatcher // optional; nil disables notifications
	Now   func() time.Time
	NewID func(t time.Time) (string, error)
	// DigestWindow collapses repeated touches of the same trap, by the same
	// source, at the same thing into one finding and ONE notification. Zero
	// means DefaultDigestWindow.
	DigestWindow time.Duration
}

// Record handles one trip end-to-end (Path A). It is safe to call from any
// goroutine (listeners run concurrently).
func (s *TripSink) Record(t Trip) error {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	if t.At.IsZero() {
		t.At = now()
	}
	if t.ID == "" {
		id, err := s.newID(t.At)
		if err != nil {
			return err
		}
		t.ID = id
	}
	if err := s.Decoy.PutTrip(t); err != nil {
		return err
	}

	// Write the finding directly as open — NOT through reconcile, which would
	// auto-resolve the deployment's other trips. A trip is append-only.
	//
	// Repeated touches inside one digest window share a fingerprint, so this
	// Upsert updates the existing finding instead of adding another: the count
	// climbs, LastSeen moves, and NO second notification is sent. That is the
	// whole of "never a flood" — twenty requests are one alert, and all twenty
	// trips remain in the store as evidence.
	f := tripFinding(t, s.DigestWindow)
	first, last := t.At, t.At
	count := 1
	rid := ""
	repeat := false
	if prev, ok, err := s.Store.Get(ModuleID, f.Fingerprint); err == nil && ok {
		repeat = true
		rid = prev.ID
		count = evidenceCount(prev.Evidence) + 1
		first = prev.FirstSeen
		if last.Before(prev.LastSeen) {
			last = prev.LastSeen
		}
		f = tripFindingN(t, s.DigestWindow, count, first, last)
	}
	if rid == "" {
		id, err := s.newID(t.At)
		if err != nil {
			return err
		}
		rid = id
	}
	rec := store.Record{Finding: f}
	rec.ID = rid
	rec.Module = ModuleID
	rec.Status = core.StatusOpen
	rec.FirstSeen = first
	rec.LastSeen = last
	if err := s.Store.Upsert(rec); err != nil {
		return err
	}

	// One burst, one notification. A repeat inside the window is already on the
	// dashboard with a rising count; paging someone again adds noise, not news.
	if s.Disp != nil && !repeat {
		s.Disp.Enqueue(notify.Event{Kind: notify.KindOpened, Module: ModuleID, Finding: f})
	}
	return nil
}

// evidenceCount reads the burst count off a stored finding. It survives the
// JSON round-trip through SQLite, where an int comes back as float64.
func evidenceCount(ev map[string]any) int {
	switch v := ev["count"].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return 1
}

func (s *TripSink) newID(t time.Time) (string, error) {
	if s.NewID != nil {
		return s.NewID(t)
	}
	return store.NewULID(t)
}
