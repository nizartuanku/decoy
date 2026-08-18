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
	ID        string    `json:"id"`       // short, unguessable; used in URLs and paths
	Kind      TrapKind  `json:"kind"`     //
	Label     string    `json:"label"`    // user-facing name, e.g. "2026_salaries.xlsx"
	Port      int       `json:"port"`     // honeypot only: the bound TCP port
	Service   string    `json:"service"`  // honeypot only: ssh|rdp|http|postgres|mysql|redis|mongodb
	Host      string    `json:"host"`     // dns_token only: the trap hostname
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

// tripFinding is the finding for one recorded trip. Its fingerprint embeds the
// unique trip id, so every distinct trip is its own finding and none ever
// collapse or auto-resolve. Used by BOTH the real-time TripSink (Path A) and
// the Collector (Path B) so the two paths agree on identity.
func tripFinding(t Trip) core.Finding {
	ip := t.SourceIP
	if ip == "" {
		ip = "an unknown source"
	}
	ev := map[string]any{
		"deployment_id": t.DeploymentID,
		"kind":          string(t.Kind),
		"source_ip":     t.SourceIP,
		"at":            t.At.UTC().Format(time.RFC3339),
	}
	for k, v := range t.Detail {
		ev[k] = v
	}
	return core.Finding{
		Fingerprint: core.Fingerprint(ModuleID, t.DeploymentID, "trap.tripped", t.ID),
		Target:      t.DeploymentID, // MUST equal the scanned canonical so reconcile groups it
		Check:       "trap.tripped",
		Title:       "DECOY TRIPPED: " + t.Label + " touched by " + ip,
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
	Store store.Store   // core finding store (Upsert)
	Decoy Store         // decoy deployment/trip store
	Disp  *notify.Dispatcher // optional; nil disables notifications
	Now   func() time.Time
	NewID func(t time.Time) (string, error)
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
	f := tripFinding(t)
	rid, err := s.newID(t.At)
	if err != nil {
		return err
	}
	rec := store.Record{Finding: f}
	rec.ID = rid
	rec.Module = ModuleID
	rec.Status = core.StatusOpen
	rec.FirstSeen = t.At
	rec.LastSeen = t.At
	if err := s.Store.Upsert(rec); err != nil {
		return err
	}

	if s.Disp != nil {
		s.Disp.Enqueue(notify.Event{Kind: notify.KindOpened, Module: ModuleID, Finding: f})
	}
	return nil
}

func (s *TripSink) newID(t time.Time) (string, error) {
	if s.NewID != nil {
		return s.NewID(t)
	}
	return store.NewULID(t)
}
