package decoy

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nizartuanku/decoy/core"
	"github.com/nizartuanku/decoy/notify"
	"github.com/nizartuanku/decoy/store"
)

// capCh captures digests the dispatcher sends.
type capCh struct {
	mu      sync.Mutex
	digests []notify.Digest
}

func (c *capCh) Name() string { return "cap" }
func (c *capCh) Send(_ context.Context, d notify.Digest) error {
	c.mu.Lock()
	c.digests = append(c.digests, d)
	c.mu.Unlock()
	return nil
}
func (c *capCh) opened() []core.Finding {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []core.Finding
	for _, d := range c.digests {
		out = append(out, d.Opened...)
	}
	return out
}

func newTestRig() (*MemStore, store.Store, *TripSink, *capCh, *notify.Dispatcher) {
	dstore := NewMemStore()
	fstore := store.NewMemStore()
	cap := &capCh{}
	disp := notify.NewDispatcher(notify.Config{FlushInterval: time.Hour}, cap)
	sink := &TripSink{Store: fstore, Decoy: dstore, Disp: disp}
	return dstore, fstore, sink, cap, disp
}

func TestTokenCallbackRecordsTripAndNotifies(t *testing.T) {
	dstore, fstore, sink, cap, disp := newTestRig()
	mgr := &Manager{Store: dstore, BaseURL: "http://decoy.test"}
	dep, err := mgr.MintWebToken("password-vault-export")
	if err != nil {
		t.Fatal(err)
	}

	h := &TokenHandler{Store: dstore, Sink: sink}
	req := httptest.NewRequest("GET", "/t/"+dep.ID+"?x=1", nil)
	req.SetPathValue("id", dep.ID)
	req.RemoteAddr = "203.0.113.9:5555"
	req.Header.Set("User-Agent", "curl/8.0")
	h.ServeHTTP(httptest.NewRecorder(), req)

	trips, _ := dstore.ListTrips()
	if len(trips) != 1 {
		t.Fatalf("want 1 trip, got %d", len(trips))
	}
	if trips[0].SourceIP != "203.0.113.9" {
		t.Errorf("source ip = %q", trips[0].SourceIP)
	}

	// Finding written open directly (Path A), before any Collect.
	open, _ := fstore.ListOpen(ModuleID)
	if len(open) != 1 || open[0].Status != core.StatusOpen {
		t.Fatalf("want 1 open finding, got %+v", open)
	}
	if open[0].Severity != core.SeverityHigh {
		t.Errorf("web token trip severity = %s, want high", open[0].Severity)
	}

	disp.Close() // flushes and waits for the async send to complete
	if got := cap.opened(); len(got) != 1 {
		t.Fatalf("want 1 alerted finding, got %d", len(got))
	}
}

func TestUnknownTokenNoTrip(t *testing.T) {
	dstore, fstore, sink, _, _ := newTestRig()
	h := &TokenHandler{Store: dstore, Sink: sink}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/t/deadbeef", nil))
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/gif" {
		t.Errorf("want a 200 gif even for unknown token, got %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	if trips, _ := dstore.ListTrips(); len(trips) != 0 {
		t.Errorf("unknown token must not record a trip, got %d", len(trips))
	}
	if open, _ := fstore.ListOpen(ModuleID); len(open) != 0 {
		t.Errorf("unknown token must not create a finding")
	}
}

func TestCollectorEmitsArmedAndTrips(t *testing.T) {
	dstore := NewMemStore()
	dep := Deployment{ID: "abc", Kind: KindHoneypot, Label: "fake-db", Service: "postgres", Port: 5432}
	_ = dstore.PutDeployment(dep)
	_ = dstore.PutTrip(Trip{ID: "t1", DeploymentID: "abc", Kind: KindHoneypot, Label: "fake-db", At: time.Now(), SourceIP: "10.0.0.5"})

	c := New(dstore)
	fs, err := c.Collect(context.Background(), core.Target{Canonical: "abc"})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("want armed + 1 trip = 2 findings, got %d", len(fs))
	}
	var armed, trip bool
	for _, f := range fs {
		switch f.Check {
		case "trap.armed":
			armed = true
			if f.Severity != core.SeverityInfo {
				t.Errorf("armed severity = %s", f.Severity)
			}
		case "trap.tripped":
			trip = true
			if f.Severity != core.SeverityCritical {
				t.Errorf("honeypot trip severity = %s, want critical", f.Severity)
			}
		}
		if f.Remediation == "" {
			t.Errorf("finding %q has no remediation", f.Check)
		}
	}
	if !armed || !trip {
		t.Errorf("armed=%v trip=%v", armed, trip)
	}

	// Deleted deployment → no findings (armed auto-resolves via reconcile).
	_ = dstore.DeleteDeployment("abc")
	fs, _ = c.Collect(context.Background(), core.Target{Canonical: "abc"})
	if len(fs) != 0 {
		t.Errorf("deleted trap should yield no findings, got %d", len(fs))
	}
}

// A trip recorded in real time (Path A) must NOT be re-announced when the poll
// (Path B) re-emits it: reconcile should see it already-open, not newly-open.
func TestNoDoubleNotify(t *testing.T) {
	dstore, fstore, sink, _, _ := newTestRig()
	dep := Deployment{ID: "xyz", Kind: KindWebToken, Label: "token"}
	_ = dstore.PutDeployment(dep)
	if err := sink.Record(Trip{DeploymentID: "xyz", Kind: KindWebToken, Label: "token", SourceIP: "1.2.3.4"}); err != nil {
		t.Fatal(err)
	}

	c := New(dstore)
	fresh, _ := c.Collect(context.Background(), core.Target{Canonical: "xyz"})
	eng := store.NewEngine(fstore)
	res, err := eng.Reconcile(c.Describe(), "xyz", fresh)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.NewlyOpen {
		if f.Check == "trap.tripped" {
			t.Fatalf("trip was double-notified: it appeared in NewlyOpen on the poll after Path A already recorded it")
		}
	}
}

func TestHoneypotListenerRecordsTrip(t *testing.T) {
	dstore, _, sink, _, _ := newTestRig()
	sup := NewSupervisor(sink)
	sup.BindHost = "127.0.0.1"
	dep := Deployment{ID: "hp1", Kind: KindHoneypot, Label: "prod-ssh", Service: "ssh", Port: 0}
	_ = dstore.PutDeployment(dep)
	if err := sup.Start(dep); err != nil {
		t.Fatal(err)
	}
	defer sup.StopAll()

	addr := sup.Addr("hp1")
	if addr == nil {
		t.Fatal("no bound address")
	}
	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	// Read the fake banner, then send a probe.
	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := conn.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "SSH-2.0") {
		t.Errorf("ssh honeypot banner = %q", string(buf[:n]))
	}
	_, _ = conn.Write([]byte("SSH-2.0-libssh\r\n"))
	conn.Close()

	waitFor(t, func() bool {
		trips, _ := dstore.ListTrips()
		return len(trips) == 1
	})
	trips, _ := dstore.ListTrips()
	if trips[0].SourceIP != "127.0.0.1" {
		t.Errorf("source ip = %q", trips[0].SourceIP)
	}
	if trips[0].Detail["service"] != "ssh" {
		t.Errorf("service detail = %v", trips[0].Detail["service"])
	}
}

func TestHTTPCredentialCapture(t *testing.T) {
	body := "POST /login HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin&password=hunter2"
	u, p, ok := extractCredentials("http", body)
	if !ok || u != "admin" || p != "hunter2" {
		t.Fatalf("cred capture = %q/%q ok=%v", u, p, ok)
	}
	if _, _, ok := extractCredentials("ssh", body); ok {
		t.Errorf("ssh must not extract HTTP form creds")
	}
}

func TestBeaconDocumentsCarryToken(t *testing.T) {
	const url = "http://decoy.test/t/abc123"

	for _, format := range []string{"docx", "xlsx"} {
		data, _, _, err := BeaconDocument(format, url)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatalf("%s is not a valid zip: %v", format, err)
		}
		found := false
		for _, f := range zr.File {
			rc, _ := f.Open()
			b, _ := io.ReadAll(rc)
			rc.Close()
			if strings.Contains(string(b), url) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s does not embed the token URL", format)
		}
	}

	pdf, _, _, err := BeaconDocument("pdf", url)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF")) || !bytes.Contains(pdf, []byte(url)) {
		t.Errorf("pdf malformed or missing token")
	}
}

func TestCloudCredFileEmbedsToken(t *testing.T) {
	id, secret, err := FakeAWSKey()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, "AKIA") || len(secret) < 20 {
		t.Errorf("fake key looks wrong: %q %q", id, secret)
	}
	body := CloudCredFile(id, secret, "http://decoy.test/t/z")
	if !strings.Contains(body, "http://decoy.test/t/z") || !strings.Contains(body, id) {
		t.Errorf("cred file missing token or key")
	}
}

func TestDNSResponderRecordsResolution(t *testing.T) {
	dstore, _, sink, _, _ := newTestRig()
	_ = dstore.PutDeployment(Deployment{ID: "d1", Kind: KindDNSToken, Label: "dns-token", Host: "d1.canary.test"})

	resp := &DNSResponder{Store: dstore, Sink: sink}
	if err := resp.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer resp.Stop()

	conn, err := net.Dial("udp", resp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	q := encodeDNSQuery("d1.canary.test")
	if _, err := conn.Write(q); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 512)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(reply)
	if err != nil {
		t.Fatal(err)
	}
	if n < 12 || binary.BigEndian.Uint16(reply[6:8]) < 1 {
		t.Errorf("expected at least one answer, ancount=%d", binary.BigEndian.Uint16(reply[6:8]))
	}
	waitFor(t, func() bool {
		trips, _ := dstore.ListTrips()
		return len(trips) == 1
	})
}

// --- helpers ---------------------------------------------------------------

func encodeDNSQuery(name string) []byte {
	var b bytes.Buffer
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], 0x1234)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT
	b.Write(hdr)
	for _, label := range strings.Split(name, ".") {
		b.WriteByte(byte(len(label)))
		b.WriteString(label)
	}
	b.WriteByte(0)
	b.Write([]byte{0x00, 0x01, 0x00, 0x01}) // QTYPE A, QCLASS IN
	return b.Bytes()
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

var _ = http.StatusOK
