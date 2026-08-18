package decoy

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Supervisor owns the honeypot TCP listeners (Path A). Each honeypot deployment
// binds one port; any connection to it is recorded as a trip and alerted. The
// responders greet like tempting infrastructure but never grant access — a
// honeypot serves nothing, it only listens and records.
type Supervisor struct {
	Sink     *TripSink
	BindHost string // interface to bind; "" → all interfaces (a honeypot must be reachable)

	mu        sync.Mutex
	listeners map[string]net.Listener
	deps      map[string]Deployment
	wg        sync.WaitGroup
}

// NewSupervisor builds a honeypot supervisor writing trips to sink.
func NewSupervisor(sink *TripSink) *Supervisor {
	return &Supervisor{
		Sink:      sink,
		listeners: make(map[string]net.Listener),
		deps:      make(map[string]Deployment),
	}
}

// Start binds and begins accepting on the deployment's port. Returns the bind
// error (typically "address already in use") so the caller can surface it.
func (s *Supervisor) Start(d Deployment) error {
	ln, err := net.Listen("tcp", net.JoinHostPort(s.BindHost, strconv.Itoa(d.Port)))
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listeners[d.ID] = ln
	s.deps[d.ID] = d
	s.mu.Unlock()

	s.wg.Add(1)
	go s.accept(d, ln)
	return nil
}

// Stop closes one honeypot's listener.
func (s *Supervisor) Stop(id string) {
	s.mu.Lock()
	ln := s.listeners[id]
	delete(s.listeners, id)
	delete(s.deps, id)
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
}

// StopAll closes every listener and waits for accept loops to drain.
func (s *Supervisor) StopAll() {
	s.mu.Lock()
	for id, ln := range s.listeners {
		_ = ln.Close()
		delete(s.listeners, id)
		delete(s.deps, id)
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// Addr returns the actual bound address for a honeypot (useful in tests where
// port 0 picks a free port).
func (s *Supervisor) Addr(id string) net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ln := s.listeners[id]; ln != nil {
		return ln.Addr()
	}
	return nil
}

func (s *Supervisor) accept(d Deployment, ln net.Listener) {
	defer s.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		go s.handle(d, conn)
	}
}

func (s *Supervisor) handle(d Deployment, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Greet like the service so a scanner banner-grabs something plausible,
	// then read what the caller sends.
	if banner := serviceBanner(d.Service); banner != "" {
		_, _ = conn.Write([]byte(banner))
	}
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	first := string(buf[:n])

	detail := map[string]any{
		"service":     d.Service,
		"port":        d.Port,
		"first_bytes": sanitize(first),
	}
	if user, pass, ok := extractCredentials(d.Service, first); ok {
		detail["captured_username"] = user
		detail["captured_password"] = pass
	}

	ip := ""
	if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
		ip = host
	} else {
		ip = conn.RemoteAddr().String()
	}

	_ = s.Sink.Record(Trip{
		DeploymentID: d.ID,
		Kind:         KindHoneypot,
		Label:        d.Label,
		SourceIP:     ip,
		Detail:       detail,
	})
}

// serviceBanner returns a plausible opening greeting for a decoy service.
func serviceBanner(service string) string {
	switch service {
	case "ssh":
		return "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
	case "http":
		return "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n" +
			"<!doctype html><title>Admin Login</title>" +
			"<form method=post><input name=username><input name=password type=password>" +
			"<button>Sign in</button></form>"
	case "postgres":
		return "" // Postgres server speaks first only after startup; stay quiet, capture the startup packet
	case "mysql":
		return "\x4a\x00\x00\x00\x0a5.7.42\x00" // truncated MySQL greeting header + version
	case "redis":
		return "" // Redis waits for a command; capture it
	case "mongodb":
		return ""
	case "rdp":
		return "" // RDP is binary; capture the connection request
	}
	return ""
}

// extractCredentials makes a best-effort attempt to pull a username/password an
// attacker submitted to the fake HTTP admin panel (a POSTed form body).
func extractCredentials(service, first string) (user, pass string, ok bool) {
	if service != "http" || !strings.HasPrefix(first, "POST") {
		return "", "", false
	}
	body := first
	if i := strings.Index(first, "\r\n\r\n"); i >= 0 {
		body = first[i+4:]
	}
	vals := parseForm(body)
	u := firstNonEmpty(vals["username"], vals["user"], vals["email"], vals["login"])
	p := firstNonEmpty(vals["password"], vals["pass"], vals["pwd"])
	if u == "" && p == "" {
		return "", "", false
	}
	return u, p, true
}

func parseForm(body string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(strings.TrimSpace(body), "&") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			out[strings.ToLower(strings.TrimSpace(kv[0]))] = kv[1]
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// sanitize trims and truncates captured bytes and strips control characters so
// a hostile payload can't corrupt logs or the dashboard.
func sanitize(s string) string {
	if len(s) > 512 {
		s = s[:512]
	}
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\t' || (r >= 0x20 && r != 0x7f) {
			b.WriteRune(r)
		} else {
			b.WriteByte('.')
		}
	}
	return strings.TrimSpace(b.String())
}
