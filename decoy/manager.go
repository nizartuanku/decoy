package decoy

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// RandID returns an unguessable lowercase-hex id of n bytes (2n chars).
func RandID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

const b32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" // AWS access-key-id charset

// randB32 returns n characters from the AWS access-key base32 alphabet.
func randB32(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, c := range b {
		out[i] = b32Alphabet[int(c)%len(b32Alphabet)]
	}
	return string(out), nil
}

// randB64 returns the base64 encoding of nbytes random bytes (an AWS secret is
// 40 chars, i.e. 30 bytes).
func randB64(nbytes int) (string, error) {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// Manager mints traps: it generates the deployment, persists it, and (for
// artefact traps) hands back the file to place. The web console calls it. It
// does not itself register scheduler targets or start listeners — the caller
// wires those, so the Manager stays free of scheduler/net dependencies and is
// trivially testable.
type Manager struct {
	Store   Store
	BaseURL string // public base the tokens are reached at, e.g. https://decoy.example.com
	Now     func() time.Time
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// TokenURL builds the callback URL for a web-token-backed trap.
func (m *Manager) TokenURL(id string) string {
	return strings.TrimRight(m.BaseURL, "/") + "/t/" + id
}

// MintWebToken creates a bare URL token.
func (m *Manager) MintWebToken(label string) (Deployment, error) {
	return m.mint(KindWebToken, label, "")
}

// MintDocBeacon creates a web-token-backed document trap. format is docx|xlsx|pdf.
// The artefact itself is produced on download by BeaconDocument.
func (m *Manager) MintDocBeacon(label, format string) (Deployment, error) {
	switch format {
	case "docx", "xlsx", "pdf":
	default:
		return Deployment{}, errors.New("unsupported document format: " + format)
	}
	return m.mint(KindDocBeacon, label, "")
}

// MintCloudCred creates a web-token-backed fake AWS credential trap. The
// credentials file is produced by CloudCredFile.
func (m *Manager) MintCloudCred(label string) (Deployment, error) {
	return m.mint(KindCloudCred, label, "")
}

// MintDNSToken creates a DNS token under the given delegated zone. The trap
// hostname is "<id>.<zone>"; anything that resolves it trips.
func (m *Manager) MintDNSToken(label, zone string) (Deployment, error) {
	zone = strings.Trim(strings.TrimSpace(zone), ".")
	if zone == "" {
		return Deployment{}, errors.New("a delegated DNS zone is required for DNS tokens")
	}
	id, err := RandID(6)
	if err != nil {
		return Deployment{}, err
	}
	d := Deployment{
		ID:        id,
		Kind:      KindDNSToken,
		Label:     label,
		Host:      id + "." + zone,
		CreatedAt: m.now(),
	}
	if err := m.Store.PutDeployment(d); err != nil {
		return Deployment{}, err
	}
	return d, nil
}

// MintHoneypot creates a decoy-service deployment on the given port. service is
// ssh|rdp|http|postgres|mysql|redis|mongodb. The caller starts the listener.
func (m *Manager) MintHoneypot(label, service string, port int) (Deployment, error) {
	if port <= 0 || port > 65535 {
		return Deployment{}, errors.New("port must be 1..65535")
	}
	if !validService(service) {
		return Deployment{}, errors.New("unknown honeypot service: " + service)
	}
	id, err := RandID(6)
	if err != nil {
		return Deployment{}, err
	}
	d := Deployment{
		ID:        id,
		Kind:      KindHoneypot,
		Label:     label,
		Service:   service,
		Port:      port,
		CreatedAt: m.now(),
	}
	if err := m.Store.PutDeployment(d); err != nil {
		return Deployment{}, err
	}
	return d, nil
}

func (m *Manager) mint(kind TrapKind, label, _ string) (Deployment, error) {
	id, err := RandID(9)
	if err != nil {
		return Deployment{}, err
	}
	d := Deployment{
		ID:        id,
		Kind:      kind,
		Label:     label,
		CreatedAt: m.now(),
	}
	if err := m.Store.PutDeployment(d); err != nil {
		return Deployment{}, err
	}
	return d, nil
}

func validService(s string) bool {
	switch s {
	case "ssh", "rdp", "http", "postgres", "mysql", "redis", "mongodb":
		return true
	}
	return false
}
