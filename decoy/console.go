package decoy

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/nizartuanku/decoy/license"
)

// Caps are Decoy's per-tier limits. Unlike the generic license.Limits (one
// MaxTargets), Decoy needs three: token count, honeypot count, and whether the
// advanced traps (DNS token, cloud credential) are unlocked. 0 = unlimited.
type Caps struct {
	MaxTokens    int
	MaxHoneypots int
	Advanced     bool
}

// DefaultCaps mirrors the pricing table: Free 3 tokens + 1 honeypot, no
// advanced; Pro 50 + 10 + advanced; Team unlimited + advanced.
var DefaultCaps = map[license.Tier]Caps{
	license.TierFree: {MaxTokens: 3, MaxHoneypots: 1, Advanced: false},
	license.TierPro:  {MaxTokens: 50, MaxHoneypots: 10, Advanced: true},
	license.TierTeam: {MaxTokens: 0, MaxHoneypots: 0, Advanced: true},
}

// Console serves the /api/decoy/* endpoints: mint, list, delete traps, download
// artefacts, and read the trip log. It is transport for the Manager; the cmd
// wires OnCreate/OnDelete to register scheduler targets and start/stop honeypot
// listeners, keeping this handler free of scheduler/net dependencies.
type Console struct {
	Store    Store
	Manager  *Manager
	Caps     func() Caps            // current tier's caps
	DNSZone  string                 // configured delegated zone ("" = DNS tokens unavailable)
	OnCreate func(Deployment) error // register target + start listener; may reject (e.g. port in use)
	OnDelete func(Deployment)       // stop listener + unregister
}

// Register mounts the console routes plus the token callback on the mux.
func (c *Console) Register(mux *http.ServeMux, tokens *TokenHandler) {
	mux.Handle("GET /t/{id}", tokens)
	mux.HandleFunc("GET /api/decoy/deployments", c.handleList)
	mux.HandleFunc("POST /api/decoy/deployments", c.handleCreate)
	mux.HandleFunc("DELETE /api/decoy/deployments", c.handleDelete)
	mux.HandleFunc("GET /api/decoy/trips", c.handleTrips)
	mux.HandleFunc("GET /api/decoy/artifact", c.handleArtifact)
}

type deploymentView struct {
	Deployment
	URL string `json:"url,omitempty"`
}

func (c *Console) view(d Deployment) deploymentView {
	v := deploymentView{Deployment: d}
	if isTokenBacked(d.Kind) {
		v.URL = c.Manager.TokenURL(d.ID)
	}
	return v
}

func (c *Console) handleList(w http.ResponseWriter, r *http.Request) {
	deps, err := c.Store.ListDeployments()
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]deploymentView, 0, len(deps))
	for _, d := range deps {
		out = append(out, c.view(d))
	}
	writeJSON(w, http.StatusOK, map[string]any{"deployments": out, "dns_zone": c.DNSZone})
}

type createRequest struct {
	Kind    string `json:"kind"`    // web_token | doc_beacon | honeypot | dns_token | cloud_cred
	Label   string `json:"label"`   //
	Format  string `json:"format"`  // doc_beacon: docx|xlsx|pdf
	Service string `json:"service"` // honeypot: ssh|rdp|http|...
	Port    int    `json:"port"`    // honeypot
}

func (c *Console) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	req.Label = strings.TrimSpace(req.Label)
	if req.Label == "" {
		httpErr(w, http.StatusBadRequest, "label is required")
		return
	}
	caps := c.Caps()

	kind := TrapKind(req.Kind)
	if kind == KindHoneypot {
		if !underHoneypotCap(c.Store, caps) {
			httpErr(w, http.StatusForbidden, "honeypot limit reached for your tier — upgrade to add more")
			return
		}
	} else {
		if (kind == KindDNSToken || kind == KindCloudCred) && !caps.Advanced {
			httpErr(w, http.StatusForbidden, "DNS and cloud-credential traps require Pro or Team")
			return
		}
		if !underTokenCap(c.Store, caps) {
			httpErr(w, http.StatusForbidden, "token limit reached for your tier — upgrade to add more")
			return
		}
	}

	var (
		dep Deployment
		err error
	)
	switch kind {
	case KindWebToken:
		dep, err = c.Manager.MintWebToken(req.Label)
	case KindDocBeacon:
		if req.Format == "" {
			req.Format = "docx"
		}
		dep, err = c.Manager.MintDocBeacon(req.Label, req.Format)
	case KindCloudCred:
		dep, err = c.Manager.MintCloudCred(req.Label)
	case KindDNSToken:
		if c.DNSZone == "" {
			httpErr(w, http.StatusBadRequest, "no DNS zone is delegated to this instance; set -dns-zone to enable DNS tokens")
			return
		}
		dep, err = c.Manager.MintDNSToken(req.Label, c.DNSZone)
	case KindHoneypot:
		dep, err = c.Manager.MintHoneypot(req.Label, req.Service, req.Port)
	default:
		httpErr(w, http.StatusBadRequest, "unknown trap kind: "+req.Kind)
		return
	}
	if err != nil {
		httpErr(w, http.StatusBadRequest, err.Error())
		return
	}

	if c.OnCreate != nil {
		if err := c.OnCreate(dep); err != nil {
			// Roll back the deployment if the listener/registration failed.
			_ = c.Store.DeleteDeployment(dep.ID)
			httpErr(w, http.StatusConflict, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, c.view(dep))
}

func (c *Console) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		httpErr(w, http.StatusBadRequest, "id is required")
		return
	}
	dep, ok, err := c.Store.GetDeployment(id)
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		httpErr(w, http.StatusNotFound, "no such deployment")
		return
	}
	if c.OnDelete != nil {
		c.OnDelete(dep)
	}
	if err := c.Store.DeleteDeployment(id); err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func (c *Console) handleTrips(w http.ResponseWriter, r *http.Request) {
	trips, err := c.Store.ListTrips()
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if trips == nil {
		trips = []Trip{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"trips": trips})
}

// handleArtifact returns the placeable file for a doc-beacon or cloud-cred trap:
// GET /api/decoy/artifact?id=<id>&format=<docx|xlsx|pdf>
func (c *Console) handleArtifact(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	dep, ok, err := c.Store.GetDeployment(id)
	if err != nil || !ok {
		httpErr(w, http.StatusNotFound, "no such deployment")
		return
	}
	tokenURL := c.Manager.TokenURL(dep.ID)
	switch dep.Kind {
	case KindDocBeacon:
		format := r.URL.Query().Get("format")
		if format == "" {
			format = "docx"
		}
		data, fname, ctype, err := BeaconDocument(format, tokenURL)
		if err != nil {
			httpErr(w, http.StatusBadRequest, err.Error())
			return
		}
		serveDownload(w, data, downloadName(dep.Label, fname), ctype)
	case KindCloudCred:
		akid, secret, err := FakeAWSKey()
		if err != nil {
			httpErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		body := CloudCredFile(akid, secret, tokenURL)
		serveDownload(w, []byte(body), "credentials", "text/plain")
	default:
		httpErr(w, http.StatusBadRequest, "this trap has no downloadable artefact")
	}
}

func underTokenCap(s Store, caps Caps) bool {
	if caps.MaxTokens == 0 {
		return true
	}
	deps, _ := s.ListDeployments()
	n := 0
	for _, d := range deps {
		if d.Kind != KindHoneypot {
			n++
		}
	}
	return n < caps.MaxTokens
}

func underHoneypotCap(s Store, caps Caps) bool {
	if caps.MaxHoneypots == 0 {
		return true
	}
	deps, _ := s.ListDeployments()
	n := 0
	for _, d := range deps {
		if d.Kind == KindHoneypot {
			n++
		}
	}
	return n < caps.MaxHoneypots
}

func downloadName(label, fallback string) string {
	label = strings.TrimSpace(label)
	if label == "" {
		return fallback
	}
	return label
}

func serveDownload(w http.ResponseWriter, data []byte, filename, ctype string) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
