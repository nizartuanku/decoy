package decoy

import (
	"net"
	"net/http"
	"strings"
)

// onePixelGIF is a 1x1 transparent GIF returned by the token callback. It makes
// a web token a valid image source (so document beacons and <img> tokens work)
// and gives an attacker nothing interesting back.
var onePixelGIF = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00,
	0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02,
	0x44, 0x01, 0x00, 0x3b,
}

// TokenHandler serves the web-token callback at /t/{id}. When {id} matches a
// live token-backed deployment it records a trip (Path A) and, either way,
// returns an innocuous 1x1 GIF so the caller learns nothing. Register it on the
// Decoy server's ExtraRoutes: mux.Handle("GET /t/{id}", h).
type TokenHandler struct {
	Store Store
	Sink  *TripSink
}

func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if dep, ok, err := h.Store.GetDeployment(id); err == nil && ok && isTokenBacked(dep.Kind) {
		_ = h.Sink.Record(Trip{
			DeploymentID: dep.ID,
			Kind:         dep.Kind,
			Label:        dep.Label,
			SourceIP:     ClientIP(r),
			Detail: map[string]any{
				"user_agent": r.UserAgent(),
				"path":       r.URL.Path,
				"query":      r.URL.RawQuery,
				"referer":    r.Referer(),
			},
		})
	}
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(onePixelGIF)
}

func isTokenBacked(k TrapKind) bool {
	return k == KindWebToken || k == KindDocBeacon || k == KindCloudCred
}

// ClientIP extracts the best-guess source IP from a request, honouring a single
// hop of X-Forwarded-For (the left-most entry) when Decoy runs behind a proxy.
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
