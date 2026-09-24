// Package dashboard exposes the aggregate RTBH configuration and policy API.
package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/netip"
	"path"
	"strings"
	"time"
)

const maxBodyBytes = 1 << 20

type Config struct {
	LocalASN      uint32   `json:"local_asn"`
	RouterID      string   `json:"router_id"`
	ListenRanges  []string `json:"listen_ranges"`
	PeerGroup     string   `json:"peer_group"`
	AllowedASNs   []uint32 `json:"allowed_asns,omitempty"`
	MaxSessions   int      `json:"max_sessions"`
	DefaultPolicy string   `json:"default_policy"`
	DryRun        bool     `json:"dry_run"`
}

type Peer struct {
	Address string `json:"address"`
	ASN     uint32 `json:"asn"`
	State   string `json:"state"`
}

type PolicyMutation struct {
	Action    string     `json:"action"`
	List      string     `json:"list"`
	Prefix    string     `json:"prefix"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type Backend interface {
	Config(context.Context) (Config, error)
	UpdateConfig(context.Context, Config) error
	EstablishedPeers(context.Context) ([]Peer, error)
	MutatePolicy(context.Context, PolicyMutation) error
}

type Authorizer func(*http.Request) bool

type handler struct {
	backend   Backend
	authorize Authorizer
	mux       *http.ServeMux
	static    fs.FS
}

func NewHandler(backend Backend, authorize Authorizer, static ...fs.FS) http.Handler {
	h := &handler{backend: backend, authorize: authorize, mux: http.NewServeMux()}
	if len(static) > 0 {
		h.static = static[0]
	}
	for _, prefix := range []string{"/api", "/api/v1"} {
		h.mux.HandleFunc("GET "+prefix+"/config", h.getConfig)
		h.mux.HandleFunc("PUT "+prefix+"/config", h.putConfig)
		h.mux.HandleFunc("GET "+prefix+"/peers", h.getPeers)
		h.mux.HandleFunc("POST "+prefix+"/block", h.mutate("blocklist"))
		h.mux.HandleFunc("POST "+prefix+"/whitelist", h.mutate("whitelist"))
	}
	h.mux.HandleFunc("GET /api/", func(w http.ResponseWriter, _ *http.Request) { writeError(w, http.StatusNotFound, "not found") })
	h.mux.HandleFunc("GET /", h.index)
	return h
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if h.backend == nil || h.authorize == nil || !h.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	h.mux.ServeHTTP(w, r)
}

func (h *handler) index(w http.ResponseWriter, r *http.Request) {
	if h.static == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<!doctype html><html><body><main><h1>RTBH Panel</h1></main></body></html>")
		return
	}
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if name == "." || name == "" {
		name = "index.html"
	}
	if _, err := fs.Stat(h.static, name); err != nil {
		if path.Ext(name) != "" {
			http.NotFound(w, r)
			return
		}
		name = "index.html"
	}
	http.ServeFileFS(w, r, h.static, name)
}

func (h *handler) getConfig(w http.ResponseWriter, r *http.Request) {
	config, err := h.backend.Config(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "config unavailable")
		return
	}
	writeJSON(w, http.StatusOK, config)
}

func (h *handler) getPeers(w http.ResponseWriter, r *http.Request) {
	peers, err := h.backend.EstablishedPeers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "peer status unavailable")
		return
	}
	writeJSON(w, http.StatusOK, peers)
}

func (h *handler) putConfig(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Apply  bool   `json:"apply"`
		Config Config `json:"config"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := request.Config.validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.Apply {
		if err := h.backend.UpdateConfig(r.Context(), request.Config); err != nil {
			writeError(w, http.StatusInternalServerError, "configuration not applied")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"applied": request.Apply, "dry_run": !request.Apply, "config": request.Config})
}

func (h *handler) mutate(list string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Action    string     `json:"action"`
			Prefix    string     `json:"prefix"`
			Apply     bool       `json:"apply"`
			ExpiresAt *time.Time `json:"expires_at,omitempty"`
		}
		if err := decodeJSON(w, r, &request); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		prefix, err := netip.ParsePrefix(request.Prefix)
		if err != nil || prefix != prefix.Masked() || (request.Action != "add" && request.Action != "remove") {
			writeError(w, http.StatusBadRequest, "action and canonical CIDR are required")
			return
		}
		if request.ExpiresAt != nil && (list != "blocklist" || request.Action != "add" || !request.ExpiresAt.After(time.Now())) {
			writeError(w, http.StatusBadRequest, "expires_at requires a future blocklist add")
			return
		}
		mutation := PolicyMutation{Action: request.Action, List: list, Prefix: request.Prefix, ExpiresAt: request.ExpiresAt}
		if request.Apply {
			if err := h.backend.MutatePolicy(r.Context(), mutation); err != nil {
				writeError(w, http.StatusInternalServerError, "policy not applied")
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"applied": request.Apply, "dry_run": !request.Apply, "mutation": mutation})
	}
}

func (config Config) validate() error {
	if config.LocalASN == 0 || config.MaxSessions < 1 {
		return errors.New("local_asn and positive max_sessions are required")
	}
	routerID, err := netip.ParseAddr(config.RouterID)
	if err != nil || !routerID.Is4() {
		return errors.New("router_id must be IPv4")
	}
	if strings.TrimSpace(config.PeerGroup) == "" || config.DefaultPolicy != "reject" || len(config.ListenRanges) == 0 {
		return errors.New("peer_group, listen_ranges, and default_policy reject are required")
	}
	for _, raw := range config.ListenRanges {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix != prefix.Masked() {
			return errors.New("listen_ranges must contain canonical CIDRs")
		}
	}
	for _, asn := range config.AllowedASNs {
		if asn == 0 {
			return errors.New("allowed_asns cannot contain zero")
		}
	}
	return nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("invalid JSON body")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON value")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
