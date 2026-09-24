package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeBackend struct {
	config    Config
	peers     []Peer
	updates   int
	mutations []PolicyMutation
}

func (f *fakeBackend) Config(context.Context) (Config, error) { return f.config, nil }
func (f *fakeBackend) UpdateConfig(_ context.Context, config Config) error {
	f.config = config
	f.updates++
	return nil
}
func (f *fakeBackend) EstablishedPeers(context.Context) ([]Peer, error) { return f.peers, nil }
func (f *fakeBackend) MutatePolicy(_ context.Context, mutation PolicyMutation) error {
	f.mutations = append(f.mutations, mutation)
	return nil
}

func authorized(*http.Request) bool { return true }

func TestConfigReportsBackendDryRunMode(t *testing.T) {
	backend := &fakeBackend{config: Config{DryRun: true}}
	response := httptest.NewRecorder()
	NewHandler(backend, authorized).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"dry_run":true`) {
		t.Fatalf("response=%d body=%s", response.Code, response.Body.String())
	}
}

func TestConfigUpdateDefaultsToDryRunAndRejectsNeighborFields(t *testing.T) {
	backend := &fakeBackend{}
	handler := NewHandler(backend, authorized)
	body := `{"config":{"local_asn":65000,"router_id":"192.0.2.1","listen_ranges":["198.51.100.0/24"],"peer_group":"edge","allowed_asns":[64512],"max_sessions":8,"default_policy":"reject"}}`
	request := httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || backend.updates != 0 {
		t.Fatalf("dry-run response=%d updates=%d body=%s", response.Code, backend.updates, response.Body.String())
	}
	var result struct {
		DryRun bool `json:"dry_run"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || !result.DryRun {
		t.Fatalf("response = %s, err=%v", response.Body.String(), err)
	}

	bad := strings.Replace(body, `"local_asn":65000`, `"local_asn":65000,"neighbor_ip":"192.0.2.9"`, 1)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(bad)))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("per-neighbor field status=%d, want 400", response.Code)
	}
}

func TestConfigApplyRequiresExplicitTrue(t *testing.T) {
	backend := &fakeBackend{}
	handler := NewHandler(backend, authorized)
	body := `{"apply":true,"config":{"local_asn":65000,"router_id":"192.0.2.1","listen_ranges":["198.51.100.0/24"],"peer_group":"edge","max_sessions":8,"default_policy":"reject"}}`
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(body)))
	if response.Code != http.StatusOK || backend.updates != 1 {
		t.Fatalf("apply response=%d updates=%d body=%s", response.Code, backend.updates, response.Body.String())
	}
}

func TestWhitelistMutationDryRunThenApply(t *testing.T) {
	backend := &fakeBackend{}
	handler := NewHandler(backend, authorized)
	for _, test := range []struct {
		body string
		want int
	}{
		{`{"action":"add","prefix":"203.0.113.7/32"}`, 0},
		{`{"action":"add","prefix":"203.0.113.7/32","apply":true}`, 1},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/whitelist", strings.NewReader(test.body)))
		if response.Code != http.StatusOK || len(backend.mutations) != test.want {
			t.Fatalf("response=%d mutations=%d body=%s", response.Code, len(backend.mutations), response.Body.String())
		}
	}
	if backend.mutations[0].List != "whitelist" {
		t.Fatalf("mutation=%#v", backend.mutations[0])
	}
}

func TestPeersAndSecurityBoundary(t *testing.T) {
	backend := &fakeBackend{peers: []Peer{{Address: "198.51.100.1", ASN: 64512, State: "ESTABLISHED"}}}
	handler := NewHandler(backend, authorized)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/peers", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "ESTABLISHED") {
		t.Fatalf("peer response=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("X-Content-Type-Options") != "nosniff" || response.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("security headers missing")
	}

	denied := NewHandler(backend, nil)
	response = httptest.NewRecorder()
	denied.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/peers", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("nil authorizer status=%d, want 401", response.Code)
	}
}

func TestDashboardHasNoPerNeighborForm(t *testing.T) {
	response := httptest.NewRecorder()
	NewHandler(&fakeBackend{}, authorized).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusOK || strings.Contains(strings.ToLower(response.Body.String()), "neighbor_ip") {
		t.Fatalf("dashboard status=%d body=%s", response.Code, response.Body.String())
	}
}
