package feed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
)

func TestValidatePublicURL(t *testing.T) {
	for _, tt := range []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{name: "public ipv4", raw: "http://93.184.216.34/feed.txt"},
		{name: "public ipv6", raw: "http://[2001:4860:4860::8888]/feed"},
		{name: "https public", raw: "https://93.184.216.34/feed.txt"},
		{name: "loopback", raw: "http://127.0.0.1/feed", wantErr: true},
		{name: "ipv6 loopback", raw: "http://[::1]/feed", wantErr: true},
		{name: "private rfc1918", raw: "http://10.0.0.5/feed", wantErr: true},
		{name: "private cgnat", raw: "http://100.64.0.1/feed", wantErr: true},
		{name: "link local metadata", raw: "http://169.254.169.254/latest/meta-data", wantErr: true},
		{name: "unspecified", raw: "http://0.0.0.0/feed", wantErr: true},
		{name: "ipv6 ula", raw: "http://[fd00::1]/feed", wantErr: true},
		{name: "ipv6 link local", raw: "http://[fe80::1]/feed", wantErr: true},
		{name: "file scheme", raw: "file:///etc/passwd", wantErr: true},
		{name: "ftp scheme", raw: "ftp://93.184.216.34/feed", wantErr: true},
		{name: "missing host", raw: "http:///feed", wantErr: true},
		{name: "userinfo", raw: "http://user@93.184.216.34/feed", wantErr: true},
		{name: "empty", raw: "", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePublicURL(context.Background(), tt.raw)
			if tt.wantErr && err == nil {
				t.Fatalf("ValidatePublicURL(%q) unexpectedly succeeded", tt.raw)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("ValidatePublicURL(%q) failed: %v", tt.raw, err)
			}
		})
	}
}

func TestFetchRejectsLoopbackHTTPSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("192.0.2.1/32\n"))
	}))
	defer srv.Close()
	if _, err := Fetch(context.Background(), srv.URL, false); err == nil {
		t.Fatal("Fetch accepted a loopback HTTP source")
	}
}

func TestPublicHTTPClientRejectsLoopbackRedirectAndDial(t *testing.T) {
	client := publicHTTPClient()
	redirect, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1/feed", nil)
	if err := client.CheckRedirect(redirect, nil); err == nil {
		t.Fatal("redirect to loopback was accepted")
	}
	transport := client.Transport.(*http.Transport)
	if _, err := transport.DialContext(context.Background(), "tcp", "127.0.0.1:80"); err == nil {
		t.Fatal("dial to loopback was accepted")
	}
}

func TestIsPublicIP(t *testing.T) {
	for _, tt := range []struct {
		raw  string
		want bool
	}{
		{"93.184.216.34", true},
		{"2001:4860:4860::8888", true},
		{"127.0.0.1", false},
		{"10.1.2.3", false},
		{"172.16.0.9", false},
		{"192.168.1.1", false},
		{"169.254.1.1", false},
		{"224.0.0.1", false},
		{"255.255.255.255", false},
		{"192.88.99.1", false},
	} {
		if got := isPublicIP(netip.MustParseAddr(tt.raw)); got != tt.want {
			t.Fatalf("isPublicIP(%s)=%v want %v", tt.raw, got, tt.want)
		}
	}
}

func TestValidateURLFormatRejectsAmbiguousAuthority(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1@93.184.216.34/feed",
		"http://example.com\\@127.0.0.1/feed",
		"http://example.com:bad/feed",
	} {
		if _, err := validateURLFormat(raw); err == nil {
			t.Errorf("validateURLFormat(%q) unexpectedly succeeded", raw)
		}
	}
	parsed, err := url.Parse("https://example.com/feed")
	if err != nil || parsed.Hostname() != "example.com" {
		t.Fatalf("control URL parse = %#v err=%v", parsed, err)
	}
}

func TestValidateURLFormatMessages(t *testing.T) {
	trimmed, err := validateURLFormat("  https://example.com/feed  ")
	if err != nil || trimmed != "https://example.com/feed" {
		t.Fatalf("validateURLFormat trimmed = %q err=%v", trimmed, err)
	}
	if _, err := validateURLFormat("notaurl"); err == nil {
		t.Fatal("validateURLFormat accepted non-URL input")
	}
}
