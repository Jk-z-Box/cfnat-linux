package cloudflare

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/cfnat-linux/cfnat-linux/internal/config"
)

func TestSyncCreatesBeforeDeletingManagedRecords(t *testing.T) {
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []record{
				{ID: "old", Type: "A", Name: "best.example.com", Content: "192.0.2.1", Comment: "managed-by:cfnat-linux"},
				{ID: "user", Type: "A", Name: "best.example.com", Content: "192.0.2.9", Comment: "user-record"},
			}})
		default:
			json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"id": "ok"}})
		}
	}))
	defer server.Close()
	os.Setenv("TEST_CF_TOKEN", "secret")
	defer os.Unsetenv("TEST_CF_TOKEN")
	cfg := config.DNSConfig{Enabled: true, ZoneID: "zone", RecordName: "best.example.com", RecordType: "A", SyncCount: 1, TTL: 1, TokenEnv: "TEST_CF_TOKEN", Marker: "managed-by:cfnat-linux"}
	client := New(cfg)
	client.baseURL = server.URL
	if err := client.Sync(context.Background(), []netip.Addr{netip.MustParseAddr("192.0.2.2")}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(methods, "|")
	if joined != "GET /zones/zone/dns_records|POST /zones/zone/dns_records|DELETE /zones/zone/dns_records/old" {
		t.Fatalf("unexpected calls: %s", joined)
	}
	if strings.Contains(joined, "/user") {
		t.Fatal("unmanaged record was deleted")
	}
}
