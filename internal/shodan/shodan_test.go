package shodan

import (
	"testing"
	"time"

	"github.com/cfnat-linux/cfnat-linux/internal/config"
)

func TestBuildQuery(t *testing.T) {
	profile := Profile{Ports: "443,8443", Countries: "sg, jp", ASNs: "16509,AS13335", Keywords: "cloudflare\nForbidden"}
	got := BuildQuery(profile)
	want := `port:443,8443 country:SG,JP asn:AS16509,AS13335 cloudflare Forbidden`
	if got != want {
		t.Fatalf("query = %q, want %q", got, want)
	}
}

func TestRawQueryOverridesBuilder(t *testing.T) {
	profile := Profile{Ports: "443", RawQuery: `port:443 country:SG "cloudflare"`}
	got := BuildQuery(profile)
	if got != profile.RawQuery {
		t.Fatalf("query = %q", got)
	}
}

func TestUpdateActiveScheduleOnlyChangesActiveProfile(t *testing.T) {
	m := New(config.ShodanConfig{Enabled: true, DataDir: t.TempDir()})
	store := StoreConfig{ActiveProfile: "SG", Profiles: map[string]Profile{
		"SG": {Name: "SG", FetchCount: 100},
		"JP": {Name: "JP", FetchCount: 200, AutoFetchEnabled: false, AutoFetchInterval: "12h"},
	}}
	if err := m.SaveConfig(store); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateActiveSchedule(true, "2h"); err != nil {
		t.Fatal(err)
	}
	got, err := m.Config()
	if err != nil {
		t.Fatal(err)
	}
	if !got.Profiles["SG"].AutoFetchEnabled || got.Profiles["SG"].AutoFetchInterval != "2h0m0s" {
		t.Fatalf("SG schedule = %+v", got.Profiles["SG"])
	}
	if got.Profiles["JP"].AutoFetchEnabled || got.Profiles["JP"].AutoFetchInterval != "12h" {
		t.Fatalf("JP schedule changed = %+v", got.Profiles["JP"])
	}
	if _, err := time.Parse(time.RFC3339, got.Profiles["SG"].NextAutoFetchAt); err != nil {
		t.Fatalf("next auto fetch invalid: %q", got.Profiles["SG"].NextAutoFetchAt)
	}
}
