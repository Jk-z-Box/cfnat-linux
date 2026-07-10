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
	if err := m.UpdateActiveSchedule(true, "interval", "2h", "03:00", 1, 1); err != nil {
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

func TestNextAutoFetchTimeCalendarModes(t *testing.T) {
	loc := time.FixedZone("TEST", 8*3600)
	from := time.Date(2026, 7, 10, 15, 30, 0, 0, loc)
	cases := []struct {
		name string
		p    Profile
		want time.Time
	}{
		{
			name: "daily",
			p:    Profile{AutoFetchMode: "daily", AutoFetchTime: "03:00"},
			want: time.Date(2026, 7, 11, 3, 0, 0, 0, loc),
		},
		{
			name: "weekly",
			p:    Profile{AutoFetchMode: "weekly", AutoFetchTime: "04:20", AutoFetchWeekday: 1},
			want: time.Date(2026, 7, 13, 4, 20, 0, 0, loc),
		},
		{
			name: "monthly",
			p:    Profile{AutoFetchMode: "monthly", AutoFetchTime: "02:15", AutoFetchMonthDay: 31},
			want: time.Date(2026, 7, 31, 2, 15, 0, 0, loc),
		},
		{
			name: "monthly clamp",
			p:    Profile{AutoFetchMode: "monthly", AutoFetchTime: "02:15", AutoFetchMonthDay: 31},
			want: time.Date(2026, 9, 30, 2, 15, 0, 0, loc),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := from
			if tc.name == "monthly clamp" {
				base = time.Date(2026, 8, 31, 3, 0, 0, 0, loc)
			}
			got, err := nextAutoFetchTime(tc.p, base)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Equal(tc.want) {
				t.Fatalf("next = %s, want %s", got, tc.want)
			}
		})
	}
}
