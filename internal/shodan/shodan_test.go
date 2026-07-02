package shodan

import "testing"

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
