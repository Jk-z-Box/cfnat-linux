package update

import "testing"

func TestIsNewer(t *testing.T) {
	tests := []struct {
		latest  string
		current string
		want    bool
	}{
		{latest: "v0.10.0", current: "v0.9.0", want: true},
		{latest: "0.10.1", current: "v0.10.0", want: true},
		{latest: "v0.10.0", current: "v0.10.0", want: false},
		{latest: "v0.9.9", current: "v0.10.0", want: false},
		{latest: "v1.0.0", current: "dev", want: false},
	}
	for _, tt := range tests {
		if got := IsNewer(tt.latest, tt.current); got != tt.want {
			t.Fatalf("IsNewer(%q, %q) = %v, want %v", tt.latest, tt.current, got, tt.want)
		}
	}
}
