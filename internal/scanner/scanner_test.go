package scanner

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cfnat-linux/cfnat-linux/internal/config"
)

func TestGenerateCandidatesInsidePrefix(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	items, err := generateCandidates([]netip.Prefix{prefix}, true, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 100 {
		t.Fatalf("got %d candidates", len(items))
	}
	seen := map[netip.Addr]bool{}
	for _, ip := range items {
		if !prefix.Contains(ip) {
			t.Fatalf("%s outside prefix", ip)
		}
		if seen[ip] {
			t.Fatalf("duplicate %s", ip)
		}
		seen[ip] = true
	}
}

func TestTraceValue(t *testing.T) {
	if got := traceValue("ip=1.2.3.4\ncolo=HKG\n", "colo"); got != "HKG" {
		t.Fatalf("got %q", got)
	}
}

func TestReadPrefixesAcceptsBareIPCIDRAndComments(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/ips.txt"
	content := "104.16.0.1\n104.17.0.0/24 # useful\ninvalid\n2001:db8::1\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.IPSources = []string{path}
	cfg.SourceCacheDir = dir + "/cache"
	s := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	prefixes, err := s.readPrefixes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[netip.Prefix]bool{
		netip.MustParsePrefix("104.16.0.1/32"): true,
		netip.MustParsePrefix("104.17.0.0/24"): true,
	}
	if len(prefixes) != len(want) {
		t.Fatalf("got %v", prefixes)
	}
	for _, prefix := range prefixes {
		if !want[prefix] {
			t.Fatalf("unexpected %s", prefix)
		}
	}
}

func TestProbeRejectsIPAboveLatencyLimit(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})}
	defer server.Close()
	go server.Serve(listener)

	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	cfg := config.Defaults()
	cfg.TargetPort = port
	cfg.TLS = false
	cfg.CheckURL = "http://example.com/"
	cfg.MaxLatency = config.Duration(time.Nanosecond)
	cfg.DialTimeout = config.Duration(time.Second)
	s := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	_, err = s.Probe(context.Background(), netip.MustParseAddr("127.0.0.1"))
	if err == nil || !strings.Contains(err.Error(), "超过限制") {
		t.Fatalf("expected latency rejection, got %v", err)
	}
}

func TestDownloadSpeed(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	payload := make([]byte, 512*1024)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	})}
	defer server.Close()
	go server.Serve(listener)

	cfg := config.Defaults()
	cfg.SpeedTest.Enabled = true
	cfg.SpeedTest.URL = "http://" + listener.Addr().String() + "/download"
	cfg.SpeedTest.MinMBps = 0.01
	cfg.SpeedTest.Timeout = config.Duration(2 * time.Second)
	cfg.SpeedTest.MaxCandidates = 1
	s := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	speed, err := s.downloadSpeed(context.Background(), netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if speed <= 0 {
		t.Fatalf("speed = %f", speed)
	}
}
