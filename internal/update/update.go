package update

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Repository string
}

type Result struct {
	CurrentVersion  string     `json:"current_version"`
	LatestVersion   string     `json:"latest_version,omitempty"`
	UpdateAvailable bool       `json:"update_available"`
	ReleaseURL      string     `json:"release_url,omitempty"`
	PackageURL      string     `json:"package_url,omitempty"`
	CheckedAt       *time.Time `json:"checked_at,omitempty"`
}

type releaseResponse struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func Check(ctx context.Context, cfg Config, currentVersion string) (Result, error) {
	repo := strings.TrimSpace(cfg.Repository)
	if repo == "" {
		repo = "Jk-z-Box/cfnat-linux"
	}
	now := time.Now().UTC()
	result := Result{CurrentVersion: normalizeVersion(currentVersion), CheckedAt: &now}
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return result, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "cfnat-linux-update-checker")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return result, fmt.Errorf("GitHub Releases API 返回状态码 %d", resp.StatusCode)
	}
	var release releaseResponse
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return result, err
	}
	result.LatestVersion = normalizeVersion(release.TagName)
	result.ReleaseURL = release.HTMLURL
	result.PackageURL = packageURL(release)
	result.UpdateAvailable = IsNewer(result.LatestVersion, result.CurrentVersion)
	return result, nil
}

func packageURL(release releaseResponse) string {
	want := fmt.Sprintf("cfnat-linux-%s.tar.gz", normalizeVersion(release.TagName))
	for _, asset := range release.Assets {
		if asset.Name == want {
			return asset.BrowserDownloadURL
		}
	}
	for _, asset := range release.Assets {
		if strings.HasSuffix(asset.Name, ".tar.gz") && strings.Contains(asset.Name, "cfnat-linux") {
			return asset.BrowserDownloadURL
		}
	}
	return ""
}

func IsNewer(latest, current string) bool {
	latestParts, okLatest := semverParts(latest)
	currentParts, okCurrent := semverParts(current)
	if !okLatest || !okCurrent {
		return false
	}
	for i := 0; i < 3; i++ {
		if latestParts[i] > currentParts[i] {
			return true
		}
		if latestParts[i] < currentParts[i] {
			return false
		}
	}
	return false
}

func semverParts(value string) ([3]int, bool) {
	var parts [3]int
	value = strings.TrimPrefix(normalizeVersion(value), "v")
	matches := regexp.MustCompile(`^([0-9]+)\.([0-9]+)\.([0-9]+)`).FindStringSubmatch(value)
	if matches == nil {
		return parts, false
	}
	for i := 0; i < 3; i++ {
		parsed, err := strconv.Atoi(matches[i+1])
		if err != nil {
			return parts, false
		}
		parts[i] = parsed
	}
	return parts, true
}

func normalizeVersion(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "dev"
	}
	if regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+`).MatchString(value) {
		return "v" + value
	}
	return value
}
