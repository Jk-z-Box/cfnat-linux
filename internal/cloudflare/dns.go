package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cfnat-linux/cfnat-linux/internal/config"
)

type Client struct {
	cfg     config.DNSConfig
	baseURL string
	http    *http.Client
}

type record struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Comment string `json:"comment"`
}

type envelope[T any] struct {
	Success bool `json:"success"`
	Result  T    `json:"result"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

func New(cfg config.DNSConfig) *Client {
	return &Client{cfg: cfg, baseURL: "https://api.cloudflare.com/client/v4", http: &http.Client{Timeout: 20 * time.Second}}
}

func (c *Client) Sync(ctx context.Context, ips []netip.Addr) error {
	if !c.cfg.Enabled {
		return nil
	}
	token := os.Getenv(c.cfg.TokenEnv)
	if token == "" {
		return fmt.Errorf("环境变量 %s 未设置", c.cfg.TokenEnv)
	}
	desired := make(map[string]struct{})
	for _, ip := range ips {
		if (c.cfg.RecordType == "A" && ip.Is4()) || (c.cfg.RecordType == "AAAA" && ip.Is6()) {
			desired[ip.String()] = struct{}{}
		}
		if len(desired) == c.cfg.SyncCount {
			break
		}
	}
	if len(desired) == 0 {
		return errors.New("没有可同步的 IP，保留现有 DNS 记录")
	}

	records, err := c.list(ctx, token)
	if err != nil {
		return err
	}
	existing := make(map[string]record)
	managed := make(map[string]record)
	for _, item := range records {
		existing[item.Content] = item
		if item.Comment == c.cfg.Marker {
			managed[item.Content] = item
		}
	}
	// 先创建新记录，确保更新期间域名不会变成空记录集。
	for content := range desired {
		if _, ok := existing[content]; ok {
			continue
		}
		if err := c.create(ctx, token, content); err != nil {
			return err
		}
	}
	for content, item := range managed {
		if _, keep := desired[content]; keep {
			continue
		}
		if err := c.delete(ctx, token, item.ID); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) list(ctx context.Context, token string) ([]record, error) {
	query := url.Values{"type": {c.cfg.RecordType}, "name": {c.cfg.RecordName}, "per_page": {"100"}}
	path := fmt.Sprintf("/zones/%s/dns_records?%s", c.cfg.ZoneID, query.Encode())
	var out envelope[[]record]
	if err := c.do(ctx, token, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out.Result, nil
}

func (c *Client) create(ctx context.Context, token, content string) error {
	payload := map[string]any{"type": c.cfg.RecordType, "name": c.cfg.RecordName, "content": content, "ttl": c.cfg.TTL, "proxied": false, "comment": c.cfg.Marker}
	path := fmt.Sprintf("/zones/%s/dns_records", c.cfg.ZoneID)
	var out envelope[record]
	return c.do(ctx, token, http.MethodPost, path, payload, &out)
}

func (c *Client) delete(ctx context.Context, token, id string) error {
	path := fmt.Sprintf("/zones/%s/dns_records/%s", c.cfg.ZoneID, id)
	var out envelope[map[string]any]
	return c.do(ctx, token, http.MethodDelete, path, nil, &out)
}

func (c *Client) do(ctx context.Context, token, method, path string, payload any, output interface{ isSuccessful() bool }) error {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, output); err != nil {
		return fmt.Errorf("Cloudflare API HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !output.isSuccessful() {
		return fmt.Errorf("Cloudflare API 请求失败: HTTP %d, %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return nil
}

func (e *envelope[T]) isSuccessful() bool { return e.Success }
