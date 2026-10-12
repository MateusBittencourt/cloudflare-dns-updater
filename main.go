package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const defaultAPIURL = "https://api.cloudflare.com/client/v4"

type config struct {
	token     string
	zoneID    string
	records   []string
	iface     string
	interval  time.Duration
	fullCheck time.Duration
	apiURL    string
	routeAddr string
	router    routerConfig
}

type cloudflareClient struct {
	baseURL string
	token   string
	http    *http.Client
}

type dnsRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
}

type apiResponse[T any] struct {
	Success bool       `json:"success"`
	Result  T          `json:"result"`
	Errors  []apiError `json:"errors"`
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func main() {
	once := flag.Bool("once", false, "check and update once, then exit")
	flag.Parse()

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		os.Exit(2)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	client := &cloudflareClient{
		baseURL: cfg.apiURL,
		token:   cfg.token,
		http:    &http.Client{Timeout: 20 * time.Second},
	}
	var router *routerClient
	if cfg.router.enabled() {
		jar, err := cookiejar.New(nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, "initialize router session:", err)
			os.Exit(2)
		}
		router, err = newRouterClient(cfg.router, &http.Client{Timeout: 20 * time.Second, Jar: jar})
		if err != nil {
			fmt.Fprintln(os.Stderr, "configuration error:", err)
			os.Exit(2)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var cachedIP netip.Addr
	var lastFullCheck time.Time
	run := func(force bool) error {
		checkCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		ip, err := discoverIPv6(cfg.iface, cfg.routeAddr)
		if err != nil {
			err = fmt.Errorf("discover IPv6 address: %w", err)
			logger.Error("update check failed", "error", err)
			return err
		}
		now := time.Now()
		full, reason := shouldFullCheck(cachedIP, ip, lastFullCheck, now, cfg.fullCheck)
		if force {
			full, reason = true, "forced"
		}
		if !full {
			logger.Debug("local IPv6 address is unchanged", "address", ip)
			return nil
		}
		logger.Info("starting full reconciliation", "reason", reason, "address", ip)
		if err := reconcile(checkCtx, ip, cfg, client, router, logger); err != nil {
			logger.Error("update check failed", "error", err)
			return err
		}
		cachedIP = ip
		lastFullCheck = now
		logger.Info("full reconciliation completed", "address", ip)
		return nil
	}

	firstErr := run(true)
	if *once {
		if firstErr != nil {
			os.Exit(1)
		}
		return
	}

	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Info("shutting down")
			return
		case <-ticker.C:
			_ = run(false)
		}
	}
}

func loadConfig() (config, error) {
	cfg := config{
		token:     strings.TrimSpace(os.Getenv("CF_API_TOKEN")),
		zoneID:    strings.TrimSpace(os.Getenv("CF_ZONE_ID")),
		iface:     strings.TrimSpace(os.Getenv("IPV6_INTERFACE")),
		apiURL:    strings.TrimRight(envOr("CF_API_URL", defaultAPIURL), "/"),
		routeAddr: envOr("IPV6_ROUTE_PROBE", "[2606:4700:4700::1111]:53"),
		router: routerConfig{
			baseURL:  strings.TrimSpace(os.Getenv("ROUTER_URL")),
			username: strings.TrimSpace(os.Getenv("ROUTER_USERNAME")),
			password: os.Getenv("ROUTER_PASSWORD"),
		},
	}
	for _, name := range strings.Split(os.Getenv("ROUTER_IPV6_MAPPINGS"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			cfg.router.mappings = append(cfg.router.mappings, name)
		}
	}
	for _, name := range strings.Split(os.Getenv("CF_RECORDS"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			cfg.records = append(cfg.records, name)
		}
	}
	interval, err := time.ParseDuration(envOr("CHECK_INTERVAL", "5m"))
	if err != nil || interval <= 0 {
		return cfg, fmt.Errorf("CHECK_INTERVAL must be a positive Go duration (for example 5m)")
	}
	cfg.interval = interval
	fullCheck, err := time.ParseDuration(envOr("FULL_CHECK_INTERVAL", "24h"))
	if err != nil || fullCheck <= 0 {
		return cfg, fmt.Errorf("FULL_CHECK_INTERVAL must be a positive Go duration (for example 24h)")
	}
	cfg.fullCheck = fullCheck

	var missing []string
	if cfg.token == "" {
		missing = append(missing, "CF_API_TOKEN")
	}
	if cfg.zoneID == "" {
		missing = append(missing, "CF_ZONE_ID")
	}
	if len(cfg.records) == 0 {
		missing = append(missing, "CF_RECORDS")
	}
	if len(missing) > 0 {
		return cfg, fmt.Errorf("missing required environment variable(s): %s", strings.Join(missing, ", "))
	}
	if err := cfg.router.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func reconcile(ctx context.Context, ip netip.Addr, cfg config, client *cloudflareClient, router *routerClient, logger *slog.Logger) error {
	var failures []error
	for _, name := range cfg.records {
		record, err := client.findAAAA(ctx, cfg.zoneID, name)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", name, err))
			continue
		}
		if current, err := netip.ParseAddr(record.Content); err == nil && current == ip {
			logger.Info("record is already current", "record", name)
			continue
		}
		if err := client.updateContent(ctx, cfg.zoneID, record.ID, ip.String()); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", name, err))
			continue
		}
		logger.Info("updated AAAA record", "record", name, "old", record.Content, "new", ip)
	}
	if router != nil {
		for _, name := range cfg.router.mappings {
			changed, oldIP, err := router.ensureMapping(ctx, name, ip)
			if err != nil {
				failures = append(failures, fmt.Errorf("router mapping %s: %w", name, err))
				continue
			}
			if changed {
				logger.Info("updated router IPv6 mapping", "mapping", name, "old", oldIP, "new", ip)
			} else {
				logger.Info("router IPv6 mapping is already current", "mapping", name)
			}
		}
	}
	return errors.Join(failures...)
}

func shouldFullCheck(cachedIP, currentIP netip.Addr, lastFullCheck, now time.Time, interval time.Duration) (bool, string) {
	if !cachedIP.IsValid() || lastFullCheck.IsZero() {
		return true, "startup"
	}
	if cachedIP != currentIP {
		return true, "IPv6 address changed"
	}
	if !now.Before(lastFullCheck.Add(interval)) {
		return true, "periodic verification"
	}
	return false, ""
}

func discoverIPv6(interfaceName, routeAddr string) (netip.Addr, error) {
	if interfaceName == "" {
		conn, err := net.DialTimeout("udp6", routeAddr, 5*time.Second)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("probe IPv6 route to %s: %w", routeAddr, err)
		}
		defer conn.Close()
		addr, ok := conn.LocalAddr().(*net.UDPAddr)
		if !ok {
			return netip.Addr{}, fmt.Errorf("unexpected local address %q", conn.LocalAddr())
		}
		ip, ok := netip.AddrFromSlice(addr.IP)
		if !ok || !isPublicIPv6(ip) {
			return netip.Addr{}, fmt.Errorf("route selected non-public address %q", addr.IP)
		}
		return ip.Unmap(), nil
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return netip.Addr{}, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, raw := range addrs {
		prefix, err := netip.ParsePrefix(raw.String())
		if err == nil && isPublicIPv6(prefix.Addr()) {
			return prefix.Addr(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("interface %q has no public IPv6 address", interfaceName)
}

func isPublicIPv6(ip netip.Addr) bool {
	return ip.IsValid() && ip.Is6() && !ip.Is4In6() && ip.IsGlobalUnicast() && !ip.IsPrivate()
}

func (c *cloudflareClient) findAAAA(ctx context.Context, zoneID, name string) (dnsRecord, error) {
	endpoint := fmt.Sprintf("%s/zones/%s/dns_records?type=AAAA&name=%s", c.baseURL, url.PathEscape(zoneID), url.QueryEscape(name))
	var response apiResponse[[]dnsRecord]
	if err := c.do(ctx, http.MethodGet, endpoint, nil, &response); err != nil {
		return dnsRecord{}, err
	}
	if len(response.Result) == 0 {
		return dnsRecord{}, fmt.Errorf("AAAA record does not exist (create it in Cloudflare first)")
	}
	if len(response.Result) > 1 {
		return dnsRecord{}, fmt.Errorf("found %d AAAA records; expected exactly one", len(response.Result))
	}
	return response.Result[0], nil
}

func (c *cloudflareClient) updateContent(ctx context.Context, zoneID, recordID, content string) error {
	endpoint := fmt.Sprintf("%s/zones/%s/dns_records/%s", c.baseURL, url.PathEscape(zoneID), url.PathEscape(recordID))
	body := strings.NewReader(fmt.Sprintf(`{"content":%q}`, content))
	var response apiResponse[dnsRecord]
	return c.do(ctx, http.MethodPatch, endpoint, body, &response)
}

func (c *cloudflareClient) do(ctx context.Context, method, url string, body io.Reader, target any) error {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("Cloudflare returned HTTP %d with an invalid response", resp.StatusCode)
	}
	var envelope apiResponse[json.RawMessage]
	if err := json.Unmarshal(data, &envelope); err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !envelope.Success {
		var messages []string
		for _, apiErr := range envelope.Errors {
			messages = append(messages, fmt.Sprintf("%d: %s", apiErr.Code, apiErr.Message))
		}
		if len(messages) == 0 {
			messages = append(messages, http.StatusText(resp.StatusCode))
		}
		return fmt.Errorf("Cloudflare API HTTP %d: %s", resp.StatusCode, strings.Join(messages, "; "))
	}
	return nil
}
