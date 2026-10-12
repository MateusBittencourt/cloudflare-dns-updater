package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const routerMappingPath = "/html/bbsp/ipv6portmapping/ipv6portmapping.asp"

type routerConfig struct {
	baseURL  string
	username string
	password string
	mappings []string
}

func (c routerConfig) enabled() bool {
	return c.baseURL != "" || c.username != "" || c.password != "" || len(c.mappings) != 0
}

func (c routerConfig) validate() error {
	if !c.enabled() {
		return nil
	}
	var missing []string
	if c.baseURL == "" {
		missing = append(missing, "ROUTER_URL")
	}
	if c.username == "" {
		missing = append(missing, "ROUTER_USERNAME")
	}
	if c.password == "" {
		missing = append(missing, "ROUTER_PASSWORD")
	}
	if len(c.mappings) == 0 {
		missing = append(missing, "ROUTER_IPV6_MAPPINGS")
	}
	if len(missing) != 0 {
		return fmt.Errorf("router integration is partially configured; missing: %s", strings.Join(missing, ", "))
	}
	return nil
}

type routerClient struct {
	baseURL  *url.URL
	username string
	password string
	http     *http.Client
}

type routerMapping struct {
	domain     string
	enabled    string
	internalIP string
	remoteHost string
	remoteEnd  string
	name       string
}

var mappingPattern = regexp.MustCompile(`new\s+stPortMap\("((?:\\.|[^"\\])*)","((?:\\.|[^"\\])*)","((?:\\.|[^"\\])*)","((?:\\.|[^"\\])*)","((?:\\.|[^"\\])*)","((?:\\.|[^"\\])*)"\)`)

func newRouterClient(cfg routerConfig, httpClient *http.Client) (*routerClient, error) {
	base, err := url.Parse(cfg.baseURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("ROUTER_URL must be an absolute URL: %q", cfg.baseURL)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("ROUTER_URL must use http or https")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/"
	return &routerClient{baseURL: base, username: cfg.username, password: cfg.password, http: httpClient}, nil
}

func (c *routerClient) ensureMapping(ctx context.Context, name string, ip netip.Addr) (bool, string, error) {
	page, err := c.mappingPage(ctx)
	if err != nil || !strings.Contains(page, "stPortMap") {
		if err := c.login(ctx); err != nil {
			return false, "", fmt.Errorf("login: %w", err)
		}
		page, err = c.mappingPage(ctx)
		if err != nil {
			return false, "", err
		}
	}
	mapping, err := findRouterMapping(page, name)
	if err != nil {
		return false, "", err
	}
	old := mapping.internalIP
	if current, err := netip.ParseAddr(old); err == nil && current == ip {
		return false, old, nil
	}
	if err := c.updateMapping(ctx, mapping, ip.String()); err != nil {
		return false, old, err
	}
	page, err = c.mappingPage(ctx)
	if err != nil {
		return false, old, fmt.Errorf("verify update: %w", err)
	}
	updated, err := findRouterMapping(page, name)
	if err != nil {
		return false, old, fmt.Errorf("verify update: %w", err)
	}
	verified, err := netip.ParseAddr(updated.internalIP)
	if err != nil || verified != ip {
		return false, old, fmt.Errorf("router did not retain new address; read back %q", updated.internalIP)
	}
	return true, old, nil
}

func (c *routerClient) login(ctx context.Context) error {
	if _, err := c.request(ctx, http.MethodGet, "/", nil); err != nil {
		return err
	}
	token, err := c.token(ctx)
	if err != nil {
		return err
	}
	form := url.Values{
		"UserName":     {c.username},
		"PassWord":     {base64.StdEncoding.EncodeToString([]byte(c.password))},
		"Language":     {"english"},
		"x.X_HW_Token": {token},
	}
	body, err := c.request(ctx, http.MethodPost, "/login.cgi", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	if strings.Contains(body, "LoginSubmit") || strings.Contains(body, "txt_Username") {
		return fmt.Errorf("router rejected the credentials")
	}
	return nil
}

func (c *routerClient) token(ctx context.Context) (string, error) {
	body, err := c.request(ctx, http.MethodPost, "/asp/GetRandCount.asp", strings.NewReader(""))
	if err != nil {
		return "", err
	}
	token := strings.Trim(strings.TrimSpace(body), "\"'")
	if token == "" || len(token) > 256 {
		return "", fmt.Errorf("router returned an invalid request token")
	}
	return token, nil
}

func (c *routerClient) mappingPage(ctx context.Context) (string, error) {
	return c.request(ctx, http.MethodGet, routerMappingPath, nil)
}

func (c *routerClient) updateMapping(ctx context.Context, mapping routerMapping, newIP string) error {
	token, err := c.token(ctx)
	if err != nil {
		return err
	}
	query := url.Values{
		"x":           {mapping.domain},
		"RequestFile": {strings.TrimPrefix(routerMappingPath, "/")},
	}
	form := url.Values{
		"x.Enabled":         {mapping.enabled},
		"x.Description":     {mapping.name},
		"x.InternalClient":  {newIP},
		"x.RemoteHost":      {mapping.remoteHost},
		"x.RemoteHostRange": {mapping.remoteEnd},
		"x.X_HW_Token":      {token},
	}
	endpoint := "/html/bbsp/ipv6portmapping/complex.cgi?" + query.Encode()
	_, err = c.request(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	return err
}

func (c *routerClient) request(ctx context.Context, method, path string, body io.Reader) (string, error) {
	relative, err := url.Parse(path)
	if err != nil {
		return "", err
	}
	endpoint := c.baseURL.ResolveReference(relative)
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return "", err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if path == "/login.cgi" {
		req.AddCookie(&http.Cookie{Name: "Cookie", Value: "body:Language:english:id=-1", Path: "/"})
	}
	req.Header.Set("Referer", c.baseURL.ResolveReference(&url.URL{Path: routerMappingPath}).String())
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("router returned HTTP %d", resp.StatusCode)
	}
	return string(data), nil
}

func findRouterMapping(page, name string) (routerMapping, error) {
	var found []routerMapping
	for _, match := range mappingPattern.FindAllStringSubmatch(page, -1) {
		values := make([]string, 6)
		valid := true
		for i := range values {
			decoded, err := strconv.Unquote(`"` + match[i+1] + `"`)
			if err != nil {
				valid = false
				break
			}
			values[i] = decoded
		}
		if valid && values[5] == name {
			found = append(found, routerMapping{
				domain: values[0], enabled: values[1], internalIP: values[2],
				remoteHost: values[3], remoteEnd: values[4], name: values[5],
			})
		}
	}
	if len(found) == 0 {
		return routerMapping{}, fmt.Errorf("IPv6 mapping %q does not exist", name)
	}
	if len(found) > 1 {
		return routerMapping{}, fmt.Errorf("found %d IPv6 mappings named %q; expected exactly one", len(found), name)
	}
	return found[0], nil
}
