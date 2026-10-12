package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestFindRouterMapping(t *testing.T) {
	page := `var WanPPPPortMapping = new Array(` +
		`new stPortMap("Device.PortForward.2","1","2001\x3adb8\x3a\x3a1","","","nginx"),` +
		`new stPortMap("Device.PortForward.3","1","2001\x3adb8\x3a\x3a2","","","other"),null);`
	mapping, err := findRouterMapping(page, "nginx")
	if err != nil {
		t.Fatal(err)
	}
	if mapping.domain != "Device.PortForward.2" || mapping.internalIP != "2001:db8::1" {
		t.Fatalf("unexpected mapping: %#v", mapping)
	}
}

func TestRouterEnsureMapping(t *testing.T) {
	const session = "test-session"
	const loginToken = "0123456789abcdef0123456789abcdef"
	currentIP := "2001:db8::1"
	authenticated := false
	var updateCount int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			io.WriteString(w, "login")
		case "/asp/GetRandCount.asp":
			io.WriteString(w, "\n"+loginToken)
		case "/login.cgi":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Form.Get("UserName") != "user" || r.Form.Get("PassWord") != "cGFzcw==" || r.Form.Get("x.X_HW_Token") != loginToken {
				t.Errorf("unexpected login form: %v", r.Form)
			}
			authenticated = true
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: session, Path: "/"})
			io.WriteString(w, "ok")
		case routerMappingPath:
			cookie, _ := r.Cookie("sid")
			if !authenticated || cookie == nil || cookie.Value != session {
				io.WriteString(w, "function LoginSubmit() {}")
				return
			}
			fmt.Fprintf(w, `<input type="hidden" name="onttoken" id="hwonttoken" value="abcdef0123456789abcdef0123456789">new stPortMap("Device.PortForward.2","1","%s","","","nginx")`, strings.ReplaceAll(currentIP, ":", `\x3a`))
		case "/html/bbsp/ipv6portmapping/complex.cgi":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.URL.Query().Get("x") != "Device.PortForward.2" {
				t.Errorf("unexpected mapping domain: %s", r.URL.RawQuery)
			}
			if r.Form.Get("x.Description") != "nginx" || r.Form.Get("x.X_HW_Token") != "abcdef0123456789abcdef0123456789" {
				t.Errorf("unexpected update form: %v", r.Form)
			}
			currentIP = r.Form.Get("x.InternalClient")
			updateCount++
			io.WriteString(w, "ok")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	jar, _ := cookiejar.New(nil)
	client, err := newRouterClient(routerConfig{baseURL: server.URL, username: "user", password: "pass", mappings: []string{"nginx"}}, &http.Client{Jar: jar})
	if err != nil {
		t.Fatal(err)
	}
	want := netip.MustParseAddr("2001:db8::99")
	changed, old, err := client.ensureMapping(context.Background(), "nginx", want)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || old != "2001:db8::1" || updateCount != 1 {
		t.Fatalf("changed=%v old=%q updates=%d", changed, old, updateCount)
	}
	changed, _, err = client.ensureMapping(context.Background(), "nginx", want)
	if err != nil || changed || updateCount != 1 {
		t.Fatalf("second check: changed=%v updates=%d err=%v", changed, updateCount, err)
	}
}

func TestAuthenticatedTokenFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/html/ssmp/common/GetRandToken.asp" {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, `var token = "0123456789abcdef0123456789abcdef";`)
	}))
	defer server.Close()

	client, err := newRouterClient(routerConfig{baseURL: server.URL}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	token, err := client.authenticatedToken(context.Background(), "page without a token")
	if err != nil || token != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("authenticatedToken() = %q, %v", token, err)
	}
}

func TestRouterConfigAllOrNothing(t *testing.T) {
	err := (routerConfig{baseURL: "http://router", username: "user"}).validate()
	if err == nil || !strings.Contains(err.Error(), "ROUTER_PASSWORD") {
		t.Fatalf("validate() error = %v", err)
	}
}

func TestTokenUsesFinalHexValue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `prefix:0123456789abcdef0123456789abcdef`)
	}))
	defer server.Close()

	client, err := newRouterClient(routerConfig{baseURL: server.URL}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	token, err := client.token(context.Background())
	if err != nil || token != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("token() = %q, %v", token, err)
	}
}
