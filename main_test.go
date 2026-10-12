package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestIsPublicIPv6(t *testing.T) {
	tests := map[string]bool{
		"2001:db8::1": true,
		"fc00::1":     false,
		"fe80::1":     false,
		"::1":         false,
		"192.0.2.1":   false,
	}
	for raw, want := range tests {
		if got := isPublicIPv6(netip.MustParseAddr(raw)); got != want {
			t.Errorf("isPublicIPv6(%s) = %v, want %v", raw, got, want)
		}
	}
}

func TestShouldFullCheck(t *testing.T) {
	ip := netip.MustParseAddr("2001:db8::1")
	other := netip.MustParseAddr("2001:db8::2")
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		cachedIP   netip.Addr
		last       time.Time
		want       bool
		wantReason string
	}{
		{name: "startup", want: true, wantReason: "startup"},
		{name: "address changed", cachedIP: other, last: now.Add(-time.Hour), want: true, wantReason: "IPv6 address changed"},
		{name: "daily verification", cachedIP: ip, last: now.Add(-24 * time.Hour), want: true, wantReason: "periodic verification"},
		{name: "unchanged", cachedIP: ip, last: now.Add(-time.Hour), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := shouldFullCheck(tt.cachedIP, ip, tt.last, now, 24*time.Hour)
			if got != tt.want || reason != tt.wantReason {
				t.Fatalf("shouldFullCheck() = %v, %q; want %v, %q", got, reason, tt.want, tt.wantReason)
			}
		})
	}
}

func TestFindAndPatchRecord(t *testing.T) {
	var patched string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("missing bearer token")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			io.WriteString(w, `{"success":true,"result":[{"id":"record-id","name":"home.example.com","type":"AAAA","content":"2001:db8::1"}]}`)
		case http.MethodPatch:
			data, _ := io.ReadAll(r.Body)
			patched = string(data)
			io.WriteString(w, `{"success":true,"result":{"id":"record-id"}}`)
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	}))
	defer server.Close()

	client := &cloudflareClient{baseURL: server.URL, token: "secret", http: server.Client()}
	record, err := client.findAAAA(context.Background(), "zone", "home.example.com")
	if err != nil || record.ID != "record-id" {
		t.Fatalf("findAAAA() = %#v, %v", record, err)
	}
	if err := client.updateContent(context.Background(), "zone", record.ID, "2001:db8::2"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(patched, "2001:db8::2") {
		t.Fatalf("patch body = %q", patched)
	}
}

func TestFindAAAAReportsCloudflareError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}]}`)
	}))
	defer server.Close()

	client := &cloudflareClient{baseURL: server.URL, token: "bad", http: server.Client()}
	_, err := client.findAAAA(context.Background(), "zone", "home.example.com")
	if err == nil || !strings.Contains(err.Error(), "Invalid access token") {
		t.Fatalf("findAAAA() error = %v", err)
	}
}
