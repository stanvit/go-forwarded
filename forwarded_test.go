package forwarded

import (
	"github.com/stanvit/go-ipnets"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLatestHeader(t *testing.T) {
	h := "Foo"
	r, _ := http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	if latestHeader(r, h) != "" {
		t.Errorf("%v should be empty", h)
	}
	r.Header.Add(h, "one")
	if v := latestHeader(r, h); v != "one" {
		t.Errorf("%v should be \"one\", not %v", h, v)
	}
	r.Header.Add(h, "two")
	if v := latestHeader(r, h); v != "two" {
		t.Errorf("%v should be \"two\", not %v", h, v)
	}
	r.Header.Add("fOO", "three, four")
	if v := latestHeader(r, h); v != "four" {
		t.Errorf("%v should be \"four\", not %v", h, v)
	}
	r.Header.Add("FOO", "fi,ve")
	if v := latestHeader(r, h); v != "fi,ve" {
		t.Errorf("%v should be \"fi,ve\", not %v", h, v)
	}
}

func TestGetIP(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	if ip, err := getIP(r); err != nil || ip.String() != "1.2.3.4" {
		t.Errorf("%v should parse as 1.2.3.4", r.RemoteAddr)
	}
	r.RemoteAddr = "1.2.3.4"
	if ip, err := getIP(r); err != nil || ip.String() != "1.2.3.4" {
		t.Errorf("%v should parse as 1.2.3.4", r.RemoteAddr)
	}
	r.RemoteAddr = "@"
	if ip, err := getIP(r); err != nil || ip != nil {
		t.Errorf("%v should parse as nil", r.RemoteAddr)
	}
	r.RemoteAddr = "256.1.1.0:123"
	if _, err := getIP(r); err == nil {
		t.Errorf("%v should not parse", r.RemoteAddr)
	}
}

func TestParseForwarded(t *testing.T) {
	if addr, proto := parseForwarded("for=192.0.2.60;proto=http;by=203.0.113.43"); addr != "192.0.2.60" || proto != "http" {
		t.Errorf("Address should be 192.0.2.60 and proto http, not \"%v\" and \"%v\"", addr, proto)
	}
	if addr, proto := parseForwarded(" for = 192.0.2.60 ; proto = http ; by = 203.0.113.43 "); addr != "192.0.2.60" || proto != "http" {
		t.Errorf("Address should be 192.0.2.60 and proto http, not \"%v\" and \"%v\"", addr, proto)
	}
	if addr, proto := parseForwarded(`For="[2001:db8:cafe::17]:4711"`); addr != "[2001:db8:cafe::17]:4711" || proto != "" {
		t.Errorf("Address should be [2001:db8:cafe::17]:4711 and proto \"\", not \"%v\" and \"%v\"", addr, proto)
	}
}

func TestUpdateForwarded(t *testing.T) {
	wrapper := new(Wrapper)
	wrapper.ParseForwarded = true
	wrapper.ForHeader = "X-Forwarded-For"
	wrapper.ProtocolHeader = "X-Forwarded-Proto"

	r, _ := http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	r.Header.Add("X-Forwarded-For", "9.9.9.9")
	r.Header.Add("X-Forwarded-Proto", "https")
	wrapper.update(r)
	if r.RemoteAddr != "" {
		t.Errorf("Remote Address should be \"\", not %v", r.RemoteAddr)
	}
	if r.TLS != nil {
		t.Errorf("r.TLS should remain nil")
	}

	r, _ = http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	r.Header.Set("Forwarded", "for=1.2.3.4;proto=https")
	r.Header.Add("Forwarded", "for=4.3.2.1")
	r.Header.Add("X-Forwarded-For", "9.9.9.9")
	r.Header.Add("X-Forwarded-Proto", "https")
	wrapper.update(r)
	if r.RemoteAddr != "4.3.2.1:65535" {
		t.Errorf("Remote Address should be 4.3.2.1:65535, not %v", r.RemoteAddr)
	}
	if r.TLS != nil {
		t.Errorf("r.TLS should remain nil")
	}

	r, _ = http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	r.Header.Add("Forwarded", "for=4.3.2.1")
	r.Header.Set("Forwarded", "for=1.1.1.1, for=1.2.3.4;proto=https")
	r.Header.Add("X-Forwarded-For", "9.9.9.9")
	r.Header.Add("X-Forwarded-Proto", "https")
	wrapper.update(r)
	if r.RemoteAddr != "1.2.3.4:65535" {
		t.Errorf("Remote Address should be 1.2.3.4:65535, not %v", r.RemoteAddr)
	}
	if r.TLS == nil {
		t.Errorf("r.TLS should be not nil")
	}
}

func TestUpdateXFF(t *testing.T) {
	wrapper := new(Wrapper)
	wrapper.ForHeader = "X-Forwarded-For"
	wrapper.ProtocolHeader = "X-Forwarded-Proto"

	r, _ := http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	r.Header.Add("Forwarded", "for=4.3.2.1")
	wrapper.update(r)
	if r.RemoteAddr != "" {
		t.Errorf("Remote Address should be \"\", not %v", r.RemoteAddr)
	}
	if r.TLS != nil {
		t.Errorf("r.TLS should remain nil")
	}

	r, _ = http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	r.Header.Add("Forwarded", "for=4.3.2.1")
	r.Header.Add("X-Forwarded-For", "1.2.3.4")
	r.Header.Add("X-Forwarded-For", "4.4.4.4, 5.5.5.5")
	r.Header.Add("X-Forwarded-Proto", "http")
	r.Header.Add("X-Forwarded-Proto", "http, https")
	wrapper.update(r)
	if r.RemoteAddr != "5.5.5.5:65535" {
		t.Errorf("Remote Address should be \"5.5.5.5:65535\", not %v", r.RemoteAddr)
	}
	if r.TLS == nil {
		t.Errorf("r.TLS should be not nil")
	}
}

func StubHandler(w http.ResponseWriter, r *http.Request) {
}

func TestHandler(t *testing.T) {
	allowedIps := make(ipnets.IPNets, 0)
	allowedIps.Set("127.0.0.1")
	wrapper := new(Wrapper)
	wrapper.ParseForwarded = true
	wrapper.AllowedNets = allowedIps

	r, _ := http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	r.Header.Set("Forwarded", "for=4.3.2.1;proto=https")
	r.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()

	wrapper.Handler(http.HandlerFunc(StubHandler)).ServeHTTP(w, r)
	if r.RemoteAddr != "4.3.2.1:65535" {
		t.Errorf("Remote Address should be \"4.3.2.1:65535\", not %v", r.RemoteAddr)
	}
	if r.TLS == nil {
		t.Errorf("r.TLS should be not nil")
	}

	r, _ = http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	r.Header.Set("Forwarded", "for=4.3.2.1;proto=https")
	r.RemoteAddr = "192.168.1.1:1234"
	w = httptest.NewRecorder()

	wrapper.Handler(http.HandlerFunc(StubHandler)).ServeHTTP(w, r)
	if r.RemoteAddr != "192.168.1.1:1234" {
		t.Errorf("Remote Address should remain \"192.168.1.1:1234\", not %v", r.RemoteAddr)
	}
	if r.TLS != nil {
		t.Errorf("r.TLS should remain nil")
	}

	r, _ = http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	r.Header.Set("Forwarded", "for=4.3.2.1;proto=https")
	r.RemoteAddr = "@"
	w = httptest.NewRecorder()

	wrapper.Handler(http.HandlerFunc(StubHandler)).ServeHTTP(w, r)
	if r.RemoteAddr != "@" {
		t.Errorf("Remote Address should remain \"@\", not %v", r.RemoteAddr)
	}
	if r.TLS != nil {
		t.Errorf("r.TLS should remain nil")
	}

	wrapper.AllowEmptySrc = true
	r, _ = http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	r.Header.Set("Forwarded", "for=4.3.2.1;proto=https")
	r.RemoteAddr = "@"
	w = httptest.NewRecorder()

	wrapper.Handler(http.HandlerFunc(StubHandler)).ServeHTTP(w, r)
	if r.RemoteAddr != "4.3.2.1:65535" {
		t.Errorf("Remote Address should be \"4.3.2.1:65535\", not %v", r.RemoteAddr)
	}
	if r.TLS == nil {
		t.Errorf("r.TLS should be not nil")
	}
}
