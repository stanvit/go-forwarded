package forwarded

import (
	"crypto/tls"
	"github.com/stanvit/go-ipnets"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLatestHeader(t *testing.T) {
	h := "Foo"
	r, _ := http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	// should be empty and shouldn't fail
	if latestHeader(r, h) != "" {
		t.Errorf("%v should be empty", h)
	}
	// just a single heder value
	r.Header.Add(h, "one")
	if v := latestHeader(r, h); v != "one" {
		t.Errorf(`%v should be "one", not "%v"`, h, v)
	}
	// now, the request has two header instances, only the last one should be seen
	r.Header.Add(h, "two")
	if v := latestHeader(r, h); v != "two" {
		t.Errorf(`%v should be "two", not "%v"`, h, v)
	}
	// different case, comma-separated values
	r.Header.Add("fOO", "three, four")
	if v := latestHeader(r, h); v != "four" {
		t.Errorf(`%v should be "four", not "%v"`, h, v)
	}
	// no space after the comma, counted as a single value
	r.Header.Add("FOO", "fi,ve")
	if v := latestHeader(r, h); v != "fi,ve" {
		t.Errorf(`%v should be "fi,ve", not "%v"`, h, v)
	}
}

func TestGetIP(t *testing.T) {
	// normal value IP:PORT
	r, _ := http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	if ip, err := getIP(r); err != nil || ip.String() != "1.2.3.4" {
		t.Errorf("%v should parse as 1.2.3.4", r.RemoteAddr)
	}
	// just IP
	r.RemoteAddr = "1.2.3.4"
	if ip, err := getIP(r); err != nil || ip.String() != "1.2.3.4" {
		t.Errorf("%v should parse as 1.2.3.4", r.RemoteAddr)
	}
	// Unix domain socket sets this as its RemoteAddr
	r.RemoteAddr = "@"
	if ip, err := getIP(r); err != nil || ip != nil {
		t.Errorf("%v should parse as nil", r.RemoteAddr)
	}
	// Invalid IP
	r.RemoteAddr = "256.1.1.0:123"
	if _, err := getIP(r); err == nil {
		t.Errorf("%v should not parse", r.RemoteAddr)
	}
}

func TestParseForwarded(t *testing.T) {
	if addr, proto := parseForwarded("for=192.0.2.60;proto=http;by=203.0.113.43"); addr != "192.0.2.60" || proto != "http" {
		t.Errorf(`Address should be 192.0.2.60 and proto http, not "%v" and "%v"`, addr, proto)
	}
	// ports also should be OK
	if addr, proto := parseForwarded("for=192.0.2.60:2345;proto=http;by=203.0.113.43"); addr != "192.0.2.60:2345" || proto != "http" {
		t.Errorf(`Address should be 192.0.2.60:2345 and proto http, not "%v" and "%v"`, addr, proto)
	}
	// shouldn't freak out because of spaces
	if addr, proto := parseForwarded(" for = 192.0.2.60 ; proto = http ; by = 203.0.113.43 "); addr != "192.0.2.60" || proto != "http" {
		t.Errorf(`Address should be 192.0.2.60 and proto http, not "%v" and "%v"`, addr, proto)
	}
	// should understand IPv6
	if addr, proto := parseForwarded(`For="2001:db8:cafe::17"`); addr != "2001:db8:cafe::17" || proto != "" {
		t.Errorf(`Address should be 2001:db8:cafe::17 and proto "", not "%v" and "%v"`, addr, proto)
	}
	if addr, proto := parseForwarded(`For="[2001:db8:cafe::17]:4711"`); addr != "[2001:db8:cafe::17]:4711" || proto != "" {
		t.Errorf(`Address should be [2001:db8:cafe::17]:4711 and proto "", not "%v" and "%v"`, addr, proto)
	}
}

func TestUpdateForwarded(t *testing.T) {
	// create the wrapper where all headers except for the "Forwarded" should be ignored
	wrapper := new(Wrapper)
	wrapper.ParseForwarded = true
	wrapper.ForHeader = "X-Forwarded-For"
	wrapper.ProtocolHeader = "X-Forwarded-Proto"

	// confirm that the XFF and XFP don't work
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

	// confirm that Forwarded works, only last instance is taken into account and XFF and XFP are still ignored
	r, _ = http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	r.Header.Set("Forwarded", "for=1.2.3.4;proto=https")
	r.Header.Add("Forwarded", "for=4.3.2.1:1234")
	r.Header.Add("X-Forwarded-For", "9.9.9.9")
	r.Header.Add("X-Forwarded-Proto", "https")
	wrapper.update(r)
	if r.RemoteAddr != "4.3.2.1:1234" {
		t.Errorf("Remote Address should be 4.3.2.1:1234, not %v", r.RemoteAddr)
	}
	if r.TLS != nil {
		t.Errorf("r.TLS should be nil")
	}

	// confirm tthat "proto=https" sets requets.TLS
	r, _ = http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	r.Header.Add("Forwarded", "for=4.3.2.1")
	r.Header.Set("Forwarded", "for=1.1.1.1, for=1.2.3.4;proto=https")
	r.Header.Add("X-Forwarded-For", "9.9.9.9")
	r.Header.Add("X-Forwarded-Proto", "http")
	wrapper.update(r)
	if r.RemoteAddr != "1.2.3.4:65535" {
		t.Errorf("Remote Address should be 1.2.3.4:65535, not %v", r.RemoteAddr)
	}
	if r.TLS == nil {
		t.Errorf("r.TLS should be not nil")
	}

	// confirm that request.TLS is removed because of "proto=http"
	r, _ = http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	r.TLS = new(tls.ConnectionState)
	r.Header.Set("Forwarded", "for=1.2.3.4;proto=http")
	r.Header.Add("X-Forwarded-Proto", "https")
	wrapper.update(r)
	if r.TLS != nil {
		t.Errorf("r.TLS should be nil")
	}

	// confirm that the invlid IP is parsed as 0.0.0.0
	r, _ = http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	r.Header.Set("Forwarded", "for=256.0.0.1;proto=https")
	wrapper.update(r)
	if r.RemoteAddr != "0.0.0.0:65535" {
		t.Errorf("Remote Address should be 0.0.0.0:65535, not %v", r.RemoteAddr)
	}
}

func TestUpdateXFF(t *testing.T) {

	// configure a wrapper that takes XFF and XFP headers into account and ignore Forwarded
	wrapper := new(Wrapper)
	wrapper.ForHeader = "X-Forwarded-For"
	wrapper.ProtocolHeader = "X-Forwarded-Proto"

	// confirm that Forwarded is ignored
	r, _ := http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	r.Header.Add("Forwarded", "for=4.3.2.1;proto=https")
	wrapper.update(r)
	if r.RemoteAddr != "" {
		t.Errorf(`Remote Address should be "", not %v`, r.RemoteAddr)
	}
	if r.TLS != nil {
		t.Errorf("r.TLS should remain nil")
	}

	// confirm that Forwarded is still ignored and only the last instances of XFF and XFP are considered
	r, _ = http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	r.Header.Add("Forwarded", "for=4.3.2.1")
	r.Header.Add("X-Forwarded-For", "1.2.3.4")
	r.Header.Add("X-Forwarded-For", "4.4.4.4, 5.5.5.5")
	r.Header.Add("X-Forwarded-Proto", "http")
	r.Header.Add("X-Forwarded-Proto", "http, https")
	wrapper.update(r)
	if r.RemoteAddr != "5.5.5.5:65535" {
		t.Errorf(`Remote Address should be "5.5.5.5:65535", not %v`, r.RemoteAddr)
	}
	if r.TLS == nil {
		t.Errorf("r.TLS should be not nil")
	}

	// requets.TLS should b removed
	r, _ = http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	r.TLS = new(tls.ConnectionState)
	r.Header.Add("Forwarded", "for=4.3.2.1;proto=http")
	r.Header.Add("X-Forwarded-Proto", "https")
	r.Header.Add("X-Forwarded-Proto", "https, http")
	wrapper.update(r)
	if r.TLS != nil {
		t.Errorf("r.TLS should be nil")
	}
}

func stubHandler(w http.ResponseWriter, r *http.Request) {
}

func TestHandler(t *testing.T) {
	allowedIps := make(ipnets.IPNets, 0)
	allowedIps.Set("127.0.0.1")
	wrapper := new(Wrapper)
	wrapper.ParseForwarded = true
	wrapper.AllowedNets = allowedIps

	// just a normal Forwarded wrapper
	r, _ := http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	r.Header.Set("Forwarded", `for="2001:db8:cafe::17";proto=https`)
	r.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	wrapper.Handler(http.HandlerFunc(stubHandler)).ServeHTTP(w, r)
	if r.RemoteAddr != "[2001:db8:cafe::17]:65535" {
		t.Errorf(`Remote Address should be "[2001:db8:cafe::17]:65535", not "%v"`, r.RemoteAddr)
	}
	if r.TLS == nil {
		t.Errorf("r.TLS should be not nil")
	}

	// request from a non-trusted IP, shouldn't be updated
	r, _ = http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	r.Header.Set("Forwarded", "for=4.3.2.1;proto=https")
	r.RemoteAddr = "192.168.1.1:1234"
	w = httptest.NewRecorder()
	wrapper.Handler(http.HandlerFunc(stubHandler)).ServeHTTP(w, r)
	if r.RemoteAddr != "192.168.1.1:1234" {
		t.Errorf(`Remote Address should remain "192.168.1.1:1234", not "%v"`, r.RemoteAddr)
	}
	if r.TLS != nil {
		t.Errorf("r.TLS should remain nil")
	}

	// request from unix domain socket, it's unrusted so no updates as well
	r, _ = http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	r.Header.Set("Forwarded", "for=4.3.2.1;proto=https")
	r.RemoteAddr = "@"
	w = httptest.NewRecorder()
	wrapper.Handler(http.HandlerFunc(stubHandler)).ServeHTTP(w, r)
	if r.RemoteAddr != "@" {
		t.Errorf(`Remote Address should remain "@", not "%v"`, r.RemoteAddr)
	}
	if r.TLS != nil {
		t.Errorf("r.TLS should remain nil")
	}

	// trusted usnix domain socket, should update
	wrapper.AllowEmptySrc = true
	r, _ = http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	r.Header.Set("Forwarded", "for=4.3.2.1;proto=https")
	r.RemoteAddr = "@"
	w = httptest.NewRecorder()
	wrapper.Handler(http.HandlerFunc(stubHandler)).ServeHTTP(w, r)
	if r.RemoteAddr != "4.3.2.1:65535" {
		t.Errorf(`Remote Address should be "4.3.2.1:65535", not "%v"`, r.RemoteAddr)
	}
	if r.TLS == nil {
		t.Errorf("r.TLS should be not nil")
	}
}

func TestNew(t *testing.T) {
	// test all non-default values
	wrapper, err := New("1.2.3.4, 192.168.4.0/24, 172.28.45.16/30", true, true, "Foo", "Bar")
	if err != nil {
		t.Errorf("New should run without error: %v", err)
	}
	if l := len(wrapper.AllowedNets); l != 3 {
		t.Errorf("Length of wrapper.AllowedNets should be 3, not %v", l)
	}
	if !wrapper.AllowEmptySrc {
		t.Error("wrapper.AllowEmptySrc should be true")
	}
	if !wrapper.ParseForwarded {
		t.Error("wrapper.parseForwarded should be true")
	}
	if hdr := wrapper.ForHeader; hdr != "Foo" {
		t.Errorf(`wrapper.ForHeader should be "Foo", not "%v"`, hdr)
	}
	if hdr := wrapper.ProtocolHeader; hdr != "Bar" {
		t.Errorf(`wrapper.ProtocolHeader should be "Bar", not "%v"`, hdr)
	}
	// test wrong IP
	if _, err := New("257.0.0.1", true, true, "Foo", "Bar"); err == nil {
		t.Error("New should return an error")
	}
}
