package forwarded

import (
	"crypto/tls"
	"fmt"
	"github.com/stanvit/go-ipnets"
	"net"
	"net/http"
	"strings"
)

type Wrapper struct {
	// a slice of networks that are allowed to set the *Forwarded headers
	AllowedNets ipnets.IPNets
	// Trust empty remote address (for Unix Domain Sockets)
	AllowEmptySrc bool
	// Parse Forwarded (rfc7239) header
	ParseForwarded bool
	// A header with the actual IP address[es]
	ForHeader string
	// A header with the protocol name (http or https)
	ProtocolHeader string
}

func parseForwarded(forwarded string) (addr, proto string) {
	for _, forwardedPair := range strings.Split(forwarded, ";") {
		if tv := strings.SplitN(forwardedPair, "=", 2); len(tv) == 2 {
			token, value := tv[0], tv[1]
			token = strings.TrimSpace(token)
			value = strings.TrimSpace(strings.Trim(value, `"`))
			switch strings.ToLower(token) {
			case "for":
				addr = value
			case "proto":
				proto = value
			}
		}
	}
	return addr, proto
}

func latestHeader(r *http.Request, h string) (val string) {
	if values, ok := r.Header[h]; ok {
		latestHeaderInstance := values[len(values)-1]
		instanceValues := strings.Split(latestHeaderInstance, ", ")
		return instanceValues[len(instanceValues)-1]
	}
	return ""
}

func (wrapper *Wrapper) update(r *http.Request) {
	var addr, proto string
	if wrapper.ParseForwarded {
		if forwarded := latestHeader(r, "Forwarded"); forwarded != "" {
			addr, proto = parseForwarded(forwarded)
		}
	} else {
		if wrapper.ForHeader != "" {
			addr = strings.TrimSpace(strings.Trim(latestHeader(r, wrapper.ForHeader), `"`))
		}
		if wrapper.ProtocolHeader != "" {
			proto = strings.TrimSpace(latestHeader(r, wrapper.ProtocolHeader))
		}
	}
	if addr != "" {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(addr, "65535")
		}
		r.RemoteAddr = addr
	}
	if strings.ToLower(proto) == "https" && r.TLS == nil {
		r.TLS = new(tls.ConnectionState)
	}
}

func getIP(r *http.Request) (ip net.IP, err error) {
	ipString := r.RemoteAddr
	if ipString == "@" {
		return nil, nil
	}
	if ipNoport, _, err := net.SplitHostPort(ipString); err == nil {
		ipString = ipNoport
	}
	ip = net.ParseIP(ipString)
	if ip == nil {
		return nil, fmt.Errorf("Failed to parse IP %v", ipString)
	}
	return ip, nil
}

func (wrapper *Wrapper) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ip, err := getIP(r); err == nil && ((ip == nil && wrapper.AllowEmptySrc) || (ip != nil && wrapper.AllowedNets.Contains(ip))) {
			wrapper.update(r)
		}
		h.ServeHTTP(w, r)
	})
}
