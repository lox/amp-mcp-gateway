package upstream

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// ValidatePublicURL validates browser-entered endpoints. DNS is checked again at dial time.
func ValidatePublicURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") {
		return errors.New("use a public HTTPS URL on port 443 without credentials or a fragment")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".local") {
		return errors.New("private-network endpoints cannot be added through the browser")
	}
	if ip, err := netip.ParseAddr(host); err == nil && !publicIP(ip) {
		return errors.New("private-network endpoints cannot be added through the browser")
	}
	return nil
}

func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.Is6() {
		return netip.MustParsePrefix("2000::/3").Contains(ip) && !netip.MustParsePrefix("2001::/23").Contains(ip) && !netip.MustParsePrefix("2002::/16").Contains(ip)
	}
	for _, block := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4"} {
		if netip.MustParsePrefix(block).Contains(ip) {
			return false
		}
	}
	return true
}

var publicTransport http.RoundTripper = boundedPublicTransport{transport: &http.Transport{
	Proxy:                 nil,
	TLSHandshakeTimeout:   10 * time.Second,
	ResponseHeaderTimeout: 20 * time.Second,
	IdleConnTimeout:       30 * time.Second,
	DialContext: (&net.Dialer{
		Timeout: 10 * time.Second,
		// Go resolves once and handles address fallback / Happy Eyeballs. This
		// hook checks each numeric destination before its socket can connect.
		ControlContext: func(_ context.Context, _, address string, _ syscall.RawConn) error {
			destination, err := netip.ParseAddrPort(address)
			if err != nil || !publicIP(destination.Addr()) {
				return errors.New("private-network destination blocked")
			}
			return nil
		},
	}).DialContext,
}}

type boundedPublicTransport struct{ transport http.RoundTripper }

func (t boundedPublicTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := ValidatePublicURL(r.URL.String()); err != nil {
		return nil, err
	}
	res, err := t.transport.RoundTrip(r)
	if err == nil {
		res.Body = &boundedBody{Reader: io.LimitReader(res.Body, 4<<20), Closer: res.Body}
	}
	return res, err
}

type boundedBody struct {
	io.Reader
	io.Closer
}

func oauthHTTPClient(c Connection) *http.Client {
	h := &http.Client{Timeout: requestTimeout, CheckRedirect: rejectRedirect}
	if c.PublicOnly {
		h.Transport = publicTransport
	}
	return h
}
