package imageproxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// newSecureTransport builds an http.RoundTripper with secureDialer enforced.
// It is always used for upstream requests — there is no way to bypass it via config.
func newSecureTransport(cfg *config) http.RoundTripper {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = cfg.proxy // nil means no proxy (intentional: no ProxyFromEnvironment)
	t.TLSClientConfig = cfg.tlsClientConfig
	t.ResponseHeaderTimeout = cfg.requestTimeout
	t.DialContext = (&secureDialer{
		allowPrivateNetworks: cfg.allowPrivateNetworks,
		dialer: net.Dialer{
			Timeout:   cfg.requestTimeout,
			KeepAlive: 30 * time.Second,
		},
	}).DialContext
	return t
}

type secureDialer struct {
	dialer               net.Dialer
	allowPrivateNetworks bool
}

func (d *secureDialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		return d.dialAddr(ctx, network, addr, port)
	}

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, addr := range addrs {
		conn, err := d.dialAddr(ctx, network, addr, port)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}

	return nil, errors.New("host has no ip addresses")
}

func (d *secureDialer) dialAddr(ctx context.Context, network string, addr netip.Addr, port string) (net.Conn, error) {
	addr = addr.Unmap()
	if !d.allowPrivateNetworks && isBlockedAddr(addr) {
		return nil, invalidURL("private or internal host is not allowed")
	}
	if network == "tcp4" && !addr.Is4() {
		return nil, errors.New("address is not ipv4")
	}
	if network == "tcp6" && !addr.Is6() {
		return nil, errors.New("address is not ipv6")
	}

	return d.dialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
}
