package imageproxy

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

type urlValidator struct {
	allowedHosts         []hostRule
	allowPrivateNetworks bool
	maxURLLength         int
}

type hostRule struct {
	host     string
	wildcard bool
}

func newURLValidator(cfg *config) urlValidator {
	return urlValidator{
		allowedHosts:         cfg.allowedHosts,
		allowPrivateNetworks: cfg.allowPrivateNetworks,
		maxURLLength:         cfg.maxURLLength,
	}
}

func (v urlValidator) validate(ctx context.Context, raw string) (string, error) {
	clean, host, err := v.validateStructural(raw)
	if err != nil {
		return "", err
	}
	if !v.allowPrivateNetworks {
		if err := validatePublicHost(ctx, host); err != nil {
			return "", err
		}
	}

	return clean, nil
}

// validateStructuralURL performs URL parsing, scheme and host policy checks
// without resolving DNS. Use it on hot paths where a deeper SSRF check
// (secureDialer) already runs at the TCP layer.
func (v urlValidator) validateStructuralURL(raw string) (string, error) {
	clean, _, err := v.validateStructural(raw)
	return clean, err
}

func (v urlValidator) validateStructural(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", invalidURL("url is required")
	}
	if v.maxURLLength > 0 && len(raw) > v.maxURLLength {
		return "", "", invalidURL("url is too long")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", "", invalidURL("url parse failed")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", "", invalidURL("scheme must be http or https")
	}
	if u.Host == "" {
		return "", "", invalidURL("host is required")
	}
	if u.User != nil {
		return "", "", invalidURL("userinfo is not allowed")
	}

	host := normalizeHost(u.Hostname())
	if host == "" {
		return "", "", invalidURL("host is required")
	}
	if strings.Contains(host, "%") {
		return "", "", invalidURL("host zone identifiers are not allowed")
	}
	if !v.hostAllowed(host) {
		return "", "", invalidURL("host is not allowed")
	}

	u.Fragment = ""
	return u.String(), host, nil
}

func (v urlValidator) hostAllowed(host string) bool {
	for _, rule := range v.allowedHosts {
		if rule.wildcard {
			if strings.HasSuffix(host, "."+rule.host) {
				return true
			}

			continue
		}

		if host == rule.host {
			return true
		}
	}

	return false
}

func compileHostRules(values []string) ([]hostRule, error) {
	if len(values) == 0 {
		return nil, configError("at least one allowed host is required")
	}

	rules := make([]hostRule, 0, len(values))
	for _, raw := range values {
		value := normalizeHost(strings.TrimSpace(raw))
		if value == "" {
			return nil, configError("allowed host must not be empty")
		}
		if strings.ContainsAny(value, " \t\n\r") {
			return nil, configError("allowed host must not contain whitespace")
		}
		if strings.Contains(value, "/") {
			return nil, configError("allowed host must not contain slash")
		}

		if value == "*" {
			return nil, configError("bare wildcard is not allowed as an allowed host")
		}

		rule := hostRule{host: value}
		if wildcardHost, ok := strings.CutPrefix(value, "*."); ok {
			rule.wildcard = true
			rule.host = wildcardHost
			if rule.host == "" {
				return nil, configError("wildcard allowed host is empty")
			}
			// Require at least one dot in the wildcard base to prevent *.com patterns.
			if !strings.Contains(rule.host, ".") {
				return nil, configError("wildcard host must contain at least two labels (e.g. *.example.com)")
			}
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

func validatePublicHost(ctx context.Context, host string) error {
	if addr, err := netip.ParseAddr(host); err == nil {
		if isBlockedAddr(addr) {
			return invalidURL("private or internal host is not allowed")
		}

		return nil
	}

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return invalidURL("host resolution failed")
	}
	if len(addrs) == 0 {
		return invalidURL("host has no ip addresses")
	}

	for _, addr := range addrs {
		if isBlockedAddr(addr) {
			return invalidURL("private or internal host is not allowed")
		}
	}

	return nil
}

func isBlockedAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return true
	}
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return true
	}
	if addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	if !addr.IsGlobalUnicast() {
		return true
	}

	return false
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}
