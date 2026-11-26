// Package egressproxy provides a CONNECT-only proxy for allowlisted market
// hosts. It supports only IPv4 targets and dials validated DNS answers directly.
// It relays opaque bytes without TLS decryption. There is no OTLP exporter.
// Collector transport_error metrics and proxy connection logs report failures.
package egressproxy

import (
	"net/netip"
	"strings"
)

var denied = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"), // includes limited broadcast
	netip.MustParsePrefix("::/128"), netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("64:ff9b::/96"),
}

func permitted(ip netip.Addr, allow []netip.Prefix) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	for _, p := range allow {
		if p.Contains(ip) {
			return true
		}
	}
	for _, p := range denied {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

func hostname(s string) (string, bool) {
	// DNS case folding applies to ASCII labels. Internationalized names must
	// be supplied in their DNS (A-label) form.
	for i := range len(s) {
		if s[i] >= 0x80 {
			return "", false
		}
	}
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if len(s) == 0 || len(s) > 253 {
		return "", false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return "", false
	}
	for label := range strings.SplitSeq(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", false
			}
		}
	}
	return s, true
}
