package main

import (
	"regexp"
	"strings"
)

type portalOrigins struct{ platform, seller string }

// Browsers parse a numeric final label as IPv4, including short and hex forms.
var numericHostSuffix = regexp.MustCompile(`^(?:[0-9]+|0x[0-9a-f]*)$`)

func readPortalOrigins(env map[string]string) portalOrigins {
	origin := func(key, fallback string) string {
		value := env[key]
		if value == "" {
			value = fallback
		}
		host, https := strings.CutPrefix(value, "https://")
		require(https && len(host) <= 253 && strings.Contains(host, "."),
			key+" must be a canonical HTTPS origin with a lowercase DNS hostname")
		for label := range strings.SplitSeq(host, ".") {
			require(len(label) <= 63 && dnsLabel.MatchString(label), key+" contains an invalid DNS label")
		}
		suffix := host[strings.LastIndexByte(host, '.')+1:]
		require(!numericHostSuffix.MatchString(suffix), key+" requires a DNS hostname")
		return value
	}
	o := portalOrigins{
		platform: origin("AIPAY_PLATFORM_ORIGIN", "https://admin.aipay.test"),
		seller:   origin("AIPAY_SELLER_ORIGIN", "https://seller.aipay.test"),
	}
	require(o.platform != o.seller, "AIPAY_PLATFORM_ORIGIN and AIPAY_SELLER_ORIGIN must have different hosts")
	return o
}

func (o portalOrigins) rpID() string { return strings.TrimPrefix(o.platform, "https://") }
