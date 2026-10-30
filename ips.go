package trusteddevices

import (
	"fmt"
	"net/netip"
	"strings"
)

// ipList holds the trusted addresses; a single address is stored as a /32 or /128 prefix.
type ipList []netip.Prefix

// parseIPList reads one address or CIDR range per line, skipping blank lines and comments. It returns a warning for
// every line it skips or reads differently from how it's written, so a typo shows up in the log instead of silently
// trusting more or fewer addresses than meant.
func parseIPList(data string) (list ipList, warnings []string) {
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if prefix, err := netip.ParsePrefix(line); err == nil {
			prefix = unmapPrefix(prefix)
			if masked := prefix.Masked(); masked != prefix {
				warnings = append(warnings, fmt.Sprintf("%q has host bits set, trusting all of %s", line, masked))
				prefix = masked
			}
			if prefix.Bits() == 0 {
				warnings = append(warnings, fmt.Sprintf("%q trusts every address", line))
			}
			list = append(list, prefix)
		} else if addr, err := netip.ParseAddr(line); err == nil {
			addr = addr.Unmap()
			list = append(list, netip.PrefixFrom(addr, addr.BitLen()))
		} else {
			warnings = append(warnings, fmt.Sprintf("%q is not an IP address or CIDR range, skipped", line))
		}
	}
	return list, warnings
}

// unmapPrefix turns an IPv4-mapped IPv6 range (::ffff:10.0.0.0/120) into its IPv4 form, because client addresses
// are unmapped before they're compared.
func unmapPrefix(prefix netip.Prefix) netip.Prefix {
	if addr := prefix.Addr(); addr.Is4In6() && prefix.Bits() >= 96 {
		return netip.PrefixFrom(addr.Unmap(), prefix.Bits()-96)
	}
	return prefix
}

// contains reports whether ip falls in one of the trusted ranges.
func (l ipList) contains(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	// A link-local address can come with a zone (fe80::1%en0), which never falls in a prefix.
	addr = addr.Unmap().WithZone("")
	for _, prefix := range l {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
