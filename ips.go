package trusteddevices

import (
	"net/netip"
	"strings"
)

// ipList holds the trusted addresses; a single address is stored as a /32 or /128 prefix.
type ipList []netip.Prefix

// parseIPList reads one address or CIDR range per line, skipping blank lines and comments.
// Lines that are neither are returned as invalid, so they can be logged instead of silently never matching.
func parseIPList(data string) (list ipList, invalid []string) {
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if prefix, err := netip.ParsePrefix(line); err == nil {
			list = append(list, prefix.Masked())
		} else if addr, err := netip.ParseAddr(line); err == nil {
			addr = addr.Unmap()
			list = append(list, netip.PrefixFrom(addr, addr.BitLen()))
		} else {
			invalid = append(invalid, line)
		}
	}
	return list, invalid
}

// contains reports whether ip falls in one of the trusted ranges.
func (l ipList) contains(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range l {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
