package service

import "net/netip"

// ipString renders an address, or an empty string when it is not valid, so that
// records are never polluted with "invalid IP".
func ipString(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	return ip.String()
}
