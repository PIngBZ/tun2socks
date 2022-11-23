package dns

import (
	"net"

	"github.com/PIngBZ/tun2socks/v2/component/dialer"
)

func init() {
	// We must use this DialContext to query DNS
	// when using net default resolver.
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = dialer.DialContext
}
