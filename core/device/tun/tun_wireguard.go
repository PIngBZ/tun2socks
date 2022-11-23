//go:build !(linux && amd64) && !(linux && arm64)

package tun

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"

	"golang.zx2c4.com/wireguard/tun"

	wroute "github.com/LLParse/win-route"
	"github.com/PIngBZ/tun2socks/v2/core/device"
	"github.com/PIngBZ/tun2socks/v2/core/device/iobased"
	"github.com/PIngBZ/tun2socks/v2/core/device/tun/winipcfg"
)

type TUN struct {
	*iobased.Endpoint

	nt     *tun.NativeTun
	mtu    uint32
	name   string
	offset int
}

func Open(name string, params url.Values, mtu uint32) (_ device.Device, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("open tun: %v", r)
		}
	}()

	t := &TUN{name: name, mtu: mtu, offset: offset}

	forcedMTU := defaultMTU
	if t.mtu > 0 {
		forcedMTU = int(t.mtu)
	}

	nt, err := tun.CreateTUN(t.name, forcedMTU)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}
	t.nt = nt.(*tun.NativeTun)

	link := winipcfg.LUID(t.nt.LUID())
	if ip := params.Get("ip"); len(ip) > 0 {
		ipn, err := netip.ParsePrefix(ip)
		if err == nil {
			if !ipn.IsValid() {
				return nil, fmt.Errorf("ip not valid: %s", ip)
			}
			if err = link.SetIPAddresses([]netip.Prefix{ipn}); err != nil {
				return nil, fmt.Errorf("SetIPAddresses: %w", err)
			}
		} else {
			return nil, fmt.Errorf("parse ip: %w", err)
		}

		if route := params.Get("route"); len(route) > 0 {
			if routen, err := netip.ParsePrefix(route); err == nil {
				if !routen.IsValid() {
					return nil, fmt.Errorf("route not valid: %s", route)
				}
				intf, err := wroute.ResolveInterface(net.ParseIP(ipn.Addr().String()))
				if err != nil {
					return nil, fmt.Errorf("ResolveInterface: %w", err)
				}

				r := wroute.NewNetRoute()
				defer r.Close()

				i, err := r.GetInterfaceByIndex(uint32(intf.Index))
				if err != nil {
					return nil, fmt.Errorf("GetInterfaceByIndex: %w", err)
				}

				r1 := &wroute.IPForwardRow{
					ForwardDest:    wroute.Inet_aton(routen.Addr().String(), false),
					ForwardMask:    wroute.Inet_aton(t.LenToSubNetMask(routen.Bits()), false),
					ForwardNextHop: wroute.Inet_aton(ipn.Addr().String(), false),
					ForwardIfIndex: i.InterfaceIndex,
					ForwardType:    3,
					ForwardProto:   3,
					ForwardMetric1: i.Metric,
				}

				if err = r.AddRoute(r1); err != nil {
					return nil, fmt.Errorf("AddRoute: %w", err)
				}

			} else {
				return nil, fmt.Errorf("parse route: %w", err)
			}
		}
	}

	tunMTU, err := nt.MTU()
	if err != nil {
		return nil, fmt.Errorf("get mtu: %w", err)
	}
	t.mtu = uint32(tunMTU)

	ep, err := iobased.New(t, t.mtu, offset)
	if err != nil {
		return nil, fmt.Errorf("create endpoint: %w", err)
	}
	t.Endpoint = ep

	return t, nil
}

func (t *TUN) Read(packet []byte) (int, error) {
	return t.nt.Read(packet, t.offset)
}

func (t *TUN) Write(packet []byte) (int, error) {
	return t.nt.Write(packet, t.offset)
}

func (t *TUN) Name() string {
	name, _ := t.nt.Name()
	return name
}

func (t *TUN) Close() error {
	defer t.Endpoint.Close()
	return t.nt.Close()
}

func (t *TUN) LenToSubNetMask(subnet int) string {
	var buff bytes.Buffer
	for i := 0; i < subnet; i++ {
		buff.WriteString("1")
	}
	for i := subnet; i < 32; i++ {
		buff.WriteString("0")
	}
	masker := buff.String()
	a, _ := strconv.ParseUint(masker[:8], 2, 8)
	b, _ := strconv.ParseUint(masker[8:16], 2, 8)
	c, _ := strconv.ParseUint(masker[16:24], 2, 8)
	d, _ := strconv.ParseUint(masker[24:32], 2, 8)
	resultMask := fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
	return resultMask
}
