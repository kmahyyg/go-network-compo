//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package routes

import (
	"golang.org/x/net/route"
	"strconv"
	"syscall"
)

// https://github.com/apple/darwin-xnu/blob/main/bsd/net/route.h
const (
	RTF_UP        = 0x1
	RTF_GATEWAY   = 0x2
	RTF_HOST      = 0x4
	RTF_REJECT    = 0x8
	RTF_DYNAMIC   = 0x10
	RTF_MODIFIED  = 0x20
	RTF_DONE      = 0x40
	RTF_MASK      = 0x80
	RTF_CLONING   = 0x100
	RTF_XRESOLVE  = 0x200
	RTF_LLINFO    = 0x400
	RTF_STATIC    = 0x800
	RTF_BLACKHOLE = 0x1000
	RTF_PROTO2    = 0x4000
	RTF_PROTO1    = 0x8000
	RTF_LOCAL     = 0x200000
	RTF_BROADCAST = 0x400000
	RTF_MULTICAST = 0x800000
	RTF_IFSCOPE   = 0x1000000
)

func Retrieve() ([]NetRoute, error) {
	// check https://github.com/golang/go/issues/45736
	// problem still exists
	//
	// ENOCH
	// ENOMEM is frequently met due to race condition in kernel
	//
	// By default, Mac OS has a super small limitation:
	// $ sysctl -a | grep -i shm
	// kern.sysv.shmmax: 4194304
	// kern.sysv.shmmin: 1
	// kern.sysv.shmmni: 32
	// kern.sysv.shmseg: 8
	// kern.sysv.shmall: 1024
	//
	//
	// You should change them by writing those params into a plist for autostart, then reboot
	// plist permission should be root:wheel, 0644
	//
	// also, you should try to raise the maxproc limit to max `sudo launchctl limit maxproc 4000 4000`.
	//
	rib, err := route.FetchRIB(syscall.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}
	nrs := make([]NetRoute, 0)
	for _, v := range msgs {
		rmsg := v.(*route.RouteMessage)

		dest := rmsg.Addrs[syscall.RTAX_DST]
		var destStr = ""
		switch dest.(type) {
		case nil:
			break
		case *route.Inet4Addr:
			destStr = bytes2IPv4(dest.(*route.Inet4Addr).IP)
		default:
			destStr = "unk"
		}

		// error is encountered
		if rmsg.Err != nil && destStr != "0.0.0.0" {
			// ignore this route, so many errors drive me crazy
			continue
		}

		netmaskOri := rmsg.Addrs[syscall.RTAX_NETMASK]
		var netmaskStr = ""
		switch netmaskOri.(type) {
		case nil:
			netmaskStr = "0"
		case *route.Inet4Addr:
			netmaskStr = bytes2IPv4(netmaskOri.(*route.Inet4Addr).IP)
		default:
			netmaskStr = "unk"
		}

		gateway := rmsg.Addrs[syscall.RTAX_GATEWAY]
		var gatewayStr = ""
		switch gateway.(type) {
		case *route.Inet4Addr:
			gatewayStr = bytes2IPv4(gateway.(*route.Inet4Addr).IP)
		case *route.LinkAddr:
			gatewayTmp := gateway.(*route.LinkAddr)
			gatewayStr = "link#" + strconv.Itoa(gatewayTmp.Index)
			if gatewayTmp.Name != "" {
				gatewayStr = gatewayTmp.Name
			} else if gatewayTmp.Addr != nil {
				gatewayStr += "@" + bytes2HWAddr_MACAddr(gatewayTmp.Addr)
			}
		default:
			gatewayStr = "unk"
		}

		netIfAddr := rmsg.Addrs[syscall.RTAX_IFA]
		netIfName := rmsg.Addrs[syscall.RTAX_IFP]
		var netIfStr = ""
		if netIfName != nil {
			netIfStr = ""
		} else {
			switch netIfAddr.(type) {
			case (*route.Inet4Addr):
				netIfStr = bytes2IPv4(netIfAddr.(*route.Inet4Addr).IP)
			default:
				netIfStr = "unk"
			}
		}

		nrs = append(nrs, NetRoute{
			Metric:      uint32(rmsg.Seq),
			Destination: destStr + "/" + netmaskStr,
			Gateway:     gatewayStr,
			Flags:       RetrieveFlagFromRIB(rmsg.Flags),
			NetIf:       netIfStr,
		})
	}
	return nrs, nil

}
func RetrieveFlagFromRIB(flags int) string {
	data := RouteFlag{
		U:        flags&RTF_UP != 0,
		H:        flags&RTF_HOST != 0,
		G:        flags&RTF_GATEWAY != 0,
		S:        flags&RTF_STATIC != 0,
		Cloned:   flags&RTF_CLONING != 0,
		W:        false,
		L:        false,
		Reinsta:  false,
		D:        flags&RTF_DYNAMIC != 0,
		M:        flags&RTF_MODIFIED != 0,
		A:        false,
		Cached:   false,
		Rejected: flags&RTF_REJECT != 0,
	}
	return data.ToTableString()
}
