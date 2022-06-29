//go:build windows

package routes

import (
	"github.com/kmahyyg/go-network-compo/wintypes"
	"strconv"
)

// module impl

func Retrieve() ([]NetRoute, error) {
	routingTable, err := wintypes.GetIPForwardTable2(wintypes.AddressFamily(wintypes.AF_INET))
	if err != nil {
		return nil, err
	}
	netRoutes := make([]NetRoute, len(routingTable))
	for i := range routingTable {
		singleIpFwdRow := &routingTable[i]
		ifaceRow, err := singleIpFwdRow.InterfaceLUID.Interface()
		if err != nil {
			return nil, err
		}
		singleNetRoute := NetRoute{
			Metric:      singleIpFwdRow.Metric,
			Destination: singleIpFwdRow.DestinationPrefix.RawPrefix.Addr().String() + "/" + strconv.Itoa(int(singleIpFwdRow.DestinationPrefix.PrefixLength)),
			Gateway:     singleIpFwdRow.NextHop.Addr().String(),
			Flags:       RetrieveFlagFromMibRow2(ifaceRow, singleIpFwdRow),
			NetIf:       ifaceRow.Alias(),
		}
		netRoutes[i] = singleNetRoute
	}
	return netRoutes, nil
}

func RetrieveFlagFromMibRow2(mibIfRow *wintypes.MibIfRow2, mibIpFwdRow *wintypes.MibIPforwardRow2) string {
	return RouteFlag{
		U:        mibIfRow.OperStatus == wintypes.IfOperStatusUp && mibIpFwdRow.Publish,
		H:        int(mibIpFwdRow.DestinationPrefix.PrefixLength) == 32,
		G:        mibIpFwdRow.DestinationPrefix.RawPrefix.Addr().String() == "0.0.0.0",
		S:        mibIpFwdRow.Immortal,
		Cloned:   false,                                            // windows not support
		W:        false,                                            // windows not support
		L:        false,                                            // not related to hardware
		Reinsta:  false,                                            // unknown
		D:        mibIpFwdRow.NextHop.Addr().String() == "0.0.0.0", // routing daemon not available here
		M:        false,                                            // routing daemon not available here
		A:        mibIpFwdRow.AutoconfigureAddress,
		Cached:   false,
		Rejected: false, // always false here in Chinese
	}.ToTableString()
}
