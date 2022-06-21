//go:build windows

package routes

import (
	"strconv"
)

// module impl

func Retrieve() ([]NetRoute, error) {
	routingTable, err := GetIPForwardTable2(AddressFamily(AF_INET))
	if err != nil {
		return nil, err
	}
	netRoutes := make([]NetRoute, 0)
	for i := range routingTable {
		singleIpFwdRow := &routingTable[i]
		ifaceRow := &MibIfRow2{}
		singleNetRoute := NetRoute{
			Metric:      singleIpFwdRow.Metric,
			Destination: singleIpFwdRow.DestinationPrefix.RawPrefix.Addr().String() + "/" + strconv.Itoa(int(singleIpFwdRow.DestinationPrefix.PrefixLength)),
			Gateway:     singleIpFwdRow.NextHop.Addr().String(),
			Flags:       0,
			NetIf:       "",
		}
		netRoutes = append(netRoutes, singleNetRoute)
	}
	return netRoutes, nil
}
