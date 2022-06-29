//go:build linux

package routes

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"strconv"
	"strings"
	"syscall"
)

const (
	ROUTE_FILE_PATH = "/proc/net/route"
	seperator       = "\t" // not rune, but string here
	totalFields     = 11
	headerFields    = 12
)

func Retrieve() ([]NetRoute, error) {
	// read file in a total, without race condition
	fileData, err := ioutil.ReadFile(ROUTE_FILE_PATH)
	if err != nil {
		return nil, err
	}
	// scan line by line
	scanner := bufio.NewScanner(bytes.NewBuffer(fileData))
	nRs := make([]NetRoute, 0)
	for scanner.Scan() {
		// process end of file
		if scanner.Err() == io.EOF {
			break
		}
		// other errors
		if err = scanner.Err(); err != nil {
			log.Println(err)
		}
		// go ahead
		routeRow := strings.Split(scanner.Text(), seperator)
		if len(routeRow) == headerFields {
			// table header, skip
			continue
		}
		if len(routeRow) != totalFields {
			return nil, errors.New("invalid route row")
		}
		// current row is route row
		// build NetRoute
		// convert metric
		metricNum, err := strconv.Atoi(routeRow[6])
		if err != nil {
			return nil, err
		}
		// destination to hex ipnet
		destIP, err := hex.DecodeString(routeRow[1])
		var destIPbytes [4]byte
		if err != nil {
			return nil, err
		}
		destMask, err := hex.DecodeString(routeRow[7])
		var destMaskIPbytes [4]byte
		if err != nil {
			return nil, err
		}
		// ip to string
		copy(destMaskIPbytes[:], destMask)
		copy(destIPbytes[:], destIP)
		// gateway to hex ipnet
		gatewayIP, err := hex.DecodeString(routeRow[2])
		if err != nil {
			return nil, err
		}
		var gatewayIPBytes [4]byte
		copy(gatewayIPBytes[:], gatewayIP)
		// flags in int
		flagInt, err := strconv.ParseInt(routeRow[3], 16, 64)
		if err != nil {
			return nil, err
		}
		// build s-nr
		singleNR := NetRoute{
			Metric:      uint32(metricNum),
			Destination: common.Bytes2IPv4(destIPbytes, true) + "/" + common.Bytes2IPv4(destMaskIPbytes, true),
			Gateway:     common.Bytes2IPv4(gatewayIPBytes, true),
			Flags:       buildRouteFlagsFromRouteRow(int(flagInt)),
			NetIf:       routeRow[0],
		}
		nRs = append(nRs, singleNR)
	}
	// debug placeholder
	return nRs, nil
}

func buildRouteFlagsFromRouteRow(flag int) string {
	rf := RouteFlag{
		U:        flag&syscall.RTF_UP != 0,
		H:        flag&syscall.RTF_HOST != 0,
		G:        flag&syscall.RTF_GATEWAY != 0,
		S:        flag&syscall.RTF_STATIC != 0,
		Cloned:   false,
		W:        false,
		L:        false,
		Reinsta:  flag&syscall.RTF_REINSTATE != 0,
		D:        flag&syscall.RTF_DYNAMIC != 0,
		M:        false,
		A:        false,
		Cached:   false,
		Rejected: flag&syscall.RTF_REJECT != 0,
	}
	return rf.ToTableString()
}
