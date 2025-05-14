package list

import (
	"fmt"
	"net"
)

type IpList []net.IPNet

func LoadIpListFromStringList(inputList StringList) (list IpList, err error) {
	list = make([]net.IPNet, len(inputList))
	for i, ipsRange := range inputList {
		_, netRange, err := net.ParseCIDR(ipsRange)
		if err != nil {
			panic(fmt.Errorf("list.LoadIpListFromStringList: error parsing IP range (%s): %w", ipsRange, err))
		}
		list[i] = *netRange
	}
	return
}

func (list IpList) Contains(ip net.IP) bool {
	for _, ipRange := range list {
		if ipRange.Contains(ip) {
			return true
		}
	}

	return false
}
