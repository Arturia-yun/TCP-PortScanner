package scanner

import (
	"github.com/malfunkt/iprange"
	"net"
)

// 解析IP地址范围
func GetIpList(ips string) ([]net.IP, error) {
	addressList, err := iprange.ParseList(ips)
	if err != nil {
		return nil, err
	}

	list := addressList.Expand()
	return list, err
}
