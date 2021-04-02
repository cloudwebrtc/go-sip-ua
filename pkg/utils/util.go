package utils

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"

	"github.com/ghettovoice/gosip/sip"
)

var (
	localIPPrefix = [...]string{"192.168", "10.0", "169.254", "172.16"}
	ErrPort       = errors.New("invalid port")
)

func GetIP(addr string) string {
	if strings.Contains(addr, ":") {
		return strings.Split(addr, ":")[0]
	}
	return ""
}

func GetPort(addr string) string {
	if strings.Contains(addr, ":") {
		return strings.Split(addr, ":")[1]
	}
	return ""
}

func StrToUint16(str string) uint16 {
	i, _ := strconv.ParseUint(str, 10, 16)
	return uint16(i)
}

func BuildContactHeader(name string, from, to sip.Message, expires *sip.Expires) {
	name = strings.ToLower(name)
	for _, h := range from.GetHeaders(name) {
		AddParamsToContact(h.(*sip.ContactHeader), expires)
		to.AppendHeader(h.Clone())
	}
}

func AddParamsToContact(contact *sip.ContactHeader, expires *sip.Expires) {
	if urn, ok := contact.Params.Get("+sip.instance"); ok {
		contact.Params.Add("+sip.instance", sip.String{Str: fmt.Sprintf(`"%s"`, urn)})
	}
	if expires != nil {
		contact.Params.Add("expires", sip.String{Str: fmt.Sprintf("%d", int(*expires))})
	}
}

func ListenUDPInPortRange(portMin, portMax int, laddr *net.UDPAddr) (*net.UDPConn, error) {
	if (laddr.Port != 0) || ((portMin == 0) && (portMax == 0)) {
		return net.ListenUDP("udp", laddr)
	}
	var i, j int
	i = portMin
	if i == 0 {
		i = 1
	}
	j = portMax
	if j == 0 {
		j = 0xFFFF
	}
	if i > j {
		return nil, ErrPort
	}
	portStart := rand.Intn(j-i+1) + i
	portCurrent := portStart
	for {
		*laddr = net.UDPAddr{IP: laddr.IP, Port: portCurrent}
		c, e := net.ListenUDP("udp", laddr)
		if e == nil {
			return c, e
		}
		portCurrent++
		if portCurrent > j {
			portCurrent = i
		}

		fmt.Printf("failed to listen %s: %v, try next port %d", laddr.String(), e, portCurrent)

		if portCurrent == portStart {
			break
		}
	}
	return nil, ErrPort
}
