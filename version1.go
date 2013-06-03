package proxyProtocol

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

var (
	_proxy = []byte{'P', 'R', 'O', 'X', 'Y'}
	_CRLF  = "\r\n"
	_sep   = " "
)

func initVersion1() *ProxyLine {
	ret := new(ProxyLine)
	ret.Cmd = PROXY
	return ret
}

func parseVersion1(reader *bufio.Reader) (*ProxyLine, error) {
	line, err := reader.ReadString('\n')
	if !strings.HasSuffix(line, _CRLF) {
		return nil, InvalidProxyLine
	}
	tokens := strings.Split(line[:len(line)-2], _sep)
	ret := initVersion1()
	if len(tokens) < 6 {
		return nil, InvalidProxyLine
	}
	switch tokens[1] {
	case "TCP4":
		ret.Protocol = TCPoverIPv4
	case "TCP6":
		ret.Protocol = TCPoverIPv6
	default:
		ret.Protocol = UNSPEC
	}
	ret.SrcAddr, err = parseIPAddr(ret.Protocol, tokens[2])
	if err != nil {
		return nil, err
	}
	ret.DstAddr, err = parseIPAddr(ret.Protocol, tokens[3])
	if err != nil {
		return nil, err
	}
	ret.SrcPort, err = parsePortNumber(tokens[4])
	if err != nil {
		return nil, err
	}
	ret.DstPort, err = parsePortNumber(tokens[5])
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (p *ProxyLine) writeVersion1(w io.Writer) (err error) {
	proto := "UNKNOWN"
	if p.Protocol == TCPoverIPv4 {
		proto = "TCP4"
	} else if p.Protocol == TCPoverIPv6 {
		proto = "TCP6"
	}
	_, err = fmt.Fprintf(w, "PROXY %s %s %s %d %d\r\n", proto, p.SrcAddr.String(), p.DstAddr.String(), p.SrcPort, p.DstPort)
	return
}

func parsePortNumber(portStr string) (port uint16, err error) {
	_port, err := strconv.Atoi(portStr)
	if err == nil {
		if port < 0 || port > 65535 {
			err = InvalidPortNum
		}
		port = uint16(_port)
	}
	return port, err
}

func parseIPAddr(protocol AddressFamilyAndProtocol, addrStr string) (addr *net.IPAddr, err error) {
	proto := "ip"
	if protocol == TCPoverIPv4 {
		proto = "ip4"
	} else if protocol == TCPoverIPv6 {
		proto = "ip6"
	}
	addr, err = net.ResolveIPAddr(proto, addrStr)
	if err == nil {
		tryV4 := addr.IP.To4()
		if (protocol == TCPoverIPv4 && tryV4 == nil) || (protocol == TCPoverIPv6 && tryV4 != nil) {
			err = UnmatchedIPAddress
		}
	}
	return
}
