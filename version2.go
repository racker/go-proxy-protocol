package proxyProtocol

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
)

type _addr4 struct {
	Src     [4]byte
	Dst     [4]byte
	SrcPort uint16
	DstPort uint16
}

type _addr6 struct {
	Src     [16]byte
	Dst     [16]byte
	SrcPort uint16
	DstPort uint16
}

type _addrUnix struct {
	Src [108]byte
	Dst [108]byte
}

func parseVersion2(reader *bufio.Reader) (ret *ProxyLine, err error) {
	for i := 0; i < 13; i++ { // skip first 13 bytes (signature + version number)
		_, err = reader.ReadByte()
		if err != nil {
			return
		}
	}
	ret = new(ProxyLine)
	ret.Cmd, err = reader.ReadByte()
	if err != nil {
		return
	}
	tmp, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	ret.Protocol = AddressFamilyAndProtocol(tmp)
	length, err := reader.ReadByte()
	if err != nil {
		return ret, err
	}
	if _, ok := supportedAP[ret.Protocol]; !ok {
		for i := 0; i < int(length); i++ {
			_, err = reader.ReadByte()
			if err != nil {
				return
			}
		}
		return ret, InvalidProxyLine
	}
	if !ret.validateLength(length) {
		return ret, InvalidProxyLine
	}

	if ret.Protocol.IsIPv4() {
		var addr _addr4
		err = binary.Read(io.LimitReader(reader, int64(length)), binary.BigEndian, addr)
		if err != nil {
			return
		}
		ret.SrcAddr = &net.IPAddr{IP: addr.Src[:], Zone: ""}
		ret.DstAddr = &net.IPAddr{IP: addr.Dst[:], Zone: ""}
		ret.SrcPort = addr.SrcPort
		ret.DstPort = addr.DstPort
	} else if ret.Protocol.IsIPv6() {
		var addr _addr6
		err = binary.Read(io.LimitReader(reader, int64(length)), binary.BigEndian, addr)
		if err != nil {
			return
		}
		ret.SrcAddr = &net.IPAddr{IP: addr.Src[:], Zone: ""}
		ret.DstAddr = &net.IPAddr{IP: addr.Dst[:], Zone: ""}
		ret.SrcPort = addr.SrcPort
		ret.DstPort = addr.DstPort
	} else if ret.Protocol.IsUnix() {
		var addr _addrUnix
		err = binary.Read(io.LimitReader(reader, int64(length)), binary.BigEndian, addr)
		if err != nil {
			return
		}
		ret.SrcAddr, err = net.ResolveUnixAddr("unix", string(addr.Src[:]))
		if err != nil {
			return
		}
		ret.DstAddr, err = net.ResolveUnixAddr("unix", string(addr.Dst[:]))
		if err != nil {
			return
		}
	}
	return
}

func (p *ProxyLine) writeVersion2(w io.Writer) (err error) {
	return
}

func (p *ProxyLine) validateLength(length byte) bool {
	if p.Protocol.IsIPv4() {
		return length == 12
	} else if p.Protocol.IsIPv6() {
		return length == 36
	} else if p.Protocol.IsUnix() {
		return length == 218
	} else {
		return false
	}
}
