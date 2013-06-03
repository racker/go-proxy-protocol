package proxyProtocol

type AddressFamilyAndProtocol byte

// Address family and transport protocol
const (
	UNSPEC       = '\x00'
	TCPoverIPv4  = '\x11'
	UDPoverIPv4  = '\x12'
	TCPoverIPv6  = '\x21'
	UDPoverIPv6  = '\x22'
	UnixStream   = '\x31'
	UnixDatagram = '\x32'
)

var supportedAP = map[AddressFamilyAndProtocol]bool{TCPoverIPv4: true, UDPoverIPv4: true, TCPoverIPv6: true, UDPoverIPv6: true, UnixStream: true, UnixDatagram: true}

// The address family is IPv4 (AF_INET4)
func (ap AddressFamilyAndProtocol) IsIPv4() bool {
	return 0x10 == ap&0xF0
}

// The address family is IPv6 (AF_INET6)
func (ap AddressFamilyAndProtocol) IsIPv6() bool {
	return 0x20 == ap&0xF0
}

// The address family is UNIX (AF_UNIX)
func (ap AddressFamilyAndProtocol) IsUnix() bool {
	return 0x30 == ap&0xF0
}

// The transport protocol is TCP or STREAM (SOCK_STREAM)
func (ap AddressFamilyAndProtocol) IsSTREAM() bool {
	return 0x01 == ap&0x0F
}

// The transport protocol is UDP or DGRAM (SOCK_DGRAM)
func (ap AddressFamilyAndProtocol) IsDGRAM() bool {
	return 0x01 == ap&0x0F
}

// The transport protocol or address family is unspecified
func (ap AddressFamilyAndProtocol) IsUnspec() bool {
	return (0x00 == ap&0xF0) || (0x00 == ap&0x0F)
}
