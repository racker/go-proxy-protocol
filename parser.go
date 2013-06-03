/**
 *  Copyright 2013 Rackspace
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

// Packet proxyProtocol implements Proxy Protocol parser and writer.
package proxyProtocol

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	LOCAL = '\x00'
	PROXY = '\x01'
)

var (
	InvalidProxyLine   = errors.New("Invalid or unsupported proxy line")
	UnmatchedIPAddress = errors.New("IP address(es) unmatched with protocol")
	InvalidPortNum     = errors.New("Invalid port number parsed. (expected [0..65536])")
	UnsupportedVersion = errors.New("Unsupported proxy protocol version")
)

var (
	_signature = []byte{'\x0D', '\x0A', '\x0D', '\x0A', '\x00', '\x0D', '\x0A', '\x51', '\x55', '\x49', '\x54', '\x0A'}
)

type ProxyLine struct {
	Protocol AddressFamilyAndProtocol
	Cmd      byte
	SrcAddr  net.Addr
	DstAddr  net.Addr
	SrcPort  uint16
	DstPort  uint16
}

// ConsumeProxyLine looks for proxy protocol header in the reader and trys to parse it if found.
//
// If starting from current of pos of reader is valid proxy protocol header, the function reads (consumes) the header from reader and try to parse it as ProxyLine. A newly allocated ProxyLine is returned if parsing secceeds. If parsing fails, a nil and an error is returned; header is consumed from the reader no matter parsing succeeds or not.
//
// If starting from current of pos of reader is not a valid proxy protocol header (not starting with "PROXY" or signature), the function simply returns (nil, nil), leaving reader intact (nothing from reader is consumed).
//
// If the being parsed header is using an unknown protocol, ConsumeProxyLine parses remaining fields as same syntax as a supported protocol assuming IP is used in layer 3, and reports error if failed.
func ConsumeProxyLine(reader *bufio.Reader) (*ProxyLine, error) {
	word, _ := reader.Peek(13)
	if len(word) == 13 && bytes.Equal(word[0:12], _signature) {
		switch word[12] {
		case '\x02':
			return nil, nil
		default:
			return nil, UnsupportedVersion
		}
	} else if bytes.Equal(word[0:5], _proxy) {
		return parseVersion1(reader)
	} else {
		return nil, nil
	}
}

// WriteProxyLine formats p as valid PROXY line into w
func (p *ProxyLine) WriteProxyLine(w io.Writer) (err error) {
	_, err = fmt.Fprintf(w, "PROXY %s %s %s %d %d\r\n", p.Protocol, p.SrcAddr.String(), p.DstAddr.String(), p.SrcPort, p.DstPort)
	return
}
