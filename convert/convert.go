// Terms Of Use
// ------------
// Do NOT use this on any computer you do not own or are not allowed to run this on.
// You may NEVER attempt to sell this, it is free and open source.
// The authors and publishers assume no responsibility.
// For educational purposes only.

// Package routine provides input validation and conversion functionality.
package convert

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
)

// Int8ToByte converts an uint8 to a byte.
// It will return a *byte.
func Int8ToByte(n *uint8) *byte {
	nUint16 := uint16(*n)
	nByte := make([]byte, 2, 2)
	binary.BigEndian.PutUint16(nByte, nUint16)
	nByte1 := nByte[1]
	return &nByte1
}

// Int8ToByte converts an uint16 to a []byte.
// It will return a *[]byte.
func Int16ToByte(n *uint16) *[]byte {
	nUint16 := uint16(*n)
	nByte := make([]byte, 2, 2)
	binary.BigEndian.PutUint16(nByte, nUint16)
	return &nByte
}

// ParseTime converts a string time in seconds to an integer.
// It will return a *int or an error if one occurred.
func ParseTime(timeStr *string) (*int, error) {
	timeInt, err := strconv.Atoi(*timeStr)
	if err != nil {
		return nil, errors.New("invalid time value")
	}
	if timeInt < 1 {
		return nil, errors.New("time must be at least 1 second")
	}
	return &timeInt, nil
}

// ParseGoroutines converts a string goroutine count to an integer.
// It will return a *int or an error if one occurred.
func ParseGoroutines(goroutines *string) (*int, error) {
	goroutineCount, err := strconv.Atoi(*goroutines)
	if err != nil {
		return nil, errors.New("invalid goroutine count")
	}
	if goroutineCount < 1 {
		return nil, errors.New("goroutine count must be at least 1")
	}
	return &goroutineCount, nil
}

// IP4 converts a string into a properly formatted byte.
// It will return a []byte and []byte or an error if one occurred.
func IP4(ethInterface, ip, port *string) (*[]byte, *[]byte, error) {
	if !((*ethInterface == "eth0") || (*ethInterface == "wlan0")) {
		return nil, nil, errors.New("invalid interface")
	}
	ip4NetIP := net.ParseIP(*ip)
	if ip4NetIP == nil {
		return nil, nil, errors.New("invalid ip4 ip")
	}
	validIP4IP := strings.Contains(*ip, ":")
	if validIP4IP == true {
		return nil, nil, errors.New("invalid ip4 ip")
	}
	ip4Byte := []byte(ip4NetIP)
	portInt, err := strconv.Atoi(*port) // convert first string octet to int
	portUInt16 := uint16(portInt)
	if err != nil {
		return nil, nil, errors.New("invalid uint16")
	}
	if portInt < 1 || portInt > 65535 {
		return nil, nil, errors.New("invalid port range")
	}
	portByte := Int16ToByte(&portUInt16)
	return &ip4Byte, portByte, nil
}

// IP6 converts a string into a properly formatted byte.
// It will return a []byte, []byte or an error if one occurred.
func IP6(ethInterface, ip, port *string) (*[]byte, *[]byte, error) {
	if !((*ethInterface == "eth0") || (*ethInterface == "wlan0")) {
		return nil, nil, errors.New("invalid interface")
	}
	ip6NetIP := net.ParseIP(*ip)
	if ip6NetIP == nil {
		return nil, nil, errors.New("invalid ip6 ip")
	}
	validIP6IP := strings.Contains(*ip, ".")
	if validIP6IP == true {
		return nil, nil, errors.New("invalid ip6 ip")
	}
	ip6Byte := []byte(ip6NetIP)
	portInt, _ := strconv.Atoi(*port) // convert first string octet to int
	portUInt16 := uint16(portInt)
	if portInt < 1 || portInt > 65535 {
		return nil, nil, errors.New("invalid port range")
	}
	portByte := Int16ToByte(&portUInt16)
	return &ip6Byte, portByte, nil
}
