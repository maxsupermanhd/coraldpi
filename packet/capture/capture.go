package capture

// effectively just github.com/google/gopacket/pcapgo
// but with less things going on

import (
	"fmt"
	"net"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

var hdrLen = unix.CmsgSpace(0)
var auxLen = unix.CmsgSpace(int(unsafe.Sizeof(unix.TpacketAuxdata{})))
var timensLen = unix.CmsgSpace(int(unsafe.Sizeof(unix.Timespec{})))
var timeLen = unix.CmsgSpace(int(unsafe.Sizeof(unix.Timeval{})))

func htons(data uint16) uint16 { return data<<8 | data>>8 }

// CaptureInfo provides standardized information about a packet captured off
// the wire or read from a file.
type CaptureInfo struct {
	// Timestamp is the time the packet was captured, if that is known.
	Timestamp time.Time
	// CaptureLength is the total number of bytes read off of the wire.
	CaptureLength int
	// Length is the size of the original packet.  Should always be >=
	// CaptureLength.
	Length  int
	HasVLAN bool
	VLAN    int
}

// EthernetHandle holds shared buffers and file descriptor of af_packet socket
type EthernetHandle struct {
	fd     int
	Buffer []byte
	oob    []byte
	ancil  []interface{}
	intf   int
	addr   net.HardwareAddr

	CI CaptureInfo
}

// readOne reads a packet from the handle and populates Buffer and CI fields
func (h *EthernetHandle) ReadPacket() error {
	// we could use unix.Recvmsg, but that does a memory allocation (for the returned sockaddr) :(
	var msg unix.Msghdr
	var sa unix.RawSockaddrLinklayer

	msg.Name = (*byte)(unsafe.Pointer(&sa))
	msg.Namelen = uint32(unsafe.Sizeof(sa))

	var iov unix.Iovec
	if len(h.Buffer) > 0 {
		iov.Base = &h.Buffer[0]
		iov.SetLen(len(h.Buffer))
	}
	msg.Iov = &iov
	msg.Iovlen = 1

	if len(h.oob) > 0 {
		msg.Control = &h.oob[0]
		msg.SetControllen(len(h.oob))
	}

	// use msg_trunc so we know packet size without auxdata, which might be missing
	n, _, e := syscall.Syscall(unix.SYS_RECVMSG, uintptr(h.fd), uintptr(unsafe.Pointer(&msg)), uintptr(unix.MSG_TRUNC))

	if e != 0 {
		return fmt.Errorf("couldn't read packet: %s", e)
	}

	// if sa.Family == unix.AF_PACKET {
	// 	ci.InterfaceIndex = int(sa.Ifindex)
	// } else {
	// 	ci.InterfaceIndex = h.intf
	// }

	// custom aux parsing so we don't allocate stuff (unix.ParseSocketControlMessage allocates a slice)
	// we're getting at most 2 cmsgs anyway and know which ones they are (auxdata + timestamp(ns))
	oob := h.oob[:msg.Controllen]
	gotAux := false

	for len(oob) > hdrLen { // > hdrLen, because we also need something after the cmsg header
		hdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		switch {
		case hdr.Level == unix.SOL_PACKET && hdr.Type == unix.PACKET_AUXDATA && len(oob) >= auxLen:
			aux := (*unix.TpacketAuxdata)(unsafe.Pointer(&oob[hdrLen]))
			h.CI.CaptureLength = int(n)
			h.CI.Length = int(aux.Len)
			h.CI.VLAN = int(aux.Vlan_tci)
			h.CI.HasVLAN = (aux.Status & unix.TP_STATUS_VLAN_VALID) != 0
			gotAux = true
		case hdr.Level == unix.SOL_SOCKET && hdr.Type == unix.SO_TIMESTAMPNS && len(oob) >= timensLen:
			tstamp := (*unix.Timespec)(unsafe.Pointer(&oob[hdrLen]))
			h.CI.Timestamp = time.Unix(int64(tstamp.Sec), int64(tstamp.Nsec))
		case hdr.Level == unix.SOL_SOCKET && hdr.Type == unix.SO_TIMESTAMP && len(oob) >= timeLen:
			tstamp := (*unix.Timeval)(unsafe.Pointer(&oob[hdrLen]))
			h.CI.Timestamp = time.Unix(int64(tstamp.Sec), int64(tstamp.Usec)*1000)
		}
		oob = oob[unix.CmsgSpace(int(hdr.Len))-hdrLen:]
	}

	if !gotAux {
		// fallback for no aux cmsg
		h.CI.CaptureLength = int(n)
		h.CI.Length = int(n)
	}

	// fix up capture length if we needed to truncate
	if h.CI.CaptureLength > len(h.Buffer) {
		h.CI.CaptureLength = len(h.Buffer)
	}

	if h.CI.Timestamp.IsZero() {
		// we got no timestamp info -> emulate it
		h.CI.Timestamp = time.Now()
	}

	return nil
}

// Close closes the underlying socket
func (h *EthernetHandle) Close() {
	if h.fd != -1 {
		unix.Close(h.fd)
		h.fd = -1
		runtime.SetFinalizer(h, nil)
	}
}

// SetCaptureLength sets the maximum capture length to the given value
func (h *EthernetHandle) SetCaptureLength(len int) error {
	if len < 0 {
		return fmt.Errorf("illegal capture length %d. Must be at least 0", len)
	}
	h.Buffer = make([]byte, len)
	return nil
}

// GetCaptureLength returns the maximum capture length
func (h *EthernetHandle) GetCaptureLength() int {
	return len(h.Buffer)
}

// LocalAddr returns the local network address
func (h *EthernetHandle) LocalAddr() net.HardwareAddr {
	// Hardware Address might have changed. Fetch new one and fall back to the stored one if fetching interface fails
	intf, err := net.InterfaceByIndex(h.intf)
	if err == nil {
		h.addr = intf.HardwareAddr
	}
	return h.addr
}

// SetPromiscuous sets promiscous mode to the required value. If it is enabled, traffic not destined for the interface will also be captured.
func (h *EthernetHandle) SetPromiscuous(b bool) error {
	mreq := unix.PacketMreq{
		Ifindex: int32(h.intf),
		Type:    unix.PACKET_MR_PROMISC,
	}

	opt := unix.PACKET_ADD_MEMBERSHIP
	if !b {
		opt = unix.PACKET_DROP_MEMBERSHIP
	}

	return unix.SetsockoptPacketMreq(h.fd, unix.SOL_PACKET, opt, &mreq)
}

// Stats returns number of packets and dropped packets. This will be the number of packets/dropped packets since the last call to stats (not the cummulative sum!).
func (h *EthernetHandle) Stats() (*unix.TpacketStats, error) {
	return unix.GetsockoptTpacketStats(h.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
}

// NewEthernetHandle implements pcap.OpenLive for network devices.
// If you want better performance have a look at github.com/google/gopacket/afpacket.
// SetCaptureLength can be used to limit the maximum capture length.
func NewEthernetHandle(ifname string) (*EthernetHandle, error) {
	intf, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("couldn't query interface %s: %s", ifname, err)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("couldn't open packet socket: %s", err)
	}

	addr := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  intf.Index,
	}

	if err := unix.Bind(fd, &addr); err != nil {
		return nil, fmt.Errorf("couldn't bind to interface %s: %s", ifname, err)
	}

	ooblen := 0

	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_AUXDATA, 1); err != nil {
		// we can't get auxdata -> no vlan info
	} else {
		ooblen += auxLen
	}

	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1); err != nil {
		// no nanosecond resolution :( -> try ms
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMP, 1); err != nil {
			// if this doesn't work we well use time.Now() -> ignore errors here
		} else {
			ooblen += timeLen
		}
	} else {
		ooblen += timensLen
	}

	handle := &EthernetHandle{
		fd:     fd,
		Buffer: make([]byte, intf.MTU),
		oob:    make([]byte, ooblen),
		intf:   intf.Index,
		addr:   intf.HardwareAddr,
	}
	runtime.SetFinalizer(handle, (*EthernetHandle).Close)
	return handle, nil
}
