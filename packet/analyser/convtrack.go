package analyser

import (
	"coraldpi/util"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/google/gopacket/layers"
)

const peekBufSize = 512

type conversation struct {
	SrcIP        [4]byte
	SrcPort      uint16
	DstIP        [4]byte
	DstPort      uint16
	StartTime    time.Time
	LastDataTime time.Time
	L3Proto      uint8
	State        uint16
	DetectedTo   string
	DetectedFrom string
	PacketsTo    uint32
	PacketsFrom  uint32
	BytesTo      uint32
	BytesFrom    uint32
	PeekTo       [peekBufSize]byte
	PeekFrom     [peekBufSize]byte
}

func (ct *conversation) Reset() {
	ct.SrcIP = [4]byte{}
	ct.SrcPort = 0
	ct.DstIP = [4]byte{}
	ct.DstPort = 0
	ct.StartTime = time.Time{}
	ct.LastDataTime = time.Time{}
	ct.L3Proto = 0
	ct.State = 0
	ct.DetectedFrom = ""
	ct.DetectedTo = ""
	ct.BytesTo = 0
	ct.BytesFrom = 0
	ct.PeekTo = [peekBufSize]byte{}
	ct.PeekFrom = [peekBufSize]byte{}
}

func (ct *conversation) String() string {
	protostr := ""
	switch ct.L3Proto {
	case uint8(layers.IPProtocolTCP):
		protostr = "TCP"
	case uint8(layers.IPProtocolUDP):
		protostr = "UDP"
	case uint8(layers.IPProtocolICMPv4):
		protostr = "ICMP"
	default:
		protostr = strconv.FormatInt(int64(ct.L3Proto), 10)
	}
	srcip := fmt.Sprintf("%d.%d.%d.%d", ct.SrcIP[0], ct.SrcIP[1], ct.SrcIP[2], ct.SrcIP[3])
	dstip := fmt.Sprintf("%d.%d.%d.%d", ct.DstIP[0], ct.DstIP[1], ct.DstIP[2], ct.DstIP[3])
	dtTo := ct.DetectedTo
	if dtTo == "" && ct.BytesTo > 0 {
		dtTo = util.PeekBytes(ct.PeekTo[:min(ct.BytesTo, peekBufSize)], 16)
	}
	dtFrom := ct.DetectedFrom
	if dtFrom == "" && ct.BytesFrom > 0 {
		dtFrom = util.PeekBytes(ct.PeekFrom[:min(ct.BytesFrom, peekBufSize)], 16)
	}
	return fmt.Sprintf("%s %4s %-15s:%-6d %7s >-< %-7s %-15s:%-6d %s >-< %s",
		ct.StartTime.Format(time.DateTime), protostr,
		srcip, ct.SrcPort, humanize.Bytes(uint64(ct.BytesTo)), humanize.Bytes(uint64(ct.BytesFrom)), dstip, ct.DstPort,
		dtTo, dtFrom)
}

func (ct *conversation) AddrBelongs(srcIP, dstIP [4]byte, srcPort, dstPort uint16) bool {
	return ct.SrcIP[0] == srcIP[0] && ct.SrcIP[1] == srcIP[1] && ct.SrcIP[2] == srcIP[2] && ct.SrcIP[3] == srcIP[3] &&
		ct.DstIP[0] == dstIP[0] && ct.DstIP[1] == dstIP[1] && ct.DstIP[2] == dstIP[2] && ct.DstIP[3] == dstIP[3] &&
		ct.SrcPort == srcPort && ct.DstPort == dstPort
}

func (ct *conversation) AddrSet(srcIP, dstIP [4]byte, srcPort, dstPort uint16) {
	ct.SrcIP[0] = srcIP[0]
	ct.SrcIP[1] = srcIP[1]
	ct.SrcIP[2] = srcIP[2]
	ct.SrcIP[3] = srcIP[3]
	ct.DstIP[0] = dstIP[0]
	ct.DstIP[1] = dstIP[1]
	ct.DstIP[2] = dstIP[2]
	ct.DstIP[3] = dstIP[3]
	ct.SrcPort = srcPort
	ct.DstPort = dstPort
}

func (ct *conversation) Feed(isSrc bool, buf []byte) {
	ct.LastDataTime = time.Now()
	if isSrc {
		ct.PacketsTo++
		if ct.BytesTo < peekBufSize {
			copy(ct.PeekTo[ct.BytesTo:], buf)
		}
		ct.BytesTo += uint32(len(buf))
	} else {
		ct.PacketsFrom++
		if ct.BytesFrom < peekBufSize {
			copy(ct.PeekFrom[ct.BytesFrom:], buf)
		}
		ct.BytesFrom += uint32(len(buf))
	}
}

type convtrack struct {
	convsByProto [255][]*conversation
	pool         sync.Pool
}

func (ct *convtrack) findOrAllocateConv(srcIP, dstIP [4]byte, proto uint8, srcPort, dstPort uint16) (ret *conversation, isSrc bool) {
	cc := 0
	emptySpot := -1
	for i, c := range ct.convsByProto[proto] {
		if c == nil {
			emptySpot = i
			continue
		}
		cc++
		if c.AddrBelongs(srcIP, dstIP, srcPort, dstPort) {
			return c, true
		}
		if c.AddrBelongs(dstIP, srcIP, dstPort, srcPort) {
			return c, false
		}
	}
	r := ct.pool.Get()
	if r == nil {
		ret = &conversation{}
		ret.Reset()
	} else {
		ret = r.(*conversation)
	}
	now := time.Now()
	ret.StartTime = now
	ret.LastDataTime = now
	ret.L3Proto = proto
	ret.AddrSet(srcIP, dstIP, srcPort, dstPort)
	if emptySpot != -1 {
		ct.convsByProto[proto][emptySpot] = ret
	} else {
		ct.convsByProto[proto] = append(ct.convsByProto[proto], ret)
	}
	return ret, true
}

func (ct *convtrack) flush(t time.Time) {
	for _, convs := range ct.convsByProto {
		for i, c := range convs {
			if c == nil {
				continue
			}
			if c.LastDataTime.Compare(t) > 0 {
				continue
			}
			c.Reset()
			convs[i] = nil
			ct.pool.Put(c)
		}
	}
}
