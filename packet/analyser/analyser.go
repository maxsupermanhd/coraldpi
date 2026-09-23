package analyser

import (
	"coraldpi/packet/capture"
	"coraldpi/packet/detectors"
	"fmt"
	"maps"
	"sync"
	"sync/atomic"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type interfaceAnalyser struct {
	cap                 *capture.EthernetHandle
	lock                sync.Mutex
	pkCountL2           map[uint16]int
	pkCountL3           map[uint8]int
	pkCountL4           map[string]int
	framesCapturedTotal atomic.Uint64
	framesDroppedTotal  atomic.Uint32

	pEthernet layers.Ethernet
	pIPv4     layers.IPv4
	pTCP      layers.TCP
	pUDP      layers.UDP
	pICMP     layers.ICMPv4

	convtrack convtrack
}

func NewInterfaceAnalyser() *interfaceAnalyser {
	ret := &interfaceAnalyser{
		pkCountL2: map[uint16]int{},
		pkCountL3: map[uint8]int{},
		pkCountL4: map[string]int{},
	}
	return ret
}

func (ia *interfaceAnalyser) Capture(device string, exitChan chan struct{}) (err error) {
	ia.cap, err = capture.NewEthernetHandle(device)
	if err != nil {
		return err
	}
	err = ia.cap.SetPromiscuous(true)
	if err != nil {
		return err
	}
	capClose := sync.OnceFunc(func() { ia.cap.Close() })
	exitChanLocal := make(chan struct{})
	exit := sync.OnceFunc(func() { close(exitChanLocal) })
	go func() {
		select {
		case <-exitChanLocal:
			capClose()
		case <-exitChan:
			exit()
		}
	}()
	defer exit()
	fmt.Println("capturing:", ia.cap.LocalAddr().String(), ia.cap.GetCaptureLength())
	go func() {
		for {
			select {
			case <-time.After(1 * time.Second):
				ia.lock.Lock()
				ia.convtrack.flush(time.Now().Add(-30 * time.Second))
				ia.lock.Unlock()
				capStats, err := ia.cap.Stats()
				if err == nil {
					ia.framesDroppedTotal.Store(capStats.Drops)
				}
			case <-exitChanLocal:
				return
			}
		}
	}()
	for {
		select {
		case <-exitChanLocal:
			return nil
		default:
		}
		err = ia.cap.ReadPacket()
		if err != nil {
			return err
		}
		ia.framesCapturedTotal.Add(1)
		ia.processPacket(ia.cap.Buffer[:ia.cap.CI.CaptureLength])
		if err != nil {
			fmt.Println("Error parsing packet:", err.Error())
			spew.Dump(ia.cap.Buffer[:ia.cap.CI.CaptureLength])
		}
	}
}

func (ia *interfaceAnalyser) processPacket(data []byte) (err error) {
	ia.lock.Lock()
	defer ia.lock.Unlock()
	err = ia.pEthernet.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		return fmt.Errorf("decoding ethernet: %w", err)
	}
	ia.pkCountL2[uint16(ia.pEthernet.EthernetType)] = ia.pkCountL2[uint16(ia.pEthernet.EthernetType)] + 1
	if ia.pEthernet.EthernetType != layers.EthernetTypeIPv4 {
		return nil
	}

	err = ia.pIPv4.DecodeFromBytes(ia.pEthernet.Payload, gopacket.NilDecodeFeedback)
	if err != nil {
		return fmt.Errorf("decoding ipv4: %w", err)
	}
	ia.pkCountL3[uint8(ia.pIPv4.Protocol)] = ia.pkCountL3[uint8(ia.pIPv4.Protocol)] + 1

	var srcPort, dstPort uint16
	var detectfn func(uint16, []byte) string
	var payload []byte
	switch ia.pIPv4.Protocol {
	case layers.IPProtocolTCP:
		err = ia.pTCP.DecodeFromBytes(ia.pIPv4.Payload, gopacket.NilDecodeFeedback)
		if err != nil {
			return fmt.Errorf("decoding tcp: %w", err)
		}
		srcPort = uint16(ia.pTCP.SrcPort)
		dstPort = uint16(ia.pTCP.DstPort)
		detectfn = detectors.DetectTCP
		payload = ia.pTCP.Payload
	case layers.IPProtocolUDP:
		err = ia.pUDP.DecodeFromBytes(ia.pIPv4.Payload, gopacket.NilDecodeFeedback)
		if err != nil {
			return fmt.Errorf("decoding udp: %w", err)
		}
		srcPort = uint16(ia.pUDP.SrcPort)
		dstPort = uint16(ia.pUDP.DstPort)
		detectfn = detectors.DetectUDP
		payload = ia.pUDP.Payload
		// case layers.IPProtocolICMPv4:
		// 	err = ia.pICMP.DecodeFromBytes(ia.pIPv4.Payload, gopacket.NilDecodeFeedback)
		// 	if err != nil {
		// 		return fmt.Errorf("decoding icmp: %w", err)
		// 	}
		// 	// detected = detectors.DetectICMP()
	default:
		return nil
	}

	conv, isSrc := ia.convtrack.findOrAllocateConv([4]byte(ia.pIPv4.SrcIP), [4]byte(ia.pIPv4.DstIP), uint8(ia.pIPv4.Protocol), srcPort, dstPort)
	conv.Feed(isSrc, payload)

	var detectstr *string
	var detectPort uint16
	if isSrc {
		detectstr = &conv.DetectedTo
		detectPort = uint16(dstPort)
	} else {
		detectstr = &conv.DetectedFrom
		detectPort = uint16(srcPort)
	}

	if *detectstr == "" {
		*detectstr = detectfn(detectPort, payload)
		if *detectstr != "" {
			fmt.Println(conv.String())
		}
	}

	return nil
}

type CaptureStats struct {
	PkCountL2           map[uint16]int
	PkCountL3           map[uint8]int
	PkCountL4           map[string]int
	FramesCapturedTotal uint64
	FramesDroppedTotal  uint32
	Convs               []string
}

func (ia *interfaceAnalyser) GetStats() CaptureStats {
	ia.lock.Lock()
	ret := CaptureStats{
		PkCountL2:           maps.Clone(ia.pkCountL2),
		PkCountL3:           maps.Clone(ia.pkCountL3),
		PkCountL4:           maps.Clone(ia.pkCountL4),
		FramesCapturedTotal: ia.framesCapturedTotal.Load(),
		FramesDroppedTotal:  ia.framesDroppedTotal.Load(),
	}
	for _, convs := range ia.convtrack.convsByProto {
		for _, c := range convs {
			if c == nil {
				continue
			}
			ret.Convs = append(ret.Convs, c.String())
		}
	}
	ia.lock.Unlock()
	return ret
}
