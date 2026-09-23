package analyser

import (
	"coraldpi/detectors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
)

type interfaceAnalyser struct {
	tcpStreamFactory *PeekableTCPStreamFactory
	tcpStreamPool    *tcpassembly.StreamPool
	tcpAssembler     *tcpassembly.Assembler

	pkCountL4 map[string]int
}

func NewInterfaceAnalyser() *interfaceAnalyser {
	ret := &interfaceAnalyser{
		tcpStreamFactory: NewPeekableTCPStreamFactory(detectors.DetectTCP),
		pkCountL4:        map[string]int{},
	}
	ret.tcpStreamPool = tcpassembly.NewStreamPool(ret.tcpStreamFactory)
	ret.tcpAssembler = tcpassembly.NewAssembler(ret.tcpStreamPool)
	return ret
}

func (ia *interfaceAnalyser) Capture(device string, exitChan chan struct{}) error {
	cap, err := pcapgo.NewEthernetHandle(device)
	if err != nil {
		return err
	}
	err = cap.SetPromiscuous(true)
	if err != nil {
		return err
	}
	capClose := sync.OnceFunc(func() { cap.Close() })
	defer capClose()
	fmt.Println("capturing:", cap.LocalAddr().String(), cap.GetCaptureLength())
	go func() {
		<-exitChan
		capClose()
	}()
	go func() {
		for {
			select {
			case <-time.After(5 * time.Second):
				ia.tcpAssembler.FlushWithOptions(tcpassembly.FlushOptions{
					T: time.Now().Add(-30 * time.Second),
				})
				spew.Dump(cap.Stats())
			case <-exitChan:
				return
			}
		}
	}()
	for {
		select {
		case <-exitChan:
			return nil
		default:
		}
		pk, info, err := cap.ZeroCopyReadPacketData()
		if err != nil {
			return err
		}
		// ia.processPacketBytes(pk, info)
		// spew.Dump(packetBytes)
		ia.processPacket(gopacket.NewPacket(pk, layers.LayerTypeEthernet, gopacket.NoCopy), info)
	}
}

func (ia *interfaceAnalyser) processPacketBytes(pk []byte, info gopacket.CaptureInfo) {
	// if len(pk) < 64 {
	// 	fmt.Println("ethernet packet too small")
	// 	spew.Dump(pk, info)
	// 	return
	// }

	// srcMac :=
}

func (ia *interfaceAnalyser) processPacket(pk gopacket.Packet, info gopacket.CaptureInfo) {
	// spew.Dump(pk)
	if pk.ErrorLayer() != nil {
		return
	}
	for _, l := range pk.Layers() {
		if l.LayerType() == layers.LayerTypeTLS {
			fmt.Println("got tls")
		}
	}
	lNetwork := pk.NetworkLayer()
	flowIP := gopacket.InvalidFlow
	if lNetwork != nil {
		flowIP = lNetwork.NetworkFlow()
	}
	// fmt.Println(pkGetLayersString(pk), info.Length)
	lTransport := pk.TransportLayer()
	if lTransport != nil {
		lts := lTransport.LayerType().String()
		ia.pkCountL4[lts] = ia.pkCountL4[lts] + 1
		layerTCP, ok := lTransport.(*layers.TCP)
		if ok {
			ia.tcpAssembler.Assemble(flowIP, layerTCP)
		}
	}
}

func pkGetLayersString(pk gopacket.Packet) (ret string) {
	for _, layer := range pk.Layers() {
		ret += layer.LayerType().String() + "\t"
	}
	return
}

type CaptureStats struct {
	PkCountL4      map[string]int
	TCPConnsOpen   int
	TCPConnsClosed int
	Conns          []string
}

func (ia *interfaceAnalyser) GetStats() CaptureStats {
	ia.tcpStreamFactory.Lock.Lock()
	ret := CaptureStats{
		PkCountL4: maps.Clone(ia.pkCountL4),
	}
	found := []string{}
connloop:
	for _, s1 := range ia.tcpStreamFactory.OpenStreams {
		if s1 == nil {
			continue
		}
		ret.TCPConnsOpen++
		src1 := s1.FlowNet.Src().String() + ":" + s1.FlowTCP.Src().String()
		dst1 := s1.FlowNet.Dst().String() + ":" + s1.FlowTCP.Dst().String()
		if slices.Contains(found, src1+dst1) {
			continue
		}
		for _, s2 := range ia.tcpStreamFactory.OpenStreams {
			if s2 == nil {
				continue
			}
			src2 := s2.FlowNet.Src().String() + ":" + s2.FlowTCP.Src().String()
			dst2 := s2.FlowNet.Dst().String() + ":" + s2.FlowTCP.Dst().String()
			if src1 != dst2 || dst1 != src2 {
				continue
			}
			found = append(found, src1+dst1, src2+dst2)
			ret.Conns = append(ret.Conns, s1.StringWithOther(s2))
			continue connloop
		}
		ret.Conns = append(ret.Conns, "onedir "+s1.String())
	}
	ret.TCPConnsClosed = ia.tcpStreamFactory.ConnsClosed
	ia.tcpStreamFactory.Lock.Unlock()
	return ret
}
