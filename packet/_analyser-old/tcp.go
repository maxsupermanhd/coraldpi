package analyser

import (
	"coraldpi/util"
	"fmt"
	"sync"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
)

type PeekableTCPStreamFactory struct {
	DetectFunc    func([]byte) string
	Lock          sync.Mutex
	ConnsClosed   int
	OpenStreams   []*PeekableTCPStream
	ClosedStreams []*PeekableTCPStream
}

func NewPeekableTCPStreamFactory(detectFunc func([]byte) string) *PeekableTCPStreamFactory {
	return &PeekableTCPStreamFactory{
		DetectFunc:    detectFunc,
		OpenStreams:   []*PeekableTCPStream{},
		ClosedStreams: []*PeekableTCPStream{},
	}
}

func (f *PeekableTCPStreamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	f.Lock.Lock()
	var ret *PeekableTCPStream
	for i := range f.ClosedStreams {
		if f.ClosedStreams[i] != nil {
			ret = f.ClosedStreams[i]
			f.ClosedStreams[i] = nil
			break
		}
	}
	if ret == nil {
		ret = &PeekableTCPStream{
			Factory:    f,
			Lock:       sync.Mutex{},
			PeekBuffer: make([]byte, 0, 512),
			DetectFunc: f.DetectFunc,
		}
	}
	foundSpot := false
	for i := range f.OpenStreams {
		if f.OpenStreams[i] == nil {
			f.OpenStreams[i] = ret
			foundSpot = true
			break
		}
	}
	if !foundSpot {
		f.OpenStreams = append(f.OpenStreams, ret)
	}
	ret.FlowNet = netFlow
	ret.FlowTCP = tcpFlow
	f.Lock.Unlock()
	return ret
}

func (f *PeekableTCPStreamFactory) CloseStream(s *PeekableTCPStream) {
	f.Lock.Lock()
	for i := range f.OpenStreams {
		if f.OpenStreams[i] == s {
			f.OpenStreams[i] = nil
			break
		}
	}
	storedClosed := false
	for i := range f.ClosedStreams {
		if f.ClosedStreams[i] == nil {
			f.ClosedStreams[i] = s
			storedClosed = true
			break
		}
	}
	if !storedClosed {
		f.ClosedStreams = append(f.ClosedStreams, s)
	}
	s.Factory.ConnsClosed++
	s.Reset()
	f.Lock.Unlock()
}

type PeekableTCPStream struct {
	Factory *PeekableTCPStreamFactory
	FlowNet gopacket.Flow
	FlowTCP gopacket.Flow

	Lock          sync.Mutex
	FirstSeen     time.Time
	PeekBuffer    []byte
	PeekReadable  string
	TotalCaptured int
	TotalSkipped  int
	TotalStart    int
	TotalEnd      int
	ProtoDetected string
	DetectFunc    func([]byte) string
}

func (s *PeekableTCPStream) Reassembled(parts []tcpassembly.Reassembly) {
	s.Lock.Lock()
	defer s.Lock.Unlock()
	for _, p := range parts {
		if s.FirstSeen.IsZero() || s.FirstSeen.Compare(p.Seen) > 0 {
			s.FirstSeen = p.Seen
		}
		if s.TotalCaptured < 512 && s.ProtoDetected == "" {
			s.PeekBuffer = append(s.PeekBuffer, p.Bytes...)
		}
		s.TotalCaptured += len(p.Bytes)
		s.TotalSkipped += p.Skip
		if p.Start {
			s.TotalStart++
		}
		if p.End {
			s.TotalEnd++
		}
	}
	if s.PeekReadable == "" && len(s.PeekBuffer) > 24 {
		s.PeekReadable = util.ToEscapedHex(s.PeekBuffer[:24])
	}
	if s.ProtoDetected != "" || s.DetectFunc == nil {
		return
	}
	s.ProtoDetected = s.DetectFunc(s.PeekBuffer)
	if s.ProtoDetected != "" {
		fmt.Println("detected: ", s.StringNOLOCK())
	}
}

func (s *PeekableTCPStream) ReassemblyComplete() {
	s.Factory.CloseStream(s)
}

func (s *PeekableTCPStream) Reset() {
	s.Lock.Lock()
	s.FirstSeen = time.Time{}
	s.PeekBuffer = s.PeekBuffer[:0]
	s.PeekReadable = ""
	s.TotalCaptured = 0
	s.TotalSkipped = 0
	s.TotalStart = 0
	s.TotalEnd = 0
	s.ProtoDetected = ""
	s.Lock.Unlock()
}

func (s *PeekableTCPStream) String() string {
	s.Lock.Lock()
	ret := s.StringNOLOCK()
	s.Lock.Unlock()
	return ret
}

func (s *PeekableTCPStream) StringNOLOCK() string {
	ret := s.FlowNet.String()
	ret += "\t" + s.FlowTCP.String()
	ret += "\t" + humanize.Bytes(uint64(s.TotalCaptured))
	if s.TotalSkipped > 0 {
		ret += "(" + humanize.Bytes(uint64(s.TotalSkipped)) + ")"
	}
	if s.ProtoDetected != "" {
		ret += "\t" + s.ProtoDetected
	} else if s.PeekReadable != "" {
		ret += "\t" + s.PeekReadable
	}
	if s.TotalStart == 0 {
		ret += "\tno start"
	} else if s.TotalStart > 1 {
		ret += "\tMULTIPLE SYN!!!"
	}
	return ret
}

func (s *PeekableTCPStream) StringWithOther(o *PeekableTCPStream) string {
	s.Lock.Lock()
	o.Lock.Lock()
	src := s
	dst := o
	if src.FirstSeen.Compare(dst.FirstSeen) > 0 {
		src = o
		dst = s
	}
	dir := " ??? "
	if src.TotalStart == 1 && dst.TotalStart == 0 {
		dir = " --> "
	} else if src.TotalStart == 0 && dst.TotalStart == 1 {
		dir = " <-- "
	} else if o.TotalStart == 1 && s.TotalStart == 1 {
		dir = " <-> "
	} else if src.TotalStart == 0 && dst.TotalStart == 0 {
		dir = " --- "
	}
	ret := src.FlowNet.Src().String() + ":" + src.FlowTCP.Src().String() + dir +
		src.FlowNet.Dst().String() + ":" + src.FlowTCP.Dst().String() +
		" \t" + humanize.Bytes(uint64(src.TotalCaptured)) + " \t" + humanize.Bytes(uint64(dst.TotalCaptured))
	if dst.TotalSkipped > 0 || src.TotalSkipped > 0 {
		ret += "(" + humanize.Bytes(uint64(dst.TotalSkipped)) + " " + humanize.Bytes(uint64(dst.TotalSkipped)) + ")"
	}
	if src.ProtoDetected != "" {
		ret += " \t" + src.ProtoDetected
	} else if src.PeekReadable != "" {
		ret += " \t" + src.PeekReadable
	}
	if dst.ProtoDetected != "" {
		ret += " \t" + dst.ProtoDetected
	} else if dst.PeekReadable != "" {
		ret += " \t" + dst.PeekReadable
	}
	if dst.TotalStart > 1 {
		ret += " dst multiple start"
	}
	if src.TotalStart > 1 {
		ret += " src multiple start"
	}
	s.Lock.Unlock()
	o.Lock.Unlock()
	return ret
}
