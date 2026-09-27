package assemble

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type tcpAssembler struct {
}

func NewTCPAssembler() *tcpAssembler {
	return &tcpAssembler{}
}

func (ta *tcpAssembler) Feed(pkl gopacket.Layer) {
	pk, ok := pkl.(*layers.TCP)
	if !ok {
		return
	}
	_ = pk
}

func (ta *tcpAssembler) Peek() []byte {
	return nil
}

func (ta *tcpAssembler) Reset() {}
