package assemble

import "github.com/google/gopacket"

type ConvAssembler interface {
	Feed(gopacket.Layer)
	Peek() []byte
	Reset()
}

var (
	_ = ConvAssembler(NewDirectAppendAssembler())
	_ = ConvAssembler(NewTCPAssembler())
)
